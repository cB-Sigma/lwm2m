package lwm2m

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Content formats this package reads and writes (CoAP Content-Format numbers
// from the IANA registry, as LwM2M 1.1 TS Core clause 7.4 lists them).
// cfLwM2MJSON is the LwM2M 1.0 JSON format, which a 1.1 server still reads
// (clause 7.4.5) but never asks for.
const (
	cfText      = 0
	cfOpaque    = 42
	cfCBOR      = 60
	cfSenMLJSON = 110
	cfSenMLCBOR = 112
	cfTLV       = 11542
	cfLwM2MJSON = 11543
	// cfLwM2MCBOR is the LwM2M 1.2 CBOR format (Core 1.2 clause 7.5.4,
	// application/vnd.oma.lwm2m+cbor).
	cfLwM2MCBOR = 11544
	// SenML FETCH/PATCH formats (RFC 8790) a composite request may carry.
	cfSenMLEtchJSON = 320
	cfSenMLEtchCBOR = 322
)

// note records something accepted although not strictly well formed; lax
// may be nil.
func note(lax *[]string, format string, args ...any) {
	if lax != nil {
		*lax = append(*lax, fmt.Sprintf(format, args...))
	}
}

// Path is an LwM2M path: object, and optionally instance, resource and
// resource instance (-1 when absent).
type Path struct{ Obj, Inst, Res, RI int }

// ParsePath reads "/3303/0/5700", "3/0" or "/3".
func ParsePath(s string) (Path, error) {
	p := Path{-1, -1, -1, -1}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) == 0 || len(parts) > 4 || parts[0] == "" {
		return p, fmt.Errorf("%q is not an LwM2M path", s)
	}
	dst := []*int{&p.Obj, &p.Inst, &p.Res, &p.RI}
	for i, x := range parts {
		n, err := strconv.ParseUint(x, 10, 16)
		if err != nil {
			return p, fmt.Errorf("%q is not an LwM2M path", s)
		}
		*dst[i] = int(n)
	}
	return p, nil
}

func (p Path) String() string {
	var b strings.Builder
	for _, n := range []int{p.Obj, p.Inst, p.Res, p.RI} {
		if n < 0 {
			break
		}
		b.WriteString("/" + strconv.Itoa(n))
	}
	return b.String()
}

// Value is one decoded resource (or resource instance) value.
type Value struct {
	Path Path
	V    any
}

// ---- OMA TLV (TS Core clause 7.4.3) ---------------------------------------

// Identifier kinds in the top two bits of a TLV type byte.
const (
	tlvObjInst  = 0
	tlvResInst  = 1
	tlvMultiRes = 2
	tlvResValue = 3
)

type tlv struct {
	kind  int
	id    int
	value []byte
	subs  []tlv
}

func parseTLV(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		t := b[0]
		b = b[1:]
		kind := int(t >> 6)
		idLen := 1
		if t&0x20 != 0 {
			idLen = 2
		}
		lenType := int(t>>3) & 3
		if len(b) < idLen+lenType {
			return nil, errors.New("TLV header is cut short")
		}
		id := int(b[0])
		if idLen == 2 {
			id = int(binary.BigEndian.Uint16(b))
		}
		b = b[idLen:]
		n := int(t & 7)
		if lenType > 0 {
			n = 0
			for i := range lenType {
				n = n<<8 | int(b[i])
			}
			b = b[lenType:]
		}
		if len(b) < n {
			return nil, errors.New("TLV value is cut short")
		}
		e := tlv{kind: kind, id: id, value: b[:n]}
		b = b[n:]
		if kind == tlvObjInst || kind == tlvMultiRes {
			subs, err := parseTLV(e.value)
			if err != nil {
				return nil, err
			}
			e.subs = subs
		}
		out = append(out, e)
	}
	return out, nil
}

func appendTLV(dst []byte, kind, id int, value []byte) []byte {
	t := byte(kind << 6)
	var ib []byte
	if id > 255 {
		t |= 0x20
		ib = binary.BigEndian.AppendUint16(nil, uint16(id))
	} else {
		ib = []byte{byte(id)}
	}
	n := len(value)
	var lb []byte
	switch {
	case n < 8:
		t |= byte(n)
	case n < 1<<8:
		t |= 1 << 3
		lb = []byte{byte(n)}
	case n < 1<<16:
		t |= 2 << 3
		lb = binary.BigEndian.AppendUint16(nil, uint16(n))
	default:
		t |= 3 << 3
		lb = []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	}
	dst = append(dst, t)
	dst = append(dst, ib...)
	dst = append(dst, lb...)
	return append(dst, value...)
}

// DecodeTLV decodes a TLV payload read from base (the requested path) into
// resource values, typing them with the object model; resources the model
// does not know come out as hex strings of their bytes.
func DecodeTLV(m Model, base Path, b []byte) ([]Value, error) {
	return decodeTLV(m, base, b, nil)
}

func decodeTLV(m Model, base Path, b []byte, lax *[]string) ([]Value, error) {
	items, err := parseTLV(b)
	if err != nil {
		return nil, err
	}
	var out []Value
	var walk func(p Path, items []tlv) error
	walk = func(p Path, items []tlv) error {
		for _, e := range items {
			q := p
			switch e.kind {
			case tlvObjInst:
				q.Inst = e.id
				if err := walk(q, e.subs); err != nil {
					return err
				}
				continue
			case tlvResValue:
				q.Res = e.id
				if q.Inst < 0 {
					q.Inst = 0
				}
				v, err := decodeScalar(m.Lookup(q).Type, e.value, lax)
				if err != nil {
					return fmt.Errorf("%s: %w", q, err)
				}
				out = append(out, Value{q, v})
			case tlvMultiRes:
				q.Res = e.id
				mv := map[string]any{}
				for _, s := range e.subs {
					v, err := decodeScalar(m.Lookup(q).Type, s.value, lax)
					if err != nil {
						return fmt.Errorf("%s/%d: %w", q, s.id, err)
					}
					mv[strconv.Itoa(s.id)] = v
				}
				out = append(out, Value{q, mv})
			case tlvResInst:
				q.RI = e.id
				v, err := decodeScalar(m.Lookup(q).Type, e.value, lax)
				if err != nil {
					return err
				}
				out = append(out, Value{q, v})
			}
		}
		return nil
	}
	return out, walk(base, items)
}

// decodeScalar reads a TLV value of the model type typ. Integers of 3, 5, 6
// or 7 bytes and booleans other than 0 or 1 are not in appendix C; they are
// read (big-endian, non-zero is true) and noted in lax.
func decodeScalar(typ string, b []byte, lax *[]string) (any, error) {
	switch typ {
	case tString, tCorelnk:
		return string(b), nil
	case tUnsigned:
		// Appendix C: 1, 2, 4 or 8 bytes of unsigned binary.
		switch len(b) {
		case 1:
			return float64(b[0]), nil
		case 2:
			return float64(binary.BigEndian.Uint16(b)), nil
		case 4:
			return float64(binary.BigEndian.Uint32(b)), nil
		case 8:
			return float64(binary.BigEndian.Uint64(b)), nil
		case 3, 5, 6, 7:
			note(lax, "TLV unsigned integer of %d bytes", len(b))
			var n uint64
			for _, x := range b {
				n = n<<8 | uint64(x)
			}
			return float64(n), nil
		}
		return nil, fmt.Errorf("an unsigned integer of %d bytes", len(b))
	case tInteger, tTime:
		switch len(b) {
		case 1:
			return float64(int8(b[0])), nil
		case 2:
			return float64(int16(binary.BigEndian.Uint16(b))), nil
		case 4:
			return float64(int32(binary.BigEndian.Uint32(b))), nil
		case 8:
			return float64(int64(binary.BigEndian.Uint64(b))), nil
		case 3, 5, 6, 7:
			note(lax, "TLV integer of %d bytes", len(b))
			n := int64(int8(b[0])) // sign-extend the first byte
			for _, x := range b[1:] {
				n = n<<8 | int64(x)
			}
			return float64(n), nil
		}
		return nil, fmt.Errorf("an integer of %d bytes", len(b))
	case tFloat:
		switch len(b) {
		case 4:
			return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), nil
		case 8:
			return math.Float64frombits(binary.BigEndian.Uint64(b)), nil
		}
		return nil, fmt.Errorf("a float of %d bytes", len(b))
	case tBool:
		if len(b) != 1 {
			return nil, errors.New("a boolean that is not one byte")
		}
		if b[0] > 1 {
			note(lax, "TLV boolean byte %d read as true", b[0])
		}
		return b[0] != 0, nil
	case tObjlnk:
		if len(b) != 4 {
			return nil, errors.New("an object link that is not 4 bytes")
		}
		return fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])), nil
	default:
		return hex.EncodeToString(b), nil
	}
}

// EncodeScalar encodes v as a TLV value of the given model type.
func EncodeScalar(typ string, v any) ([]byte, error) {
	switch typ {
	case tString, tCorelnk:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not a string", v)
		}
		return []byte(s), nil
	case tUnsigned:
		f, ok := v.(float64)
		if !ok || f != math.Trunc(f) || f < 0 || f >= 1<<64 {
			return nil, fmt.Errorf("%v is not an unsigned integer", v)
		}
		switch n := uint64(f); {
		case n <= math.MaxUint8:
			return []byte{byte(n)}, nil
		case n <= math.MaxUint16:
			return binary.BigEndian.AppendUint16(nil, uint16(n)), nil
		case n <= math.MaxUint32:
			return binary.BigEndian.AppendUint32(nil, uint32(n)), nil
		default:
			return binary.BigEndian.AppendUint64(nil, n), nil
		}
	case tInteger, tTime:
		f, ok := v.(float64)
		if !ok || f != math.Trunc(f) {
			return nil, fmt.Errorf("%v is not an integer", v)
		}
		n := int64(f)
		switch {
		case n >= math.MinInt8 && n <= math.MaxInt8:
			return []byte{byte(int8(n))}, nil
		case n >= math.MinInt16 && n <= math.MaxInt16:
			return binary.BigEndian.AppendUint16(nil, uint16(int16(n))), nil
		case n >= math.MinInt32 && n <= math.MaxInt32:
			return binary.BigEndian.AppendUint32(nil, uint32(int32(n))), nil
		}
		return binary.BigEndian.AppendUint64(nil, uint64(n)), nil
	case tFloat:
		f, ok := v.(float64)
		if !ok {
			return nil, fmt.Errorf("%v is not a number", v)
		}
		return binary.BigEndian.AppendUint64(nil, math.Float64bits(f)), nil
	case tBool:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%v is not a boolean", v)
		}
		if b {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case tOpaque:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("opaque values are written as hex strings")
		}
		return hex.DecodeString(s)
	}
	return nil, fmt.Errorf("resources of type %q cannot be written", typ)
}

// EncodeResourceTLV encodes one single-instance resource value.
func EncodeResourceTLV(res int, typ string, v any) ([]byte, error) {
	b, err := EncodeScalar(typ, v)
	if err != nil {
		return nil, err
	}
	return appendTLV(nil, tlvResValue, res, b), nil
}

// EncodeInstanceTLV encodes an object instance with the given resources
// (a client answering a read).
func EncodeInstanceTLV(inst int, res map[int][]byte) []byte {
	ids := make([]int, 0, len(res))
	for id := range res {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var body []byte
	for _, id := range ids {
		body = appendTLV(body, tlvResValue, id, res[id])
	}
	return appendTLV(nil, tlvObjInst, inst, body)
}

// ---- SenML JSON (RFC 8428; TS Core clause 7.4.4) --------------------------

type senml struct {
	BN  string   `json:"bn,omitempty"`
	BT  *float64 `json:"bt,omitempty"`
	N   string   `json:"n,omitempty"`
	V   *float64 `json:"v,omitempty"`
	VS  *string  `json:"vs,omitempty"`
	VB  *bool    `json:"vb,omitempty"`
	VD  *string  `json:"vd,omitempty"`
	VLO *string  `json:"vlo,omitempty"`
	T   *float64 `json:"t,omitempty"`
}

// TimedValue is a decoded value with the time the device gave it (zero
// when the record has none).
type TimedValue struct {
	Value
	Time time.Time
}

// DecodeSenMLJSON decodes a SenML JSON pack; names resolve against base
// names into LwM2M paths.
func DecodeSenMLJSON(b []byte) ([]TimedValue, error) {
	return decodeSenMLJSON(b, "")
}

func decodeSenMLJSON(b []byte, root string) ([]TimedValue, error) {
	var recs []senml
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("not a SenML JSON pack: %w", err)
	}
	// Opaque values are base64 in JSON (clause 7.4.5, appendix C); they
	// are kept as hex like TLV and SenML CBOR.
	for i, r := range recs {
		if r.VD == nil {
			continue
		}
		raw, err := decodeBase64(*r.VD)
		if err != nil {
			return nil, fmt.Errorf("SenML vd %q: %w", *r.VD, err)
		}
		h := hex.EncodeToString(raw)
		recs[i].VD = &h
	}
	return decodeSenML(recs, root)
}

// decodeBase64 reads base64 in either alphabet, with or without padding:
// LwM2M says base64 (RFC 4648 clause 4), SenML base64url without padding
// (RFC 8428 clause 4.3, RFC 4648 clause 5); both are accepted.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// senmlRelative is RFC 8428 clause 4.5.3's limit: a (base) time below
// 2**28 seconds is relative to now, one at or above it is Unix time.
const senmlRelative = 1 << 28

// senmlTime is the time of a record whose base time plus time is t; zero
// means now and comes out as the zero time.
func senmlTime(t float64) time.Time {
	switch {
	case t >= senmlRelative:
		return time.Unix(0, int64(t*1e9))
	case t != 0:
		return time.Now().Add(time.Duration(t * 1e9))
	}
	return time.Time{}
}

// decodeSenML resolves SenML records (JSON or CBOR) into values; a name
// under the client's alternate path (root) is read without it.
func decodeSenML(recs []senml, root string) ([]TimedValue, error) {
	var out []TimedValue
	bn, bt := "", 0.0
	for _, r := range recs {
		if r.BN != "" {
			bn = r.BN
		}
		if r.BT != nil {
			bt = *r.BT
		}
		name := bn + r.N
		if root != "" && strings.HasPrefix(name, root+"/") {
			name = name[len(root):]
		}
		p, err := ParsePath(name)
		if err != nil {
			return nil, err
		}
		var v any
		switch {
		case r.V != nil:
			v = *r.V
		case r.VS != nil:
			v = *r.VS
		case r.VB != nil:
			v = *r.VB
		case r.VD != nil:
			v = *r.VD
		case r.VLO != nil:
			v = *r.VLO
		default:
			continue
		}
		t := bt
		if r.T != nil {
			t += *r.T
		}
		out = append(out, TimedValue{Value: Value{p, v}, Time: senmlTime(t)})
	}
	return out, nil
}

// EncodeSenMLJSON encodes values as a SenML JSON pack (used by the test
// client and for writes when configured).
func EncodeSenMLJSON(vals []Value) ([]byte, error) {
	recs := make([]senml, 0, len(vals))
	for _, v := range vals {
		r := senml{N: v.Path.String()}
		switch x := v.V.(type) {
		case float64:
			r.V = &x
		case string:
			r.VS = &x
		case bool:
			r.VB = &x
		case []byte:
			s := base64.RawURLEncoding.EncodeToString(x)
			r.VD = &s
		default:
			return nil, fmt.Errorf("%s: %T cannot be written as SenML", v.Path, v.V)
		}
		recs = append(recs, r)
	}
	return json.Marshal(recs)
}

// ---- SenML CBOR (RFC 8428 clause 6; TS Core clause 7.4.6) ---------------

// senmlCBOR is a SenML record with the integer labels of RFC 8428 table 6
// (bn -2, bt -3, n 0, v 2, vs 3, vb 4, t 6, vd 8); LwM2M's object link
// value has no integer label and keeps its text key "vlo". Numbers are
// decoded as any because CBOR carries integers and floats separately.
type senmlCBOR struct {
	BN  *string `cbor:"-2,keyasint,omitempty"`
	BT  any     `cbor:"-3,keyasint,omitempty"`
	N   *string `cbor:"0,keyasint,omitempty"`
	V   any     `cbor:"2,keyasint,omitempty"`
	VS  *string `cbor:"3,keyasint,omitempty"`
	VB  *bool   `cbor:"4,keyasint,omitempty"`
	T   any     `cbor:"6,keyasint,omitempty"`
	VD  []byte  `cbor:"8,keyasint,omitempty"`
	VLO *string `cbor:"vlo,omitempty"`
}

func cborNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

// DecodeSenMLCBOR decodes a SenML CBOR pack into the same values as
// DecodeSenMLJSON (opaque values as hex, like TLV).
func DecodeSenMLCBOR(b []byte) ([]TimedValue, error) {
	return decodeSenMLCBOR(b, "")
}

func decodeSenMLCBOR(b []byte, root string) ([]TimedValue, error) {
	var recs []senmlCBOR
	if err := cbor.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("not a SenML CBOR pack: %w", err)
	}
	js := make([]senml, 0, len(recs))
	for _, r := range recs {
		j := senml{VS: r.VS, VB: r.VB, VLO: r.VLO}
		if r.BN != nil {
			j.BN = *r.BN
		}
		if r.N != nil {
			j.N = *r.N
		}
		for _, f := range []struct {
			in  any
			out **float64
		}{{r.BT, &j.BT}, {r.V, &j.V}, {r.T, &j.T}} {
			if f.in == nil {
				continue
			}
			n, ok := cborNumber(f.in)
			if !ok {
				return nil, fmt.Errorf("a SenML CBOR number of type %T", f.in)
			}
			*f.out = &n
		}
		if r.VD != nil {
			h := hex.EncodeToString(r.VD)
			j.VD = &h
		}
		js = append(js, j)
	}
	return decodeSenML(js, root)
}

// EncodeSenMLCBOR encodes values as a SenML CBOR pack (writes to 1.1
// clients, and a client answering reads).
//
// A whole number is written as a CBOR integer unless the built-in model
// types the resource Float, which is written as a CBOR float (Core
// appendix C); EncodeSenMLCBORModel takes another model.
func EncodeSenMLCBOR(vals []Value) ([]byte, error) {
	return encodeSenMLCBOR(nil, vals)
}

// EncodeSenMLCBORModel is EncodeSenMLCBOR typing values with m.
func EncodeSenMLCBORModel(m Model, vals []Value) ([]byte, error) {
	return encodeSenMLCBOR(m, vals)
}

func encodeSenMLCBOR(m Model, vals []Value) ([]byte, error) {
	recs := make([]senmlCBOR, 0, len(vals))
	for _, v := range vals {
		n := v.Path.String()
		r := senmlCBOR{N: &n}
		switch x := v.V.(type) {
		case float64:
			if x == math.Trunc(x) && math.Abs(x) < 1<<53 && m.Lookup(v.Path).Type != tFloat {
				r.V = int64(x)
			} else {
				r.V = x
			}
		case string:
			r.VS = &x
		case bool:
			r.VB = &x
		case []byte:
			r.VD = x
		default:
			return nil, fmt.Errorf("%s: %T cannot be written as SenML", v.Path, v.V)
		}
		recs = append(recs, r)
	}
	return cbor.Marshal(recs)
}

// encodeSenML encodes one resource value of model type typ in a SenML
// content format for a Write.
func encodeSenML(cf int, p Path, typ string, v any) ([]byte, error) {
	v, err := typedValue(typ, v)
	if err != nil {
		return nil, err
	}
	vals := []Value{{p, v}}
	if cf == cfSenMLCBOR {
		// The caller's type decides integer or float, not the model.
		return encodeSenMLCBOR(Model{"/" + strconv.Itoa(p.Obj) + "/" + strconv.Itoa(p.Res): {Type: typ}}, vals)
	}
	return EncodeSenMLJSON(vals)
}

// typedValue checks a command's value against the model type typ and
// returns it as the SenML and LwM2M CBOR encoders take it (an opaque value
// as bytes).
func typedValue(typ string, v any) (any, error) {
	switch typ {
	case tInteger, tTime, tUnsigned, tFloat:
		if _, ok := v.(float64); !ok {
			return nil, fmt.Errorf("%v is not a number", v)
		}
		if typ == tUnsigned && v.(float64) < 0 {
			return nil, fmt.Errorf("%v is not an unsigned integer", v)
		}
		if typ != tFloat && v.(float64) != math.Trunc(v.(float64)) {
			return nil, fmt.Errorf("%v is not an integer", v)
		}
	case tString, tCorelnk:
		if _, ok := v.(string); !ok {
			return nil, fmt.Errorf("%v is not a string", v)
		}
	case tBool:
		if _, ok := v.(bool); !ok {
			return nil, fmt.Errorf("%v is not a boolean", v)
		}
	case tOpaque:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("opaque values are written as hex strings")
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		v = b
	case tObjlnk:
		if s, ok := v.(string); !ok || !strings.Contains(s, ":") {
			return nil, fmt.Errorf("%v is not an object link \"obj:inst\"", v)
		}
	default:
		return nil, fmt.Errorf("resources of type %q cannot be written", typ)
	}
	return v, nil
}

// ---- text/plain for a single resource (TS Core clause 7.4.1) --------------

// Appendix C text column: numbers in ASCII, booleans "0" or "1", opaque
// in base64 (kept as hex, like the other formats).
// Booleans written true or false are not appendix C text; they are read
// and noted in lax.
func decodeText(m Model, p Path, b []byte, lax *[]string) (any, error) {
	s := string(b)
	switch m.Lookup(p).Type {
	case tInteger, tTime, tUnsigned, tFloat:
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", s)
		}
		return f, nil
	case tBool:
		switch strings.TrimSpace(s) {
		case "0":
			return false, nil
		case "1":
			return true, nil
		case "true", "TRUE", "True":
			note(lax, "text boolean %q read as 1", s)
			return true, nil
		case "false", "FALSE", "False":
			note(lax, "text boolean %q read as 0", s)
			return false, nil
		}
		return nil, fmt.Errorf("%q is not a boolean (0 or 1)", s)
	case tOpaque:
		raw, err := decodeBase64(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("opaque text is not base64: %w", err)
		}
		return hex.EncodeToString(raw), nil
	}
	return s, nil
}

// ---- LwM2M 1.0 JSON (application/vnd.oma.lwm2m+json; TS Core 1.1 clause
// 7.4.5 and 7.4.5.1) ---------------------------------------------------------

type lwm2mJSON struct {
	BN string  `json:"bn"`
	BT float64 `json:"bt"`
	E  []struct {
		N  string   `json:"n"`
		V  *float64 `json:"v"`
		SV *string  `json:"sv"`
		BV *bool    `json:"bv"`
		OV *string  `json:"ov"`
		T  *float64 `json:"t"`
	} `json:"e"`
}

// DecodeLwM2MJSON decodes the LwM2M 1.0 JSON format: a base name, a base
// time and an "e" array of entries with a number (v), string (sv), boolean
// (bv) or object link (ov) and an optional time relative to the base time.
// Times follow the SenML rules like DecodeSenMLJSON.
func DecodeLwM2MJSON(b []byte) ([]TimedValue, error) {
	return decodeLwM2MJSON(b, "")
}

func decodeLwM2MJSON(b []byte, root string) ([]TimedValue, error) {
	var doc lwm2mJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("not an LwM2M 1.0 JSON object: %w", err)
	}
	recs := make([]senml, 0, len(doc.E))
	for i, e := range doc.E {
		r := senml{N: e.N, V: e.V, VS: e.SV, VB: e.BV, VLO: e.OV, T: e.T}
		if i == 0 {
			r.BN = doc.BN
			bt := doc.BT
			r.BT = &bt
		}
		recs = append(recs, r)
	}
	return decodeSenML(recs, root)
}

// ---- application/cbor for a single resource (TS Core clause 7.4.3) --------

// decodeCBORValue reads one resource value in CBOR (appendix C CBOR
// column): integers and floats as numbers, a byte string as hex, a Time
// tagged 1 (epoch) as its number.
func decodeCBORValue(b []byte) (any, error) {
	var v any
	if err := cbor.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("not a CBOR value: %w", err)
	}
	if tg, ok := v.(cbor.Tag); ok && tg.Number == 1 {
		v = tg.Content
	}
	switch x := v.(type) {
	case time.Time:
		return float64(x.Unix()), nil
	case []byte:
		return hex.EncodeToString(x), nil
	case string, bool:
		return x, nil
	}
	if n, ok := cborNumber(v); ok {
		return n, nil
	}
	return nil, fmt.Errorf("a CBOR %T is not an LwM2M resource value", v)
}

// ---- CoRE link format of the registration payload (RFC 6690) --------------

// ParseLinks returns the object and object instance paths a client
// registers, skipping the root path and attributes.
func ParseLinks(s string) []string {
	_, links := parseRegistration(s)
	return links
}

// parseRegistration reads a Register or Update payload: the alternate
// path of the link with rt="oma.lwm2m" (Transport clause 6.4.1; "" for
// the root, and a link with a numeric segment is not one) and the object
// and object instance paths under it, without it.
func parseRegistration(s string) (root string, links []string) {
	type link struct{ target, params string }
	var all []link
	for _, l := range strings.Split(s, ",") {
		l = strings.TrimSpace(l)
		i, j := strings.IndexByte(l, '<'), strings.IndexByte(l, '>')
		if i != 0 || j < 0 {
			continue
		}
		all = append(all, link{strings.ReplaceAll(l[1:j], " ", ""), l[j+1:]})
	}
	for _, l := range all {
		if !strings.Contains(l.params, `rt="oma.lwm2m"`) && !strings.Contains(l.params, "rt=oma.lwm2m") {
			continue
		}
		r := "/" + strings.Trim(l.target, "/")
		numeric := false
		for _, seg := range strings.Split(strings.Trim(r, "/"), "/") {
			if _, err := strconv.Atoi(seg); err == nil {
				numeric = true
			}
		}
		if !numeric && r != "/" {
			root = r
		}
		break
	}
	for _, l := range all {
		p := l.target
		if root != "" {
			if !strings.HasPrefix(p, root+"/") {
				continue
			}
			p = p[len(root):]
		}
		if _, err := ParsePath(p); err == nil {
			links = append(links, p)
		}
	}
	return root, links
}
