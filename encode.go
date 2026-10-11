// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lwm2m

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// This file holds the encoders a client (or a server writing) needs for
// every content format, and Encode and Decode, which pick the format by
// its Content-Format number. Values follow the package's conventions:
// numbers and times as float64, strings, booleans, opaque values as hex
// strings, object links as "obj:inst", a multiple-instance resource as
// one Value per resource instance (Path.RI set).

// ErrNotSingle is returned when a format that carries one value (plain
// text, opaque, CBOR) is asked for several.
var ErrNotSingle = errors.New("lwm2m: this content format carries a single resource value")

// EncodeText encodes one value of data type typ as plain text (Core
// appendix C, text column): numbers in decimal, booleans as 0 or 1,
// opaque values in base64, object links as "obj:inst".
func EncodeText(typ string, v any) ([]byte, error) {
	switch typ {
	case tString, tCorelnk, tObjlnk:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not a string", v)
		}
		return []byte(s), nil
	case tInteger, tTime, tUnsigned:
		f, ok := v.(float64)
		if !ok || f != math.Trunc(f) {
			return nil, fmt.Errorf("%v is not an integer", v)
		}
		if typ == tUnsigned {
			if f < 0 {
				return nil, fmt.Errorf("%v is not an unsigned integer", v)
			}
			return []byte(strconv.FormatUint(uint64(f), 10)), nil
		}
		return []byte(strconv.FormatInt(int64(f), 10)), nil
	case tFloat:
		f, ok := v.(float64)
		if !ok {
			return nil, fmt.Errorf("%v is not a number", v)
		}
		return []byte(strconv.FormatFloat(f, 'g', -1, 64)), nil
	case tBool:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%v is not a boolean", v)
		}
		if b {
			return []byte("1"), nil
		}
		return []byte("0"), nil
	case tOpaque:
		raw, err := opaqueBytes(v)
		if err != nil {
			return nil, err
		}
		return []byte(base64.StdEncoding.EncodeToString(raw)), nil
	}
	return nil, fmt.Errorf("resources of type %q have no text form", typ)
}

// EncodeCBORValue encodes one value of data type typ as a single CBOR
// data item (Content-Format 60, Core appendix C CBOR column): integers as
// CBOR integers, floats as floats, a time as an epoch time (tag 1), an
// opaque value as a byte string.
func EncodeCBORValue(typ string, v any) ([]byte, error) {
	switch typ {
	case tString, tCorelnk, tObjlnk:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not a string", v)
		}
		return cbor.Marshal(s)
	case tInteger, tUnsigned, tTime:
		f, ok := v.(float64)
		if !ok || f != math.Trunc(f) {
			return nil, fmt.Errorf("%v is not an integer", v)
		}
		if typ == tUnsigned {
			if f < 0 {
				return nil, fmt.Errorf("%v is not an unsigned integer", v)
			}
			return cbor.Marshal(uint64(f))
		}
		if typ == tTime {
			return cbor.Marshal(cbor.Tag{Number: 1, Content: int64(f)})
		}
		return cbor.Marshal(int64(f))
	case tFloat:
		f, ok := v.(float64)
		if !ok {
			return nil, fmt.Errorf("%v is not a number", v)
		}
		return cbor.Marshal(f)
	case tBool:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%v is not a boolean", v)
		}
		return cbor.Marshal(b)
	case tOpaque:
		raw, err := opaqueBytes(v)
		if err != nil {
			return nil, err
		}
		return cbor.Marshal(raw)
	}
	return nil, fmt.Errorf("resources of type %q have no CBOR form", typ)
}

// opaqueBytes takes an opaque value as bytes or as a hex string.
func opaqueBytes(v any) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case string:
		b, err := hex.DecodeString(x)
		if err != nil {
			return nil, fmt.Errorf("opaque value %q is not hex: %w", x, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%v is not an opaque value", v)
}

// EncodeTLV encodes vals as an OMA TLV payload answering a request for
// base: object instances when base is an object, resources when it is an
// object instance, a resource (single or multiple) when it is a resource,
// one resource instance when it names one. Types come from m (nil is the
// built-in model).
func EncodeTLV(m Model, base Path, vals []Value) ([]byte, error) {
	switch {
	case base.Obj < 0:
		return nil, errors.New("lwm2m: TLV needs at least an object in the base path")
	case base.Inst < 0:
		insts := map[int][]Value{}
		var ids []int
		for _, v := range vals {
			if v.Path.Inst < 0 || v.Path.Res < 0 {
				return nil, fmt.Errorf("%s is not a resource path", v.Path)
			}
			if _, ok := insts[v.Path.Inst]; !ok {
				ids = append(ids, v.Path.Inst)
			}
			insts[v.Path.Inst] = append(insts[v.Path.Inst], v)
		}
		sort.Ints(ids)
		var out []byte
		for _, id := range ids {
			body, err := tlvResources(m, insts[id])
			if err != nil {
				return nil, err
			}
			out = appendTLV(out, tlvObjInst, id, body)
		}
		return out, nil
	case base.Res < 0:
		return tlvResources(m, vals)
	case base.RI >= 0:
		if len(vals) != 1 {
			return nil, ErrNotSingle
		}
		b, err := EncodeScalar(m.Lookup(base).Type, vals[0].V)
		if err != nil {
			return nil, err
		}
		return appendTLV(nil, tlvResInst, base.RI, b), nil
	}
	return tlvResources(m, vals)
}

// tlvResources encodes the resources of one object instance, in resource
// order; values with a resource instance become a multiple resource.
func tlvResources(m Model, vals []Value) ([]byte, error) {
	type res struct {
		single *Value
		multi  []Value
	}
	byID := map[int]*res{}
	var ids []int
	for i := range vals {
		v := vals[i]
		if v.Path.Res < 0 {
			return nil, fmt.Errorf("%s is not a resource path", v.Path)
		}
		r := byID[v.Path.Res]
		if r == nil {
			r = &res{}
			byID[v.Path.Res] = r
			ids = append(ids, v.Path.Res)
		}
		if v.Path.RI >= 0 {
			r.multi = append(r.multi, v)
		} else {
			r.single = &vals[i]
		}
	}
	sort.Ints(ids)
	var out []byte
	for _, id := range ids {
		r := byID[id]
		if r.multi == nil && r.single != nil {
			b, err := EncodeScalar(m.Lookup(r.single.Path).Type, r.single.V)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", r.single.Path, err)
			}
			out = appendTLV(out, tlvResValue, id, b)
			continue
		}
		sort.Slice(r.multi, func(i, j int) bool { return r.multi[i].Path.RI < r.multi[j].Path.RI })
		var body []byte
		for _, v := range r.multi {
			b, err := EncodeScalar(m.Lookup(v.Path).Type, v.V)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", v.Path, err)
			}
			body = appendTLV(body, tlvResInst, v.Path.RI, b)
		}
		out = appendTLV(out, tlvMultiRes, id, body)
	}
	return out, nil
}

// EncodeLwM2MJSON encodes vals in the LwM2M 1.0 JSON format
// (application/vnd.oma.lwm2m+json): base name base plus "/", one entry
// per value named relative to it, numbers in v, booleans in bv, object
// links in ov, strings and opaque values (base64) in sv.
func EncodeLwM2MJSON(m Model, base Path, vals []Value) ([]byte, error) {
	type entry struct {
		N  string   `json:"n,omitempty"`
		V  *float64 `json:"v,omitempty"`
		SV *string  `json:"sv,omitempty"`
		BV *bool    `json:"bv,omitempty"`
		OV *string  `json:"ov,omitempty"`
	}
	bn := base.String() + "/"
	doc := struct {
		BN string  `json:"bn"`
		E  []entry `json:"e"`
	}{BN: bn, E: make([]entry, 0, len(vals))}
	for _, v := range vals {
		name := strings.TrimPrefix(v.Path.String(), base.String())
		name = strings.TrimPrefix(name, "/")
		e := entry{N: name}
		switch typ := m.Lookup(v.Path).Type; typ {
		case tObjlnk:
			s, ok := v.V.(string)
			if !ok {
				return nil, fmt.Errorf("%s: %v is not an object link", v.Path, v.V)
			}
			e.OV = &s
		case tOpaque:
			raw, err := opaqueBytes(v.V)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", v.Path, err)
			}
			s := base64.StdEncoding.EncodeToString(raw)
			e.SV = &s
		default:
			switch x := v.V.(type) {
			case float64:
				e.V = &x
			case string:
				e.SV = &x
			case bool:
				e.BV = &x
			default:
				return nil, fmt.Errorf("%s: %T cannot be written as LwM2M JSON", v.Path, v.V)
			}
		}
		doc.E = append(doc.E, e)
	}
	return json.Marshal(doc)
}

// senmlValues turns opaque values (hex strings) into bytes for the SenML
// and LwM2M CBOR encoders, which write []byte as opaque.
func senmlValues(m Model, vals []Value) ([]Value, error) {
	out := make([]Value, len(vals))
	for i, v := range vals {
		out[i] = v
		if m.Lookup(v.Path).Type == tOpaque {
			raw, err := opaqueBytes(v.V)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", v.Path, err)
			}
			out[i].V = raw
		}
	}
	return out, nil
}

// DecodeSenMLNames reads the names of a SenML pack, JSON or CBOR, whose
// records may carry no value: the paths of a Read-Composite or
// Observe-Composite request (Core clause 5.4.6). Base names resolve as in
// DecodeSenMLJSON.
func DecodeSenMLNames(b []byte, isCBOR bool) ([]Path, error) {
	var names [][2]string // bn, n
	if isCBOR {
		var recs []senmlCBOR
		if err := cbor.Unmarshal(b, &recs); err != nil {
			return nil, fmt.Errorf("not a SenML CBOR pack: %w", err)
		}
		for _, r := range recs {
			var bn, n string
			if r.BN != nil {
				bn = *r.BN
			}
			if r.N != nil {
				n = *r.N
			}
			names = append(names, [2]string{bn, n})
		}
	} else {
		var recs []senml
		if err := json.Unmarshal(b, &recs); err != nil {
			return nil, fmt.Errorf("not a SenML JSON pack: %w", err)
		}
		for _, r := range recs {
			names = append(names, [2]string{r.BN, r.N})
		}
	}
	var out []Path
	bn := ""
	for _, x := range names {
		if x[0] != "" {
			bn = x[0]
		}
		p, err := ParsePath(bn + x[1])
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Encode encodes vals, the answer to a request for base, in Content-Format
// cf: CFTLV, CFSenMLJSON, CFSenMLCBOR, CFLwM2MJSON, CFLwM2MCBOR, or for a
// single resource value CFText, CFOpaque (an opaque resource only) and
// CFCBOR. Types come from m (nil is the built-in model).
func Encode(cf int, m Model, base Path, vals []Value) ([]byte, error) {
	switch cf {
	case cfTLV:
		return EncodeTLV(m, base, vals)
	case cfSenMLJSON, cfSenMLCBOR, cfLwM2MCBOR:
		sv, err := senmlValues(m, vals)
		if err != nil {
			return nil, err
		}
		switch cf {
		case cfSenMLJSON:
			return EncodeSenMLJSON(sv)
		case cfSenMLCBOR:
			return EncodeSenMLCBORModel(m, sv)
		}
		return EncodeLwM2MCBORModel(m, sv)
	case cfLwM2MJSON:
		return EncodeLwM2MJSON(m, base, vals)
	case cfText, cfOpaque, cfCBOR:
		if len(vals) != 1 || vals[0].Path.Res < 0 {
			return nil, ErrNotSingle
		}
		typ := m.Lookup(vals[0].Path).Type
		switch cf {
		case cfText:
			return EncodeText(typ, vals[0].V)
		case cfCBOR:
			return EncodeCBORValue(typ, vals[0].V)
		}
		if typ != tOpaque {
			return nil, fmt.Errorf("%s is not an opaque resource", vals[0].Path)
		}
		return opaqueBytes(vals[0].V)
	}
	return nil, fmt.Errorf("lwm2m: content format %d is not supported", cf)
}

// Decode decodes a payload of Content-Format cf sent for base (a Write
// or a Read answer) into values, typed with m (nil is the built-in model).
// Single-value formats (text, opaque, CBOR) need base to be a resource.
func Decode(cf int, m Model, base Path, b []byte) ([]Value, error) {
	untime := func(tv []TimedValue, err error) ([]Value, error) {
		if err != nil {
			return nil, err
		}
		out := make([]Value, len(tv))
		for i, v := range tv {
			out[i] = v.Value
		}
		return out, nil
	}
	switch cf {
	case cfTLV:
		return DecodeTLV(m, base, b)
	case cfSenMLJSON:
		return untime(DecodeSenMLJSON(b))
	case cfSenMLCBOR:
		return untime(DecodeSenMLCBOR(b))
	case cfLwM2MJSON:
		return untime(DecodeLwM2MJSON(b))
	case cfLwM2MCBOR:
		return untime(decodeLwM2MCBOR(m, b, "", nil))
	case cfText, cfOpaque, cfCBOR:
		if base.Res < 0 {
			return nil, ErrNotSingle
		}
		var v any
		var err error
		switch cf {
		case cfText:
			v, err = decodeText(m, base, b, nil)
		case cfOpaque:
			v = hex.EncodeToString(b)
		default:
			v, err = decodeCBORValue(b)
		}
		if err != nil {
			return nil, err
		}
		return []Value{{base, v}}, nil
	}
	return nil, fmt.Errorf("lwm2m: content format %d is not supported", cf)
}
