package lwm2m

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ---- LwM2M CBOR (application/vnd.oma.lwm2m+cbor, 11544; Core 1.2 clause
// 7.5.4) ---------------------------------------------------------------------
//
// Our reading of the format: a payload is one CBOR map. Each key is an
// unsigned integer ID or an array of IDs; the IDs along a chain of nested
// maps form a path that starts at the Object ID (object, instance, resource,
// resource instance). A value that is not a map is the value of the path
// its keys name. Maps and arrays may have definite or indefinite length.
// Values use the CBOR column of appendix C: integers, unsigned integers,
// floats, text, booleans, byte strings (opaque), a time as an integer or a
// tag 0/1 date, an object link as "obj:inst" text and null for none.

// DecodeLwM2MCBOR decodes an LwM2M CBOR payload into resource values; paths
// come from the payload, so no base path is needed.
func DecodeLwM2MCBOR(b []byte) ([]TimedValue, error) {
	return decodeLwM2MCBOR(nil, b, "", nil)
}

// decodeLwM2MCBOR decodes a payload; the model and root are not needed by
// the format (its values carry their CBOR types and its paths are numeric)
// and are taken for symmetry with the other decoders.
func decodeLwM2MCBOR(_ Model, b []byte, _ string, lax *[]string) ([]TimedValue, error) {
	var out []TimedValue
	rest, err := walkLwM2MCBOR(b, nil, &out, lax)
	if err != nil {
		return nil, fmt.Errorf("not an LwM2M CBOR payload: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("not an LwM2M CBOR payload: %d bytes after the map", len(rest))
	}
	return out, nil
}

// cborHead reads a map or array head: its major type, its item count, or
// -1 for indefinite length, and the bytes after it.
func cborHead(b []byte) (major byte, n int, rest []byte, err error) {
	if len(b) == 0 {
		return 0, 0, nil, errors.New("cut short")
	}
	major, info := b[0]>>5, b[0]&0x1f
	switch {
	case info < 24:
		return major, int(info), b[1:], nil
	case info == 31:
		return major, -1, b[1:], nil
	case info > 27:
		return 0, 0, nil, fmt.Errorf("reserved additional information %d", info)
	}
	size := 1 << (info - 24) // 1, 2, 4 or 8 bytes
	if len(b) < 1+size {
		return 0, 0, nil, errors.New("cut short")
	}
	var v uint64
	for _, x := range b[1 : 1+size] {
		v = v<<8 | uint64(x)
	}
	if v > 1<<20 {
		return 0, 0, nil, fmt.Errorf("a map of %d items", v)
	}
	return major, int(v), b[1+size:], nil
}

func walkLwM2MCBOR(b []byte, prefix []int, out *[]TimedValue, lax *[]string) ([]byte, error) {
	major, n, b, err := cborHead(b)
	if err != nil {
		return nil, err
	}
	if major != 5 {
		return nil, fmt.Errorf("major type %d where a map was expected", major)
	}
	for i := 0; n < 0 || i < n; i++ {
		if n < 0 {
			if len(b) == 0 {
				return nil, errors.New("indefinite map without a break")
			}
			if b[0] == 0xFF {
				return b[1:], nil
			}
		}
		var key any
		if b, err = cbor.UnmarshalFirst(b, &key); err != nil {
			return nil, err
		}
		ids, err := cborIDs(key)
		if err != nil {
			return nil, err
		}
		path := append(append([]int{}, prefix...), ids...)
		if len(path) > 4 {
			return nil, fmt.Errorf("a path of %d IDs", len(path))
		}
		if len(b) > 0 && b[0]>>5 == 5 {
			if b, err = walkLwM2MCBOR(b, path, out, lax); err != nil {
				return nil, err
			}
			continue
		}
		var raw any
		if b, err = cbor.UnmarshalFirst(b, &raw); err != nil {
			return nil, err
		}
		if len(path) < 3 {
			return nil, fmt.Errorf("a value at %v, which is not a resource", path)
		}
		p := Path{path[0], path[1], path[2], -1}
		if len(path) == 4 {
			p.RI = path[3]
		}
		if raw == nil {
			continue // null: no value (appendix C "none")
		}
		v, err := cborLeaf(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		*out = append(*out, TimedValue{Value: Value{p, v}})
	}
	return b, nil
}

// cborIDs reads a key: one ID, or an array of IDs.
func cborIDs(key any) ([]int, error) {
	id := func(x any) (int, error) {
		n, ok := x.(uint64)
		if !ok || n > math.MaxUint16 {
			return 0, fmt.Errorf("key %v is not an LwM2M ID", x)
		}
		return int(n), nil
	}
	if arr, ok := key.([]any); ok {
		if len(arr) == 0 {
			return nil, errors.New("an empty key array")
		}
		out := make([]int, 0, len(arr))
		for _, x := range arr {
			n, err := id(x)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, nil
	}
	n, err := id(key)
	return []int{n}, err
}

// cborLeaf maps a decoded CBOR value to the values the other formats give:
// numbers as float64, byte strings as hex, times as Unix seconds.
func cborLeaf(v any) (any, error) {
	if tg, ok := v.(cbor.Tag); ok {
		switch tg.Number {
		case 0:
			s, ok := tg.Content.(string)
			t, err := time.Parse(time.RFC3339, s)
			if !ok || err != nil {
				return nil, fmt.Errorf("tag 0 date %v is not RFC 3339", tg.Content)
			}
			return float64(t.Unix()), nil
		case 1:
			v = tg.Content
		default:
			return nil, fmt.Errorf("CBOR tag %d is not an LwM2M value", tg.Number)
		}
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

// EncodeLwM2MCBOR encodes values as an LwM2M CBOR payload. One value is
// keyed by its full path; values of the same object instance share one
// [object, instance] key whose map holds the resources, a multiple
// instance resource as a map of its instances; an instance with a single
// value is keyed by that value's full path. Keys keep the order of vals.
// Values are float64 (integral ones become CBOR integers), string, bool,
// []byte (a byte string) or nil (null).
// A Float resource of the built-in model is written as a CBOR float even
// when it is a whole number; EncodeLwM2MCBORModel takes another model.
func EncodeLwM2MCBOR(vals []Value) ([]byte, error) {
	return EncodeLwM2MCBORModel(nil, vals)
}

// cborFloat is a value written as a CBOR float even when it is whole.
type cborFloat float64

// EncodeLwM2MCBORModel is EncodeLwM2MCBOR typing values with m.
func EncodeLwM2MCBORModel(m Model, vals []Value) ([]byte, error) {
	typed := make([]Value, len(vals))
	for i, v := range vals {
		typed[i] = v
		if x, ok := v.V.(float64); ok && m.Lookup(v.Path).Type == tFloat {
			typed[i].V = cborFloat(x)
		}
	}
	return encodeLwM2MCBOR(typed)
}

func encodeLwM2MCBOR(vals []Value) ([]byte, error) {
	if len(vals) == 1 {
		return lwm2mCBORMap([]cborEntry{{fullKey(vals[0].Path), vals[0].V, nil}})
	}
	type group struct {
		obj, inst int
		vals      []Value
	}
	var groups []*group
	idx := map[[2]int]*group{}
	for _, v := range vals {
		if v.Path.Obj < 0 || v.Path.Inst < 0 || v.Path.Res < 0 {
			return nil, fmt.Errorf("%s is not a resource path", v.Path)
		}
		k := [2]int{v.Path.Obj, v.Path.Inst}
		g := idx[k]
		if g == nil {
			g = &group{obj: k[0], inst: k[1]}
			idx[k] = g
			groups = append(groups, g)
		}
		g.vals = append(g.vals, v)
	}
	var top []cborEntry
	for _, g := range groups {
		if len(g.vals) == 1 {
			top = append(top, cborEntry{fullKey(g.vals[0].Path), g.vals[0].V, nil})
			continue
		}
		var res []cborEntry
		resIdx := map[int]int{}
		for _, v := range g.vals {
			if v.Path.RI < 0 {
				res = append(res, cborEntry{uint64(v.Path.Res), v.V, nil})
				continue
			}
			i, ok := resIdx[v.Path.Res]
			if !ok {
				i = len(res)
				resIdx[v.Path.Res] = i
				res = append(res, cborEntry{key: uint64(v.Path.Res), sub: []cborEntry{}})
			}
			res[i].sub = append(res[i].sub, cborEntry{uint64(v.Path.RI), v.V, nil})
		}
		top = append(top, cborEntry{[]uint64{uint64(g.obj), uint64(g.inst)}, nil, res})
	}
	return lwm2mCBORMap(top)
}

type cborEntry struct {
	key any // uint64 or []uint64
	v   any
	sub []cborEntry // a nested map instead of v, when not nil
}

func fullKey(p Path) []uint64 {
	k := []uint64{uint64(p.Obj), uint64(p.Inst), uint64(p.Res)}
	if p.RI >= 0 {
		k = append(k, uint64(p.RI))
	}
	return k
}

func lwm2mCBORMap(es []cborEntry) ([]byte, error) {
	out := cborMapHead(len(es))
	for _, e := range es {
		kb, err := cbor.Marshal(e.key)
		if err != nil {
			return nil, err
		}
		out = append(out, kb...)
		if e.sub != nil {
			sb, err := lwm2mCBORMap(e.sub)
			if err != nil {
				return nil, err
			}
			out = append(out, sb...)
			continue
		}
		vb, err := cborValue(e.v)
		if err != nil {
			return nil, err
		}
		out = append(out, vb...)
	}
	return out, nil
}

func cborMapHead(n int) []byte {
	switch {
	case n < 24:
		return []byte{0xA0 | byte(n)}
	case n < 1<<8:
		return []byte{0xB8, byte(n)}
	case n < 1<<16:
		return []byte{0xB9, byte(n >> 8), byte(n)}
	}
	return []byte{0xBA, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func cborValue(v any) ([]byte, error) {
	switch x := v.(type) {
	case cborFloat:
		return cbor.Marshal(float64(x))
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<63 {
			return cbor.Marshal(int64(x))
		}
		return cbor.Marshal(x)
	case string, bool, []byte, nil:
		return cbor.Marshal(x)
	}
	return nil, fmt.Errorf("%T cannot be written as LwM2M CBOR", v)
}
