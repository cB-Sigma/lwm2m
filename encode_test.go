// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lwm2m_test

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/cB-Sigma/lwm2m"
)

func path(t *testing.T, s string) lwm2m.Path {
	t.Helper()
	p, err := lwm2m.ParsePath(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func asMap(vals []lwm2m.Value) map[string]string {
	out := map[string]string{}
	for _, v := range vals {
		if m, ok := v.V.(map[string]any); ok {
			for ri, x := range m {
				out[v.Path.String()+"/"+ri] = fmt.Sprint(x)
			}
			continue
		}
		out[v.Path.String()] = fmt.Sprint(v.V)
	}
	return out
}

// Every content format round-trips an object instance (or a single
// value) through Encode and Decode.
func TestEncodeDecodeEveryFormat(t *testing.T) {
	inst := []lwm2m.Value{
		{Path: path(t, "/3/0/0"), V: "maker"},
		{Path: path(t, "/3/0/6/0"), V: 1.0},
		{Path: path(t, "/3/0/6/1"), V: 5.0},
		{Path: path(t, "/3/0/9"), V: 87.0},
		{Path: path(t, "/3/0/13"), V: 1700000000.0},
	}
	for _, cf := range []int{lwm2m.CFTLV, lwm2m.CFSenMLJSON, lwm2m.CFSenMLCBOR, lwm2m.CFLwM2MJSON, lwm2m.CFLwM2MCBOR} {
		b, err := lwm2m.Encode(cf, nil, path(t, "/3/0"), inst)
		if err != nil {
			t.Fatalf("encode %d: %v", cf, err)
		}
		got, err := lwm2m.Decode(cf, nil, path(t, "/3/0"), b)
		if err != nil {
			t.Fatalf("decode %d: %v", cf, err)
		}
		if g, w := fmt.Sprint(asMap(got)), fmt.Sprint(asMap(inst)); g != w {
			t.Errorf("format %d: %s, want %s", cf, g, w)
		}
	}
	// A whole object in TLV keeps its instances.
	obj := []lwm2m.Value{{Path: path(t, "/3303/0/5700"), V: 21.5}, {Path: path(t, "/3303/1/5700"), V: -4.0}}
	b, _ := lwm2m.Encode(lwm2m.CFTLV, nil, path(t, "/3303"), obj)
	got, err := lwm2m.Decode(lwm2m.CFTLV, nil, path(t, "/3303"), b)
	if err != nil || fmt.Sprint(asMap(got)) != fmt.Sprint(asMap(obj)) {
		t.Errorf("TLV object = %v %v", got, err)
	}
	// Single values.
	for _, c := range []struct {
		p    string
		v    any
		cf   int
		want string
	}{
		{"/3/0/9", 87.0, lwm2m.CFText, "87"},
		{"/3303/0/5700", 21.5, lwm2m.CFText, "21.5"},
		{"/1/0/6", true, lwm2m.CFText, "1"},
		{"/5/0/0", "0a0b", lwm2m.CFText, "Cgs="},
		{"/5/0/0", "0a0b", lwm2m.CFOpaque, "\n\v"},
		{"/3/0/0", "maker", lwm2m.CFCBOR, "emaker"},
	} {
		b, err := lwm2m.Encode(c.cf, nil, path(t, c.p), []lwm2m.Value{{Path: path(t, c.p), V: c.v}})
		if err != nil || string(b) != c.want {
			t.Errorf("%s as %d = %q %v, want %q", c.p, c.cf, b, err, c.want)
			continue
		}
		got, err := lwm2m.Decode(c.cf, nil, path(t, c.p), b)
		if err != nil || fmt.Sprint(got[0].V) != fmt.Sprint(c.v) {
			t.Errorf("%s as %d decodes to %v %v", c.p, c.cf, got, err)
		}
	}
	if _, err := lwm2m.Encode(lwm2m.CFText, nil, path(t, "/3/0"), inst); err == nil {
		t.Error("several values were written as plain text")
	}
	// A time in CBOR is tagged epoch time.
	b, _ = lwm2m.EncodeCBORValue(lwm2m.TTime, 1700000000.0)
	if !bytes.HasPrefix(b, []byte{0xC1}) {
		t.Errorf("CBOR time = %x, want tag 1", b)
	}
}

// Regression: a Float resource holding a whole number was written as a
// CBOR integer in SenML CBOR and LwM2M CBOR, which Leshan 2.0.0-M18
// refuses ("Floating-point number expected but was -40"); Core appendix
// C has Float encoded as a CBOR float.
func TestCBORFloatResourcesStayFloats(t *testing.T) {
	vals := []lwm2m.Value{{Path: path(t, "/3303/0/5603"), V: -40.0}, {Path: path(t, "/3/0/9"), V: 87.0}}
	majors := func(b []byte, _ bool) []string {
		var out []string
		var recs []map[int]cbor.RawMessage
		if err := cbor.Unmarshal(b, &recs); err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			out = append(out, kind(r[2]))
		}
		sort.Strings(out)
		return out
	}
	b, err := lwm2m.EncodeSenMLCBOR(vals)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(majors(b, true)); got != "[float int]" {
		t.Errorf("SenML CBOR value kinds = %s, want the Float resource as a float", got)
	}
	b, err = lwm2m.EncodeLwM2MCBOR(vals)
	if err != nil {
		t.Fatal(err)
	}
	minus40, _ := cbor.Marshal(-40.0) // a float64 item
	if !bytes.Contains(b, minus40) || !bytes.Contains(b, []byte{0x18, 87}) {
		t.Errorf("LwM2M CBOR = %x, want -40 as a float and 87 as an integer", b)
	}
	// A server's write of a float resource (EncodeSenML with its type).
	b, _ = lwm2m.EncodeSenML(lwm2m.CFSenMLCBOR, path(t, "/3303/0/5603"), lwm2m.TFloat, -40.0)
	if got := fmt.Sprint(majors(b, true)); got != "[float]" {
		t.Errorf("EncodeSenML float = %s", got)
	}
	// Decoding is unchanged.
	tv, err := lwm2m.DecodeSenMLCBOR(b)
	if err != nil || tv[0].V != -40.0 {
		t.Errorf("decode = %v %v", tv, err)
	}
}

// kind is "int" or "float" for a CBOR number item.
func kind(raw cbor.RawMessage) string {
	if len(raw) == 0 {
		return "none"
	}
	switch raw[0] >> 5 {
	case 0, 1:
		return "int"
	case 7:
		return "float"
	}
	return fmt.Sprintf("major %d", raw[0]>>5)
}

func TestDecodeSenMLNames(t *testing.T) {
	b, _ := lwm2m.EncodePaths(lwm2m.CFSenMLCBOR, []string{"/3/0/0", "/3303/0"})
	ps, err := lwm2m.DecodeSenMLNames(b, true)
	if err != nil || fmt.Sprint(ps) != "[/3/0/0 /3303/0]" {
		t.Errorf("CBOR names = %v %v", ps, err)
	}
	ps, err = lwm2m.DecodeSenMLNames([]byte(`[{"bn":"/3/0/","n":"0"},{"n":"1"}]`), false)
	if err != nil || fmt.Sprint(ps) != "[/3/0/0 /3/0/1]" {
		t.Errorf("JSON names = %v %v", ps, err)
	}
}
