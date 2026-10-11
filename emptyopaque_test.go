// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lwm2m

import (
	"bytes"
	"testing"
)

// An empty opaque value (a Security instance's unused key, say) is still
// a record with a value: SenML CBOR writes an empty byte string for vd, so
// a peer finds a value field. Found by Leshan refusing a Bootstrap-Write.
func TestEmptyOpaqueKeepsItsValue(t *testing.T) {
	p, _ := ParsePath("/0/1/5")
	for _, cf := range []int{CFSenMLCBOR, CFSenMLJSON, CFLwM2MCBOR, CFTLV} {
		b, err := Encode(cf, nil, Path{Obj: 0, Inst: 1, Res: -1, RI: -1}, []Value{{Path: p, V: ""}})
		if err != nil {
			t.Fatalf("%d: %v", cf, err)
		}
		if cf == CFSenMLCBOR && !bytes.Contains(b, []byte{0x08, 0x40}) {
			t.Errorf("SenML CBOR %x has no empty vd", b)
		}
		vals, err := Decode(cf, nil, Path{Obj: 0, Inst: 1, Res: -1, RI: -1}, b)
		if err != nil || len(vals) != 1 || vals[0].V != "" {
			t.Errorf("%d: round trip %v %v (%x)", cf, vals, err, b)
		}
	}
}
