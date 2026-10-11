// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lwm2m_test

import (
	"fmt"

	"github.com/cB-Sigma/lwm2m"
)

// A temperature resource written as OMA TLV and read back with the
// built-in object model, which gives its data type.
func Example() {
	b, _ := lwm2m.EncodeScalar(lwm2m.TFloat, 21.5)
	inst := lwm2m.EncodeInstanceTLV(0, map[int][]byte{5700: b})
	p, _ := lwm2m.ParsePath("/3303")
	vals, err := lwm2m.DecodeTLV(nil, p, inst)
	for _, v := range vals {
		fmt.Println(v.Path, v.V, lwm2m.Model(nil).Lookup(v.Path).Unit)
	}
	fmt.Println(err)
	// Output:
	// /3303/0/5700 21.5 Cel
	// <nil>
}

// The same instance encoded in two formats and decoded back.
func ExampleEncode() {
	base, _ := lwm2m.ParsePath("/3303/0")
	vals := []lwm2m.Value{
		{Path: lwm2m.Path{Obj: 3303, Inst: 0, Res: 5700, RI: -1}, V: 21.5},
		{Path: lwm2m.Path{Obj: 3303, Inst: 0, Res: 5701, RI: -1}, V: "Cel"},
	}
	for _, cf := range []int{lwm2m.CFLwM2MJSON, lwm2m.CFSenMLCBOR} {
		b, _ := lwm2m.Encode(cf, nil, base, vals)
		back, err := lwm2m.Decode(cf, nil, base, b)
		fmt.Println(cf, back, err)
	}
	// Output:
	// 11543 [{/3303/0/5700 21.5} {/3303/0/5701 Cel}] <nil>
	// 112 [{/3303/0/5700 21.5} {/3303/0/5701 Cel}] <nil>
}

// A SenML JSON pack with a base name and a base time.
func ExampleDecodeSenMLJSON() {
	vals, err := lwm2m.DecodeSenMLJSON([]byte(`[{"bn":"/3303/0/","bt":1700000000,"n":"5700","v":21.5}]`))
	for _, v := range vals {
		fmt.Println(v.Path, v.V, v.Time.Unix())
	}
	fmt.Println(err)
	// Output:
	// /3303/0/5700 21.5 1700000000
	// <nil>
}
