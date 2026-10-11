// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lwm2m

import (
	"strings"
	"testing"
)

// A made-up object in the DDF layout (not an OMNA file): its resources
// become a Model that types a TLV read.
const testDDF = `<?xml version="1.0" encoding="utf-8"?>
<LWM2M xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Object ObjectType="MODefinition">
    <Name>Demo Meter</Name>
    <ObjectID>32769</ObjectID>
    <Resources>
      <Item ID="0"><Name>Energy Total</Name><Operations>R</Operations><MultipleInstances>Single</MultipleInstances><Mandatory>Mandatory</Mandatory><Type>Float</Type><Units>kWh</Units></Item>
      <Item ID="1"><Name>Serial</Name><Operations>R</Operations><Type>String</Type><Units></Units></Item>
      <Item ID="2"><Name>Pulses</Name><Operations>RW</Operations><Type>Unsigned Integer</Type></Item>
      <Item ID="3"><Name>Reset Counter</Name><Operations>E</Operations><Type></Type></Item>
    </Resources>
  </Object>
</LWM2M>`

func TestParseDDF(t *testing.T) {
	m, err := ParseDDF(strings.NewReader(testDDF))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ResourceDef{
		"/32769/0": {"energy-total", tFloat, "kWh"}, "/32769/1": {"serial", tString, ""},
		"/32769/2": {"pulses", tUnsigned, ""}, "/32769/3": {"reset-counter", tExec, ""},
	}
	for k, w := range want {
		if m[k] != w {
			t.Errorf("%s = %+v, want %+v", k, m[k], w)
		}
	}
	// TLV carries no types: the model types the float.
	b, err := EncodeTLV(m, Path{Obj: 32769, Inst: 0, Res: -1, RI: -1}, []Value{{Path: Path{Obj: 32769, Inst: 0, Res: 0, RI: -1}, V: 12.5}})
	if err != nil {
		t.Fatal(err)
	}
	vals, err := DecodeTLV(m, Path{Obj: 32769, Inst: 0, Res: -1, RI: -1}, b)
	if err != nil || len(vals) != 1 || vals[0].V != 12.5 {
		t.Errorf("TLV with the DDF model: %v %v", vals, err)
	}
	if got := Model(nil).Merge(m).Lookup(Path{Obj: 3303, Res: 5700}); got.Type != tFloat {
		t.Errorf("merge lost the built-in model: %+v", got)
	}
	if _, err := ParseDDF(strings.NewReader(`<LWM2M></LWM2M>`)); err == nil {
		t.Error("a file without objects was read")
	}
}
