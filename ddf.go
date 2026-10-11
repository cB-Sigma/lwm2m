// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lwm2m

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ddf is the part of an OMA object definition (DDF) file read here: the
// LWM2M element holds one or more Object elements, each with its ObjectID
// and Resources/Item elements carrying ID, Name, Operations, Type and
// Units.
type ddf struct {
	Objects []struct {
		ObjectID  int    `xml:"ObjectID"`
		Name      string `xml:"Name"`
		Resources []struct {
			ID         int    `xml:"ID,attr"`
			Name       string `xml:"Name"`
			Operations string `xml:"Operations"`
			Type       string `xml:"Type"`
			Units      string `xml:"Units"`
		} `xml:"Resources>Item"`
	} `xml:"Object"`
}

// ddfTypes maps a DDF Type to the model's data type.
var ddfTypes = map[string]string{
	"string": tString, "integer": tInteger, "unsigned integer": tUnsigned, "float": tFloat,
	"boolean": tBool, "opaque": tOpaque, "time": tTime, "objlnk": tObjlnk, "corelnk": tCorelnk,
}

// ParseDDF reads an OMA object definition (DDF) XML file, as the OMNA
// registry publishes them, into a Model holding every resource of every
// object in it: a short name made from the resource name, the data type
// (an executable resource has the type "execute") and the unit. Merge
// several files with Model.Merge.
func ParseDDF(r io.Reader) (Model, error) {
	var d ddf
	dec := xml.NewDecoder(r)
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("lwm2m: DDF: %w", err)
	}
	if len(d.Objects) == 0 {
		return nil, fmt.Errorf("lwm2m: DDF: no Object element")
	}
	m := Model{}
	for _, o := range d.Objects {
		for _, it := range o.Resources {
			typ := ddfTypes[strings.ToLower(strings.TrimSpace(it.Type))]
			if typ == "" {
				if strings.Contains(strings.ToUpper(it.Operations), "E") {
					typ = tExec
				} else {
					return nil, fmt.Errorf("lwm2m: DDF: object %d resource %d has type %q", o.ObjectID, it.ID, it.Type)
				}
			}
			m["/"+strconv.Itoa(o.ObjectID)+"/"+strconv.Itoa(it.ID)] = ResourceDef{Name: shortName(it.Name), Type: typ, Unit: strings.TrimSpace(it.Units)}
		}
	}
	return m, nil
}

// Merge returns m with the definitions of others added (later ones win).
func (m Model) Merge(others ...Model) Model {
	out := Model{}
	for k, v := range m {
		out[k] = v
	}
	for _, o := range others {
		for k, v := range o {
			out[k] = v
		}
	}
	return out
}

// shortName makes "Sensor Value" into "sensor-value".
func shortName(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
			continue
		}
		dash = true
	}
	return b.String()
}
