// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lwm2m

import (
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
)

// Content-Format numbers (IANA CoAP Content-Formats) of the formats this
// package reads and writes.
const (
	CFText          = cfText
	CFOpaque        = cfOpaque
	CFCBOR          = cfCBOR
	CFSenMLJSON     = cfSenMLJSON
	CFSenMLCBOR     = cfSenMLCBOR
	CFTLV           = cfTLV
	CFLwM2MJSON     = cfLwM2MJSON
	CFLwM2MCBOR     = cfLwM2MCBOR
	CFSenMLEtchJSON = cfSenMLEtchJSON
	CFSenMLEtchCBOR = cfSenMLEtchCBOR
)

// Identifier kinds of a TLV entry (AppendTLV).
const (
	TLVObjInst  = tlvObjInst
	TLVResInst  = tlvResInst
	TLVMultiRes = tlvMultiRes
	TLVResValue = tlvResValue
)

// Resource data types of the object model (ResourceDef.Type).
const (
	TString   = tString
	TInteger  = tInteger
	TUnsigned = tUnsigned
	TFloat    = tFloat
	TBool     = tBool
	TOpaque   = tOpaque
	TTime     = tTime
	TObjlnk   = tObjlnk
	TCorelnk  = tCorelnk
	TExec     = tExec
)

// Objects is the built-in object model, object ID → resource ID →
// definition (see model.go). Model.Lookup falls back to it. Callers must
// not modify it.
var Objects = model

// ObjectNames are short names of the built-in objects, by object ID.
var ObjectNames = objectNames

// PointName is a resource's path with '-' separators ("3303-0-5700").
func PointName(p Path) string { return pointName(p) }

// The Lax variants take lax, where they append a note for each thing
// accepted although not strictly well formed; lax may be nil.

// DecodeTLVLax is DecodeTLV with notes.
func DecodeTLVLax(m Model, base Path, b []byte, lax *[]string) ([]Value, error) {
	return decodeTLV(m, base, b, lax)
}

// DecodeScalar decodes one TLV value of data type typ.
func DecodeScalar(typ string, b []byte, lax *[]string) (any, error) {
	return decodeScalar(typ, b, lax)
}

// AppendTLV appends one TLV entry of the given kind (0 object instance, 1
// resource instance, 2 multiple resource, 3 resource value) and ID.
func AppendTLV(dst []byte, kind, id int, value []byte) []byte {
	return appendTLV(dst, kind, id, value)
}

// DecodeText decodes a plain-text (or opaque) value of the resource at p.
func DecodeText(m Model, p Path, b []byte, lax *[]string) (any, error) {
	return decodeText(m, p, b, lax)
}

// DecodeSenMLJSONRoot is DecodeSenMLJSON for a client whose objects sit
// under the alternate path root ("" for none).
func DecodeSenMLJSONRoot(b []byte, root string) ([]TimedValue, error) {
	return decodeSenMLJSON(b, root)
}

// DecodeSenMLCBORRoot is DecodeSenMLCBOR with an alternate path root.
func DecodeSenMLCBORRoot(b []byte, root string) ([]TimedValue, error) {
	return decodeSenMLCBOR(b, root)
}

// DecodeLwM2MJSONRoot is DecodeLwM2MJSON with an alternate path root.
func DecodeLwM2MJSONRoot(b []byte, root string) ([]TimedValue, error) {
	return decodeLwM2MJSON(b, root)
}

// DecodeLwM2MCBORLax is DecodeLwM2MCBOR with notes (m and root are not
// used by the format and accepted for symmetry with the other decoders).
func DecodeLwM2MCBORLax(m Model, b []byte, root string, lax *[]string) ([]TimedValue, error) {
	return decodeLwM2MCBOR(m, b, root, lax)
}

// EncodeSenML encodes one value at p as a SenML pack in Content-Format cf
// (CFSenMLJSON or CFSenMLCBOR).
func EncodeSenML(cf int, p Path, typ string, v any) ([]byte, error) {
	return encodeSenML(cf, p, typ, v)
}

// TypedValue converts v to the Go value of data type typ that the
// encoders write.
func TypedValue(typ string, v any) (any, error) { return typedValue(typ, v) }

// DecodeCBORValue decodes a single CBOR data item (Content-Format 60).
func DecodeCBORValue(b []byte) (any, error) { return decodeCBORValue(b) }

// ParseRegistration splits a Register payload (CoRE link format) into the
// alternate path root and the object links under it.
func ParseRegistration(s string) (root string, links []string) {
	return parseRegistration(s)
}

// EncodePaths encodes paths as a SenML pack of names only (the request of
// Read-Composite and Observe-Composite), in JSON for CFSenMLJSON and
// CFSenMLEtchJSON and in CBOR otherwise.
func EncodePaths(cf int, paths []string) ([]byte, error) {
	if cf == cfSenMLJSON || cf == cfSenMLEtchJSON {
		recs := make([]map[string]string, 0, len(paths))
		for _, p := range paths {
			recs = append(recs, map[string]string{"n": p})
		}
		return json.Marshal(recs)
	}
	recs := make([]senmlCBOR, 0, len(paths))
	for _, p := range paths {
		n := p
		recs = append(recs, senmlCBOR{N: &n})
	}
	return cbor.Marshal(recs)
}
