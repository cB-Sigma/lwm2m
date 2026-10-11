package lwm2m

import (
	"math"
	"testing"
	"time"
)

// Tests written from OMA-TS-LightweightM2M_Core V1.1.1 clause 7.4 and
// appendix C (data types in each content format).

// Covers: SIG-IPE-3400
func TestLwM2MTLVUnsignedInteger(t *testing.T) {
	// Appendix C: an Unsigned Integer is 1, 2, 4 or 8 bytes of unsigned
	// binary; the top bit is not a sign.
	m := Model{"/9000/1": {Type: tUnsigned}, "/9000/2": {Type: tInteger}}
	p := Path{9000, 0, 1, -1}
	cases := []struct {
		b    []byte
		want float64
	}{
		{[]byte{0xC8}, 200},
		{[]byte{0xFF, 0xFF}, 65535},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFE}, 4294967294},
		{[]byte{0x80, 0, 0, 0, 0, 0, 0, 0}, 9223372036854775808},
	}
	for _, c := range cases {
		v, err := decodeScalar(m.Lookup(p).Type, c.b, nil)
		if err != nil || v != c.want {
			t.Errorf("unsigned % x = %v %v, want %v", c.b, v, err, c.want)
		}
	}
	// The same byte is negative for a signed Integer.
	if v, _ := decodeScalar(m.Lookup(Path{9000, 0, 2, -1}).Type, []byte{0xC8}, nil); v != -56.0 {
		t.Errorf("integer c8 = %v, want -56", v)
	}
	// Encoding an unsigned value keeps it unsigned: 200 needs one byte, and
	// a negative value is refused.
	if b, err := EncodeScalar(tUnsigned, 200.0); err != nil || len(b) != 1 || b[0] != 0xC8 {
		t.Errorf("encode unsigned 200 = % x %v", b, err)
	}
	if _, err := EncodeScalar(tUnsigned, -1.0); err == nil {
		t.Error("a negative unsigned integer was encoded")
	}
}

// Covers: SIG-IPE-3401
func TestLwM2MSenMLJSONOpaqueIsBase64(t *testing.T) {
	// Clause 7.4.5 table and appendix C: opaque values travel in "vd" as
	// base64 text; decoded values are hex like TLV and SenML CBOR.
	for _, vd := range []string{"AQIDBAU", "AQIDBAU=", "-_8"} {
		vals, err := DecodeSenMLJSON([]byte(`[{"n":"/5/0/0","vd":"` + vd + `"}]`))
		if err != nil || len(vals) != 1 {
			t.Fatalf("vd %q: %v %v", vd, vals, err)
		}
		want := map[string]string{"AQIDBAU": "0102030405", "AQIDBAU=": "0102030405", "-_8": "fbff"}[vd]
		if vals[0].V != want {
			t.Errorf("vd %q = %v, want %s", vd, vals[0].V, want)
		}
	}
	if _, err := DecodeSenMLJSON([]byte(`[{"n":"/5/0/0","vd":"not base64!"}]`)); err == nil {
		t.Error("an opaque value that is not base64 was accepted")
	}
	// A write of an opaque resource in SenML JSON carries base64 in vd.
	b, err := encodeSenML(cfSenMLJSON, Path{5, 0, 0, -1}, tOpaque, "0102030405")
	if err != nil || string(b) != `[{"n":"/5/0/0","vd":"AQIDBAU"}]` {
		t.Errorf("opaque write = %s %v", b, err)
	}
}

// Covers: SIG-IPE-3402
func TestLwM2MSenMLRelativeTime(t *testing.T) {
	// Clause 7.4.5 note and RFC 8428 clause 4.5.3: base time plus time is
	// absolute from 2**28 seconds on; smaller values (and negative ones) are
	// relative to now.
	now := time.Now()
	vals, err := DecodeSenMLJSON([]byte(`[{"n":"/3303/0/5700","v":1,"t":-60},{"n":"/3303/0/5700","v":2,"t":30},{"bt":1700000000,"n":"/3303/0/5700","v":3,"t":5},{"bt":0,"n":"/3303/0/5700","v":4}]`))
	if err != nil || len(vals) != 4 {
		t.Fatalf("%v %v", vals, err)
	}
	near := func(got, want time.Time) bool { return math.Abs(got.Sub(want).Seconds()) < 5 }
	if !near(vals[0].Time, now.Add(-time.Minute)) {
		t.Errorf("t=-60 = %v, want about a minute ago", vals[0].Time)
	}
	if !near(vals[1].Time, now.Add(30*time.Second)) {
		t.Errorf("t=30 = %v, want about 30 s from now (relative, below 2**28)", vals[1].Time)
	}
	if vals[2].Time.Unix() != 1700000005 {
		t.Errorf("bt+t = %v, want 1700000005", vals[2].Time.Unix())
	}
	if !vals[3].Time.IsZero() {
		t.Errorf("no time = %v, want zero (now)", vals[3].Time)
	}
}

// Covers: SIG-IPE-3405
func TestLwM2MPlainTextValues(t *testing.T) {
	// Clause 7.4.1 and appendix C text column: booleans are "0" or "1",
	// opaque is base64, numbers are ASCII.
	m := Model{"/9000/1": {Type: tOpaque}}
	cases := []struct {
		p    Path
		s    string
		want any
		bad  bool
	}{
		{Path{1, 0, 6, -1}, "1", true, false},
		{Path{1, 0, 6, -1}, "0", false, false},
		{Path{1, 0, 6, -1}, "true", true, false}, // accepted with a warning (SIG-IPE-3474)
		{Path{1, 0, 6, -1}, "yes", nil, true},
		{Path{9000, 0, 1, -1}, "AQIDBAU=", "0102030405", false},
		{Path{9000, 0, 1, -1}, "%%%", nil, true},
		{Path{3, 0, 9, -1}, "-750", -750.0, false},
		{Path{3, 0, 9, -1}, "12x", nil, true},
		{Path{3, 0, 0, -1}, "Open", "Open", false},
	}
	for _, c := range cases {
		v, err := decodeText(m, c.p, []byte(c.s), nil)
		if c.bad {
			if err == nil {
				t.Errorf("%s %q accepted as %v", c.p, c.s, v)
			}
			continue
		}
		if err != nil || v != c.want {
			t.Errorf("%s %q = %v %v, want %v", c.p, c.s, v, err, c.want)
		}
	}
}
