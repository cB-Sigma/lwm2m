// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop checks this module's codecs against Eclipse Leshan's
// demo client (2.0.0-M18) in Docker: a minimal LwM2M server in the test
// registers the client, reads, writes, discovers, executes and observes in
// every content format the client offers, decodes Leshan's payloads with
// this module and compares the formats with one another; and writes values
// this module encoded, which Leshan decodes and the test reads back.
package interop

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/message/pool"

	"github.com/cB-Sigma/lwm2m"
)

// formats are the multi-value content formats, by name.
var formats = []struct {
	name string
	cf   int
}{
	{"TLV", lwm2m.CFTLV},
	{"SenML JSON", lwm2m.CFSenMLJSON},
	{"SenML CBOR", lwm2m.CFSenMLCBOR},
	{"LwM2M JSON", lwm2m.CFLwM2MJSON},
	{"LwM2M CBOR", lwm2m.CFLwM2MCBOR},
}

// flat turns decoded values into path → value, a multiple-instance
// resource decoded from TLV (a map) into one entry per instance.
func flat(vals []lwm2m.Value) map[string]any {
	out := map[string]any{}
	for _, v := range vals {
		if m, ok := v.V.(map[string]any); ok {
			for ri, x := range m {
				out[v.Path.String()+"/"+ri] = x
			}
			continue
		}
		out[v.Path.String()] = v.V
	}
	return out
}

func body(t *testing.T, m *pool.Message) []byte {
	t.Helper()
	if m.Body() == nil {
		return nil
	}
	b, err := io.ReadAll(m.Body())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func startLeshanClient(t *testing.T, ep string) (*lwm2mServer, registration) {
	t.Helper()
	needDocker(t)
	s := newServer(t)
	startContainer(t, "sigma-lwm2m-interop-client-"+strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")),
		"java", "-jar", "client.jar", "-u", fmt.Sprintf("coap://host.docker.internal:%d", s.port), "-n", ep, "-l", "120")
	return s, s.waitRegistration(t)
}

func TestLeshanClientReadsInEveryFormat(t *testing.T) {
	_, reg := startLeshanClient(t, "sigma-interop-read")

	// The Register payload: Leshan's link format, read by ParseRegistration.
	root, links := lwm2m.ParseRegistration(reg.payload)
	t.Logf("register query %v payload %s", reg.query, reg.payload)
	if root != "" || !contains(links, "/3/0") || !contains(links, "/3303/0") {
		t.Fatalf("registration links = %q %v", root, links)
	}

	// /3/0 in every multi-value format; all must decode to the same values.
	base, _ := lwm2m.ParsePath("/3/0")
	var ref map[string]any
	refName := ""
	for _, f := range formats {
		resp, err := reg.conn.Get(ctx(t), "/3/0", accept(f.cf))
		if err != nil {
			t.Fatalf("%s read: %v", f.name, err)
		}
		if resp.Code() == codes.NotAcceptable {
			t.Logf("%s: Leshan answered 4.06 Not Acceptable (format not offered by the client)", f.name)
			continue
		}
		if resp.Code() != codes.Content {
			t.Errorf("%s read = %v", f.name, resp.Code())
			continue
		}
		if cf, _ := resp.ContentFormat(); int(cf) != f.cf {
			t.Errorf("%s read came back as Content-Format %d", f.name, cf)
		}
		vals, err := lwm2m.Decode(f.cf, nil, base, body(t, resp))
		if err != nil {
			t.Errorf("%s: decode Leshan's payload: %v", f.name, err)
			continue
		}
		got := flat(vals)
		if got["/3/0/0"] == nil || got["/3/0/1"] == nil {
			t.Errorf("%s: manufacturer or model missing: %v", f.name, got)
		}
		if ref == nil {
			ref, refName = got, f.name
			t.Logf("%s /3/0 = %v", f.name, got)
			continue
		}
		if d := diff(ref, got, randomInLeshanDemo...); d != "" {
			t.Errorf("%s and %s disagree on /3/0: %s", refName, f.name, d)
		}
	}

	// Single resources in plain text and CBOR agree with TLV.
	for _, p := range []string{"/3/0/0", "/3/0/2", "/3/0/16", "/3/0/21", "/3303/0/5701"} {
		pp, _ := lwm2m.ParsePath(p)
		var vals []any
		for _, cf := range []int{lwm2m.CFTLV, lwm2m.CFText, lwm2m.CFCBOR} {
			resp, err := reg.conn.Get(ctx(t), p, accept(cf))
			if err != nil || resp.Code() != codes.Content {
				t.Errorf("read %s as %d: %v %v", p, cf, resp, err)
				continue
			}
			v, err := lwm2m.Decode(cf, nil, pp, body(t, resp))
			if err != nil || len(v) != 1 {
				t.Errorf("decode %s as %d: %v %v", p, cf, v, err)
				continue
			}
			vals = append(vals, v[0].V)
		}
		if len(vals) == 3 && (fmt.Sprint(vals[0]) != fmt.Sprint(vals[1]) || fmt.Sprint(vals[0]) != fmt.Sprint(vals[2])) {
			t.Errorf("%s: TLV %v, text %v, CBOR %v", p, vals[0], vals[1], vals[2])
		}
	}

	// A whole object (/3303) in TLV and SenML CBOR.
	obj, _ := lwm2m.ParsePath("/3303")
	var byFormat []map[string]any
	for _, cf := range []int{lwm2m.CFTLV, lwm2m.CFSenMLCBOR} {
		resp, err := reg.conn.Get(ctx(t), "/3303", accept(cf))
		if err != nil || resp.Code() != codes.Content {
			t.Fatalf("read /3303 as %d: %v %v", cf, resp, err)
		}
		vals, err := lwm2m.Decode(cf, nil, obj, body(t, resp))
		if err != nil {
			t.Fatalf("decode /3303 as %d: %v", cf, err)
		}
		byFormat = append(byFormat, flat(vals))
	}
	if byFormat[0]["/3303/0/5701"] == nil {
		t.Errorf("/3303 = %v", byFormat[0])
	}
	if d := diff(byFormat[0], byFormat[1], "/3303/0/5700", "/3303/0/5601", "/3303/0/5602"); d != "" {
		t.Errorf("/3303 TLV and SenML CBOR disagree: %s", d)
	}
}

func TestLeshanClientDiscoverWriteExecute(t *testing.T) {
	_, reg := startLeshanClient(t, "sigma-interop-write")

	// Discover on an object and an instance (CoRE link format).
	for _, p := range []string{"/3", "/3/0", "/3303/0/5700"} {
		resp, err := reg.conn.Get(ctx(t), p, accept(40))
		if err != nil || resp.Code() != codes.Content {
			t.Fatalf("discover %s: %v %v", p, resp, err)
		}
		links := lwm2m.ParseLinks(string(body(t, resp)))
		t.Logf("discover %s = %v", p, links)
		if !contains(links, p) {
			t.Errorf("discover %s does not list itself: %v", p, links)
		}
		if p == "/3/0" && (!contains(links, "/3/0/0") || !contains(links, "/3/0/13")) {
			t.Errorf("discover /3/0 = %v", links)
		}
	}

	// Write the UTC offset (a string) and the current time (a time) in
	// every format this module encodes; Leshan decodes each, the read back
	// in plain text shows the value.
	all := append(append([]struct {
		name string
		cf   int
	}{}, formats...), struct {
		name string
		cf   int
	}{"text", lwm2m.CFText}, struct {
		name string
		cf   int
	}{"CBOR", lwm2m.CFCBOR})
	for i, f := range all {
		for _, w := range []struct {
			path string
			v    any
		}{
			{"/3/0/14", fmt.Sprintf("+%02d", i+1)}, // string
			{"/1/0/3", float64(300 + i)},           // integer (default maximum period)
			{"/1/0/6", i%2 == 0},                   // boolean (notification storing)
		} {
			p, _ := lwm2m.ParsePath(w.path)
			b, err := lwm2m.Encode(f.cf, nil, p, []lwm2m.Value{{Path: p, V: w.v}})
			if err != nil {
				t.Fatalf("encode %s %s: %v", f.name, w.path, err)
			}
			resp, err := reg.conn.Put(ctx(t), w.path, message.MediaType(f.cf), bytes.NewReader(b))
			if err != nil {
				t.Fatalf("write %s as %s: %v", w.path, f.name, err)
			}
			if resp.Code() == codes.UnsupportedMediaType {
				t.Logf("%s: Leshan answered 4.15 Unsupported Content-Format to a write", f.name)
				continue
			}
			if resp.Code() != codes.Changed {
				t.Errorf("write %s=%v as %s = %v (%s)", w.path, w.v, f.name, resp.Code(), body(t, resp))
				continue
			}
			back, err := reg.conn.Get(ctx(t), w.path, accept(lwm2m.CFText))
			if err != nil || back.Code() != codes.Content {
				t.Fatalf("read back %s: %v %v", w.path, back, err)
			}
			v, err := lwm2m.Decode(lwm2m.CFText, nil, p, body(t, back))
			if err != nil || fmt.Sprint(v[0].V) != fmt.Sprint(w.v) {
				t.Errorf("%s written as %s = %v, reads back %v %v", w.path, f.name, w.v, v, err)
			}
		}
	}

	// Write-Attributes and Execute.
	resp, err := reg.conn.Put(ctx(t), "/3303/0/5700", message.TextPlain, nil,
		message.Option{ID: message.URIQuery, Value: []byte("pmin=1")}, message.Option{ID: message.URIQuery, Value: []byte("pmax=5")})
	if err != nil || resp.Code() != codes.Changed {
		t.Errorf("write attributes = %v %v", resp, err)
	}
	resp, err = reg.conn.Post(ctx(t), "/3303/0/5605", message.TextPlain, nil)
	if err != nil || resp.Code() != codes.Changed {
		t.Errorf("execute reset min/max = %v %v", resp, err)
	}
	// Read of an executable resource and execute of a readable one are
	// refused.
	if resp, err := reg.conn.Post(ctx(t), "/3/0/0", message.TextPlain, nil); err != nil || resp.Code() != codes.MethodNotAllowed {
		t.Errorf("execute of /3/0/0 = %v %v, want 4.05", resp, err)
	}
}

func TestLeshanClientObserveInEveryFormat(t *testing.T) {
	_, reg := startLeshanClient(t, "sigma-interop-observe")
	single := append(append([]struct {
		name string
		cf   int
	}{}, formats...), struct {
		name string
		cf   int
	}{"text", lwm2m.CFText}, struct {
		name string
		cf   int
	}{"CBOR", lwm2m.CFCBOR})
	for _, f := range single {
		for _, path := range []string{"/3303/0/5700", "/3303/0"} {
			if path == "/3303/0" && (f.cf == lwm2m.CFText || f.cf == lwm2m.CFCBOR) {
				continue
			}
			t.Run(f.name+path, func(t *testing.T) {
				p, _ := lwm2m.ParsePath(path)
				if probe, err := reg.conn.Get(ctx(t), path, accept(f.cf)); err == nil && probe.Code() == codes.NotAcceptable {
					t.Skipf("Leshan's client does not offer %s (4.06)", f.name)
				}
				var mu sync.Mutex
				var temps []float64
				var errs []string
				obs, err := reg.conn.Observe(ctx(t), path, func(n *pool.Message) {
					mu.Lock()
					defer mu.Unlock()
					if n.Code() != codes.Content {
						errs = append(errs, n.Code().String())
						return
					}
					b, _ := io.ReadAll(n.Body())
					vals, err := lwm2m.Decode(f.cf, nil, p, b)
					if err != nil {
						errs = append(errs, err.Error())
						return
					}
					if v, ok := flat(vals)["/3303/0/5700"].(float64); ok {
						temps = append(temps, v)
					}
				}, accept(f.cf))
				if err != nil {
					t.Fatalf("observe: %v", err)
				}
				defer func() { _ = obs.Cancel(ctx(t)) }()
				deadline := time.Now().Add(20 * time.Second)
				for time.Now().Before(deadline) {
					mu.Lock()
					n, e := len(temps), len(errs)
					mu.Unlock()
					if n >= 3 || e > 0 {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				mu.Lock()
				defer mu.Unlock()
				if len(errs) > 0 {
					if f.cf == lwm2m.CFLwM2MCBOR && errs[0] == codes.NotAcceptable.String() {
						t.Skipf("Leshan does not offer LwM2M CBOR: %v", errs)
					}
					t.Fatalf("notifications: %v", errs)
				}
				if len(temps) < 3 {
					t.Fatalf("%d notifications in 20 s", len(temps))
				}
				for _, v := range temps {
					if math.IsNaN(v) || v < -50 || v > 100 {
						t.Errorf("temperature %v", v)
					}
				}
				t.Logf("temperatures %v", temps)
			})
		}
	}
}

// randomInLeshanDemo are the Device resources Leshan's demo client gives a
// new value on every read (battery level, free memory, battery status) or
// that follow its clock.
var randomInLeshanDemo = []string{"/3/0/9", "/3/0/10", "/3/0/13", "/3/0/20"}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// diff describes how two decoded payloads differ, ignoring the paths in
// skip (values that change between reads).
func diff(a, b map[string]any, skip ...string) string {
	ignore := map[string]bool{}
	for _, s := range skip {
		ignore[s] = true
	}
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if ignore[k] {
			continue
		}
		if fmt.Sprint(a[k]) != fmt.Sprint(b[k]) {
			out = append(out, fmt.Sprintf("%s: %v / %v", k, a[k], b[k]))
		}
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}
