// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/udp"

	"github.com/cB-Sigma/lwm2m"
	"github.com/cB-Sigma/lwm2m/client"
	"github.com/cB-Sigma/lwm2m/server"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// events collects registration events.
type events struct {
	reg, upd, dereg chan *server.Registration
	sent            chan []lwm2m.Value
}

func newEvents() *events {
	return &events{reg: make(chan *server.Registration, 8), upd: make(chan *server.Registration, 8),
		dereg: make(chan *server.Registration, 8), sent: make(chan []lwm2m.Value, 8)}
}

func (e *events) config(cfg server.Config) server.Config {
	cfg.OnRegister = func(r *server.Registration) { e.reg <- r }
	cfg.OnUpdate = func(r *server.Registration) { e.upd <- r }
	cfg.OnDeregister = func(r *server.Registration) { e.dereg <- r }
	cfg.OnSend = func(_ *server.Registration, v []lwm2m.Value) { e.sent <- v }
	cfg.Logger = quiet
	return cfg
}

func wait[T any](t *testing.T, ch chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s", what)
	}
	var zero T
	return zero
}

func startClient(t *testing.T, cfg client.Config) *client.Client {
	t.Helper()
	cfg.Logger = quiet
	c := client.New(cfg)
	if err := c.Start(ctx(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	return c
}

func flat(vals []lwm2m.Value) map[string]string {
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

// The library's server and client roles against each other over plain
// CoAP: registration, every device management operation, observation,
// Send and de-registration.
func TestServerOperations(t *testing.T) {
	ev := newEvents()
	s := server.New(ev.config(server.Config{}))
	addr, err := s.Listen("coap", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := startClient(t, client.Config{Endpoint: "lib-1", Server: "coap://" + addr.String(), Lifetime: time.Minute})
	reg := wait(t, ev.reg, "registration")
	if reg.Endpoint != "lib-1" || reg.Lifetime() != time.Minute || reg.Version() != "1.1" || s.Registration("lib-1") != reg {
		t.Fatalf("registration %+v", reg)
	}
	if links := strings.Join(reg.ObjectLinks(), ","); !strings.Contains(links, "/3303/0") {
		t.Errorf("object links %s", links)
	}

	base, _ := lwm2m.ParsePath("/3/0")
	want := flat(c.Objects().Values(base))
	for _, cf := range []int{lwm2m.CFTLV, lwm2m.CFSenMLJSON, lwm2m.CFSenMLCBOR, lwm2m.CFLwM2MJSON, lwm2m.CFLwM2MCBOR} {
		got, err := reg.Read(ctx(t), "/3/0", cf)
		if err != nil || fmt.Sprint(flat(got)) != fmt.Sprint(want) {
			t.Errorf("read as %d: %v %v", cf, flat(got), err)
		}
	}
	if v, err := reg.Read(ctx(t), "/3303/0/5700", lwm2m.CFText); err != nil || len(v) != 1 || v[0].V != 21.5 {
		t.Errorf("read text: %v %v", v, err)
	}

	p, _ := lwm2m.ParsePath("/3303/0/5701")
	if err := reg.Write(ctx(t), "/3303/0/5701", lwm2m.CFSenMLCBOR, true, []lwm2m.Value{{Path: p, V: "K"}}); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Objects().Get("/3303/0/5701"); v != "K" {
		t.Errorf("after write: %v", v)
	}
	var ce *server.CodeError
	if err := reg.Write(ctx(t), "/3/9", lwm2m.CFTLV, true, []lwm2m.Value{{Path: lwm2m.Path{Obj: 3, Inst: 9, Res: 0, RI: -1}, V: "x"}}); !errors.As(err, &ce) {
		t.Errorf("a write to a missing instance: %v", err)
	}

	links, err := reg.Discover(ctx(t), "/3303/0")
	if err != nil || !strings.Contains(strings.Join(links, ","), "/3303/0/5700") {
		t.Errorf("discover: %v %v", links, err)
	}
	if err := reg.WriteAttributes(ctx(t), "/3303/0/5700", "pmin=0&pmax=60"); err != nil {
		t.Errorf("write attributes: %v", err)
	}
	executed := make(chan string, 1)
	c.OnExecute("/3/0/4", func(args string) { executed <- args })
	if err := reg.Execute(ctx(t), "/3/0/4", ""); err != nil {
		t.Fatal(err)
	}
	wait(t, executed, "execute")

	notes := make(chan []lwm2m.Value, 8)
	obs, err := reg.Observe(ctx(t), "/3303/0/5700", lwm2m.CFSenMLJSON, func(v []lwm2m.Value) { notes <- v })
	if err != nil {
		t.Fatal(err)
	}
	if v := wait(t, notes, "first observe answer"); v[0].V != 21.5 {
		t.Errorf("first answer %v", v)
	}
	if err := c.Set("/3303/0/5700", 23.0); err != nil {
		t.Fatal(err)
	}
	if v := wait(t, notes, "notification"); v[0].V != 23.0 {
		t.Errorf("notification %v", v)
	}
	if err := obs.Cancel(ctx(t)); err != nil {
		t.Errorf("cancel: %v", err)
	}

	comp, err := reg.ReadComposite(ctx(t), []string{"/3/0/0", "/3303/0/5700"}, lwm2m.CFSenMLCBOR)
	if err != nil || len(comp) != 2 {
		t.Errorf("read composite: %v %v", comp, err)
	}
	if err := reg.WriteComposite(ctx(t), lwm2m.CFSenMLJSON, []lwm2m.Value{{Path: p, V: "Cel"}}); err != nil {
		t.Errorf("write composite: %v", err)
	}

	loc, err := reg.Create(ctx(t), "/3303", lwm2m.CFTLV, []lwm2m.Value{{Path: lwm2m.Path{Obj: 3303, Inst: 7, Res: 5700, RI: -1}, V: 1.5}})
	if err != nil || loc == "" {
		t.Fatalf("create: %q %v", loc, err)
	}
	if err := reg.Delete(ctx(t), loc); err != nil {
		t.Errorf("delete %s: %v", loc, err)
	}

	if err := c.Send(ctx(t), "/3303/0/5700"); err != nil {
		t.Fatal(err)
	}
	if v := wait(t, ev.sent, "send"); len(v) == 0 {
		t.Error("an empty Send")
	}
	if err := c.Update(ctx(t)); err != nil {
		t.Fatal(err)
	}
	wait(t, ev.upd, "update")
	_ = c.Stop()
	if r := wait(t, ev.dereg, "de-registration"); r.Endpoint != "lib-1" || s.Registration("lib-1") != nil {
		t.Errorf("de-registered %v", r)
	}
}

// A registration whose lifetime passes without an Update is removed.
func TestServerExpiry(t *testing.T) {
	ev := newEvents()
	s := server.New(ev.config(server.Config{}))
	addr, err := s.Listen("coap", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cc, err := udp.Dial(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	m, err := cc.Post(ctx(t), "/rd", message.AppLinkFormat, strings.NewReader("</3/0>"),
		message.Option{ID: message.URIQuery, Value: []byte("ep=short")}, message.Option{ID: message.URIQuery, Value: []byte("lt=1")})
	if err != nil || m.Code() != codes.Created {
		t.Fatalf("register: %v %v", m, err)
	}
	wait(t, ev.reg, "registration")
	if r := wait(t, ev.dereg, "expiry"); r.Endpoint != "short" {
		t.Errorf("expired %s", r.Endpoint)
	}
	if loc, _ := m.Options().LocationPath(); loc != "" {
		up, err := cc.Post(ctx(t), "/"+loc, message.AppLinkFormat, nil)
		if err != nil || up.Code() != codes.NotFound {
			t.Errorf("an update after expiry: %v %v", up, err)
		}
	}
}

// DTLS with a pre-shared key: the identity reaches Authorize, a wrong key
// fails the handshake.
func TestServerPSK(t *testing.T) {
	ev := newEvents()
	key := []byte("0123456789abcdef")
	s := server.New(ev.config(server.Config{
		Security: server.Security{PSK: func(id string) ([]byte, error) {
			if id != "dev-psk" {
				return nil, errors.New("unknown identity")
			}
			return key, nil
		}},
		Authorize: func(ep, id string) error {
			if ep != id {
				return errors.New("endpoint and identity differ")
			}
			return nil
		},
	}))
	addr, err := s.Listen("coaps", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	startClient(t, client.Config{Endpoint: "dev-psk", Server: "coaps://" + addr.String(), PSKIdentity: "dev-psk", PSK: key})
	if r := wait(t, ev.reg, "registration"); r.Identity != "dev-psk" {
		t.Errorf("identity %q", r.Identity)
	}
	bad := client.New(client.Config{Endpoint: "dev-psk", Server: "coaps://" + addr.String(), PSKIdentity: "dev-psk", PSK: []byte("wrong-key-000000"), Logger: quiet})
	if err := bad.Start(ctx(t)); err == nil {
		_ = bad.Stop()
		t.Error("a wrong key registered")
	}
	other := client.New(client.Config{Endpoint: "someone-else", Server: "coaps://" + addr.String(), PSKIdentity: "dev-psk", PSK: key, Logger: quiet})
	if err := other.Start(ctx(t)); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		_ = other.Stop()
		t.Errorf("an endpoint not matching its identity: %v", err)
	}
}

type pki struct {
	ca          *x509.Certificate
	caKey       *ecdsa.PrivateKey
	pool        *x509.CertPool
	server, dev tls.Certificate
}

func issue(t *testing.T, p *pki, cn string, serverName string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if serverName != "" {
		tmpl.IPAddresses = []net.IP{net.ParseIP(serverName)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pki{ca: ca, caKey: k, pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	p.server = issue(t, p, "lwm2m-server", "127.0.0.1")
	p.dev = issue(t, p, "dev-x509", "")
	return p
}

// DTLS with X.509 certificates both ways: the client certificate's
// common name is the identity.
func TestServerX509(t *testing.T) {
	p := newPKI(t)
	ev := newEvents()
	s := server.New(ev.config(server.Config{Security: server.Security{Certificate: &p.server, ClientCAs: p.pool}}))
	addr, err := s.Listen("coaps", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := startClient(t, client.Config{Endpoint: "dev-x509", Server: "coaps://" + addr.String(), Certificate: &p.dev, RootCAs: p.pool})
	r := wait(t, ev.reg, "registration")
	if r.Identity != "dev-x509" {
		t.Errorf("identity %q", r.Identity)
	}
	if v, err := r.Read(ctx(t), "/3/0/0", lwm2m.CFText); err != nil || len(v) != 1 {
		t.Errorf("read over DTLS: %v %v", v, err)
	}
	_ = c
	// A client whose certificate another CA issued is refused.
	other := newPKI(t)
	bad := client.New(client.Config{Endpoint: "dev-x509", Server: "coaps://" + addr.String(), Certificate: &other.dev, RootCAs: p.pool, Logger: quiet})
	if err := bad.Start(ctx(t)); err == nil {
		_ = bad.Stop()
		t.Error("a certificate of another CA registered")
	}
}

// The bootstrap server role provisions a PSK account for a coaps server;
// the client bootstraps, then registers there.
func TestBootstrapServer(t *testing.T) {
	ev := newEvents()
	key := []byte("bootstrapped-key")
	s := server.New(ev.config(server.Config{Security: server.Security{PSK: func(id string) ([]byte, error) {
		if id == "dev-bs" {
			return key, nil
		}
		return nil, errors.New("unknown identity")
	}}}))
	saddr, err := s.Listen("coaps", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mu sync.Mutex
	var done []string
	bs := server.NewBootstrap(server.BootstrapConfig{Logger: quiet,
		Accounts: func(ep, _ string) ([]server.Account, error) {
			if ep != "dev-bs" {
				return nil, errors.New("unknown endpoint")
			}
			return []server.Account{{URI: "coaps://" + saddr.String(), ShortServerID: 101, Mode: server.ModePSK,
				PSKIdentity: "dev-bs", PSK: key, Lifetime: 90 * time.Second}}, nil
		},
		OnDone: func(ep string, err error) { mu.Lock(); done = append(done, fmt.Sprint(ep, err)); mu.Unlock() },
	})
	baddr, err := bs.Listen("coap", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	for _, format := range []int{lwm2m.CFTLV} {
		_ = format
		startClient(t, client.Config{Endpoint: "dev-bs", Bootstrap: "coap://" + baddr.String()})
		r := wait(t, ev.reg, "registration after bootstrap")
		if r.Identity != "dev-bs" || r.Lifetime() != 90*time.Second {
			t.Errorf("registered as %q for %v", r.Identity, r.Lifetime())
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(done) != 1 || done[0] != "dev-bs<nil>" {
		t.Errorf("bootstrap results %v", done)
	}
	refused := client.New(client.Config{Endpoint: "stranger", Bootstrap: "coap://" + baddr.String(), Logger: quiet})
	if err := refused.Start(ctx(t)); err == nil {
		_ = refused.Stop()
		t.Error("an unknown endpoint was bootstrapped")
	}
}
