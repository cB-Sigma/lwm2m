// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"

	"github.com/cB-Sigma/lwm2m"
)

// Security modes of the Security object's resource 2 (Core E.1).
const (
	ModePSK         = 0
	ModeRPK         = 1
	ModeCertificate = 2
	ModeNoSec       = 3
)

// Account is one LwM2M server account a bootstrap server provisions: a
// Security instance and the Server instance with the same short server
// ID.
type Account struct {
	URI           string // coap:// or coaps://
	ShortServerID int    // 1 to 65534
	Mode          int    // ModePSK, ModeCertificate or ModeNoSec
	// PSKIdentity and PSK for ModePSK; Certificate (DER, the client's),
	// PrivateKey (DER, PKCS#8) and ServerCertificate (DER) for
	// ModeCertificate.
	PSKIdentity       string
	PSK               []byte
	Certificate       []byte
	PrivateKey        []byte
	ServerCertificate []byte
	Lifetime          time.Duration // default 300 s
	Binding           string        // default "U"
}

// BootstrapConfig sets up a BootstrapServer.
type BootstrapConfig struct {
	// Security of coaps listeners.
	Security Security
	// Accounts returns the accounts to provision for an endpoint
	// (identity as in Config.Authorize); an error refuses the
	// Bootstrap-Request with 4.03.
	Accounts func(endpoint, identity string) ([]Account, error)
	// Format of the Bootstrap-Write payloads (default lwm2m.CFTLV; LwM2M
	// 1.1 clients also take lwm2m.CFSenMLCBOR and lwm2m.CFSenMLJSON).
	Format int
	// OnDone is told how each bootstrap ended (nil error: Bootstrap-Finish
	// was accepted).
	OnDone  func(endpoint string, err error)
	Timeout time.Duration // per request, default 10 s
	Logger  *slog.Logger
}

// BootstrapServer is the LwM2M bootstrap server role (client-initiated
// bootstrap, Core clause 5.2.7): on a Bootstrap-Request it deletes the
// client's server accounts, writes the configured ones and sends
// Bootstrap-Finish.
type BootstrapServer struct {
	cfg   BootstrapConfig
	log   *slog.Logger
	mu    sync.Mutex
	stops []func()
}

// NewBootstrap makes a BootstrapServer; Listen starts it.
func NewBootstrap(cfg BootstrapConfig) *BootstrapServer {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Format == 0 {
		cfg.Format = lwm2m.CFTLV
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &BootstrapServer{cfg: cfg, log: cfg.Logger}
}

// Listen serves "coap" or "coaps" on a UDP address in the background.
func (b *BootstrapServer) Listen(scheme, addr string) (net.Addr, error) {
	return listen(scheme, addr, b.cfg.Security, b.serve, &b.mu, &b.stops)
}

// Close stops every listener.
func (b *BootstrapServer) Close() {
	b.mu.Lock()
	stops := b.stops
	b.stops = nil
	b.mu.Unlock()
	for _, f := range stops {
		f()
	}
}

func (b *BootstrapServer) serve(w mux.ResponseWriter, r *mux.Message) {
	p, _ := r.Options().Path()
	if strings.Trim(p, "/") != "bs" || r.Code() != codes.POST {
		respond(w, codes.NotFound)
		return
	}
	ep := queries(r)["ep"]
	if ep == "" {
		respond(w, codes.BadRequest)
		return
	}
	id := peerIdentity(w.Conn())
	accts, err := b.cfg.Accounts(ep, id)
	if err != nil || len(accts) == 0 {
		b.log.Warn("lwm2m bootstrap: refused", "endpoint", ep, "err", err)
		respond(w, codes.Forbidden)
		return
	}
	respond(w, codes.Changed)
	conn := w.Conn()
	go func() {
		err := b.provision(conn, accts)
		if err != nil {
			b.log.Warn("lwm2m bootstrap: failed", "endpoint", ep, "err", err)
		} else {
			b.log.Info("lwm2m bootstrap: done", "endpoint", ep)
		}
		if b.cfg.OnDone != nil {
			b.cfg.OnDone(ep, err)
		}
	}()
}

// Values returns the Security and Server instance values of account a,
// as instances inst of object 0 and object 1.
func (a Account) Values(inst int) (security, server []lwm2m.Value) {
	if a.Lifetime <= 0 {
		a.Lifetime = 300 * time.Second
	}
	if a.Binding == "" {
		a.Binding = "U"
	}
	sec := func(res int, v any) lwm2m.Value {
		return lwm2m.Value{Path: lwm2m.Path{Obj: 0, Inst: inst, Res: res, RI: -1}, V: v}
	}
	security = []lwm2m.Value{sec(0, a.URI), sec(1, false), sec(2, float64(a.Mode)), sec(10, float64(a.ShortServerID))}
	switch a.Mode {
	case ModePSK:
		security = append(security, sec(3, hex.EncodeToString([]byte(a.PSKIdentity))), sec(4, ""), sec(5, hex.EncodeToString(a.PSK)))
	case ModeCertificate:
		security = append(security, sec(3, hex.EncodeToString(a.Certificate)), sec(4, hex.EncodeToString(a.ServerCertificate)), sec(5, hex.EncodeToString(a.PrivateKey)))
	default:
		security = append(security, sec(3, ""), sec(4, ""), sec(5, ""))
	}
	srv := func(res int, v any) lwm2m.Value {
		return lwm2m.Value{Path: lwm2m.Path{Obj: 1, Inst: inst, Res: res, RI: -1}, V: v}
	}
	server = []lwm2m.Value{srv(0, float64(a.ShortServerID)), srv(1, float64(a.Lifetime/time.Second)), srv(6, false), srv(7, a.Binding)}
	return security, server
}

// provision runs Bootstrap-Delete "/", one Bootstrap-Write per instance
// and Bootstrap-Finish (Core clauses 5.2.7.3 to 5.2.7.5).
func (b *BootstrapServer) provision(c mux.Conn, accts []Account) error {
	ctx := context.Background()
	do := func(f func(ctx context.Context) error) error {
		cctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
		defer cancel()
		return f(cctx)
	}
	if err := do(func(ctx context.Context) error {
		m, err := c.Delete(ctx, "/")
		return expect(m, err, codes.Deleted)
	}); err != nil {
		return errors.Join(errors.New("bootstrap-delete"), err)
	}
	// Instance numbers above the bootstrap server's usual 0.
	for i, a := range accts {
		inst := i + 1
		sec, srv := a.Values(inst)
		for _, part := range []struct {
			obj  int
			vals []lwm2m.Value
		}{{0, sec}, {1, srv}} {
			base := lwm2m.Path{Obj: part.obj, Inst: inst, Res: -1, RI: -1}
			payload, err := lwm2m.Encode(b.cfg.Format, nil, base, part.vals)
			if err != nil {
				return err
			}
			if err := do(func(ctx context.Context) error {
				m, err := c.Put(ctx, base.String(), message.MediaType(b.cfg.Format), bytes.NewReader(payload))
				return expect(m, err, codes.Changed)
			}); err != nil {
				return errors.Join(errors.New("bootstrap-write "+base.String()), err)
			}
		}
	}
	return do(func(ctx context.Context) error {
		m, err := c.Post(ctx, "/bs", message.TextPlain, nil)
		return expect(m, err, codes.Changed)
	})
}
