// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package server is the LwM2M server role over CoAP/UDP and CoAP/DTLS
// (pre-shared key or X.509): the registration interface (Register,
// Update, De-register, lifetime expiry), the device management and
// information reporting interfaces towards a registered client (Read,
// Discover, Write, Write-Attributes, Execute, Create, Delete,
// Read-Composite, Write-Composite, Observe and Cancel), and Send. Payloads
// go through the lwm2m package's codecs in any content format. The
// bootstrap server role is BootstrapServer. Clauses cited are of OMA
// LwM2M Core and Transport 1.1.1.
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	piondtls "github.com/pion/dtls/v3"
	coapdtls "github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/message/pool"
	"github.com/plgd-dev/go-coap/v3/mux"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/plgd-dev/go-coap/v3/udp"

	"github.com/cB-Sigma/lwm2m"
)

// Security says how a listener authenticates clients.
type Security struct {
	// PSK returns the key of a PSK identity (security mode 0); an error
	// refuses the handshake.
	PSK func(identity string) ([]byte, error)
	// Certificate is the server's certificate (security mode 2); ClientCAs
	// verify client certificates, which are then required.
	Certificate *tls.Certificate
	ClientCAs   *x509.CertPool
}

// dtlsConfig is the pion configuration of s.
func (s Security) dtlsConfig() (*piondtls.Config, error) {
	cfg := &piondtls.Config{}
	if s.PSK != nil {
		cfg.PSK = func(hint []byte) ([]byte, error) { return s.PSK(string(hint)) }
		cfg.CipherSuites = append(cfg.CipherSuites, piondtls.TLS_PSK_WITH_AES_128_CCM_8, piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256)
	}
	if s.Certificate != nil {
		cfg.Certificates = []tls.Certificate{*s.Certificate}
		cfg.CipherSuites = append(cfg.CipherSuites, piondtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, piondtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
		if s.ClientCAs != nil {
			cfg.ClientCAs = s.ClientCAs
			cfg.ClientAuth = piondtls.RequireAndVerifyClientCert
		}
	}
	if s.PSK == nil && s.Certificate == nil {
		return nil, errors.New("lwm2m server: coaps needs a PSK function or a certificate")
	}
	return cfg, nil
}

// Config sets up a Server.
type Config struct {
	// Security of coaps listeners.
	Security Security
	// Authorize admits a Register: identity is the DTLS PSK identity or
	// the client certificate's common name ("" over plain CoAP). A
	// non-nil error refuses it with 4.03. Nil admits everyone, which suits
	// tests only.
	Authorize func(endpoint, identity string) error
	// OnRegister, OnUpdate and OnDeregister follow the registrations; a
	// registration whose lifetime passes without an Update is removed and
	// reported to OnDeregister.
	OnRegister   func(r *Registration)
	OnUpdate     func(r *Registration)
	OnDeregister func(r *Registration)
	// OnSend receives the values of a Send (Core clause 6.4.1).
	OnSend func(r *Registration, values []lwm2m.Value)
	// Model types values the formats leave untyped (TLV, plain text).
	Model lwm2m.Model
	// Timeout of each request to a client (default 10 s).
	Timeout time.Duration
	// Logger (slog.Default when nil).
	Logger *slog.Logger
}

// Server is an LwM2M server. Its methods are safe for concurrent use.
type Server struct {
	cfg Config
	log *slog.Logger

	mu    sync.Mutex
	regs  map[string]*Registration // by endpoint
	byLoc map[string]*Registration // by location
	stops []func()
	seq   atomic.Uint64
}

// New makes a Server; Listen starts it.
func New(cfg Config) *Server {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{cfg: cfg, log: cfg.Logger, regs: map[string]*Registration{}, byLoc: map[string]*Registration{}}
}

// Listen serves CoAP ("coap") or CoAP over DTLS ("coaps") on a UDP
// address in the background and returns the address it listens on.
func (s *Server) Listen(scheme, addr string) (net.Addr, error) {
	return listen(scheme, addr, s.cfg.Security, s.serve, &s.mu, &s.stops)
}

func listen(scheme, addr string, sec Security, h func(mux.ResponseWriter, *mux.Message), mu *sync.Mutex, stops *[]func()) (net.Addr, error) {
	r := mux.NewRouter()
	r.DefaultHandle(mux.HandlerFunc(h))
	switch scheme {
	case "coap":
		l, err := coapnet.NewListenUDP("udp", addr)
		if err != nil {
			return nil, err
		}
		srv := udp.NewServer(options.WithMux(r))
		go func() { _ = srv.Serve(l) }()
		mu.Lock()
		*stops = append(*stops, func() { srv.Stop(); _ = l.Close() })
		mu.Unlock()
		return l.LocalAddr(), nil
	case "coaps":
		cfg, err := sec.dtlsConfig()
		if err != nil {
			return nil, err
		}
		l, err := coapnet.NewDTLSListener("udp", addr, cfg)
		if err != nil {
			return nil, err
		}
		srv := coapdtls.NewServer(options.WithMux(r))
		go func() { _ = srv.Serve(l) }()
		mu.Lock()
		*stops = append(*stops, func() { srv.Stop(); _ = l.Close() })
		mu.Unlock()
		return l.Addr(), nil
	}
	return nil, fmt.Errorf("lwm2m server: scheme %q is not coap or coaps", scheme)
}

// Close stops every listener.
func (s *Server) Close() {
	s.mu.Lock()
	stops := s.stops
	s.stops = nil
	regs := s.regs
	s.regs, s.byLoc = map[string]*Registration{}, map[string]*Registration{}
	s.mu.Unlock()
	for _, r := range regs {
		r.stopTimer()
	}
	for _, f := range stops {
		f()
	}
}

// Registration is one registered client.
type Registration struct {
	srv *Server

	Endpoint string
	Location string // "/rd/<n>"
	Identity string // PSK identity or certificate common name
	Addr     net.Addr

	mu       sync.Mutex
	lifetime time.Duration
	version  string
	binding  string
	sms      string
	queue    bool
	root     string
	links    []string
	conn     mux.Conn
	timer    *time.Timer
	updated  time.Time
}

// Lifetime, Version, Binding, ObjectLinks and RootPath are the client's
// registration parameters as last registered or updated.
func (r *Registration) Lifetime() time.Duration { r.mu.Lock(); defer r.mu.Unlock(); return r.lifetime }

// Version is the lwm2m= parameter ("1.0" when absent).
func (r *Registration) Version() string { r.mu.Lock(); defer r.mu.Unlock(); return r.version }

// Binding is the b= parameter ("U" when absent).
func (r *Registration) Binding() string { r.mu.Lock(); defer r.mu.Unlock(); return r.binding }

// QueueMode reports the Q binding or the Q parameter of LwM2M 1.1.
func (r *Registration) QueueMode() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.queue }

// ObjectLinks are the object and instance links of the payload.
func (r *Registration) ObjectLinks() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.links...)
}

// RootPath is the alternate path of the client's objects ("" for "/").
func (r *Registration) RootPath() string { r.mu.Lock(); defer r.mu.Unlock(); return r.root }

// Updated is when the registration was last refreshed.
func (r *Registration) Updated() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.updated }

func (r *Registration) stopTimer() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.timer.Stop()
	}
}

// Registration is the registration of endpoint, or nil.
func (s *Server) Registration(endpoint string) *Registration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.regs[endpoint]
}

// Registrations lists the registered clients.
func (s *Server) Registrations() []*Registration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Registration, 0, len(s.regs))
	for _, r := range s.regs {
		out = append(out, r)
	}
	return out
}

// peerIdentity is the PSK identity or certificate common name of a DTLS
// connection, or "".
func peerIdentity(c mux.Conn) string {
	dc, ok := c.NetConn().(*piondtls.Conn)
	if !ok {
		return ""
	}
	st, ok := dc.ConnectionState()
	if !ok {
		return ""
	}
	if len(st.IdentityHint) > 0 {
		return string(st.IdentityHint)
	}
	if len(st.PeerCertificates) > 0 {
		if crt, err := x509.ParseCertificate(st.PeerCertificates[0]); err == nil {
			return crt.Subject.CommonName
		}
	}
	return ""
}

func respond(w mux.ResponseWriter, code codes.Code, opts ...message.Option) {
	_ = w.SetResponse(code, message.TextPlain, nil, opts...)
}

func readBody(r *mux.Message) []byte {
	if r.Body() == nil {
		return nil
	}
	b, _ := io.ReadAll(r.Body())
	return b
}

func queries(m *mux.Message) map[string]string {
	qs, _ := m.Options().Queries()
	out := map[string]string{}
	for _, q := range qs {
		k, v, _ := strings.Cut(q, "=")
		out[k] = v
	}
	return out
}

func (s *Server) serve(w mux.ResponseWriter, r *mux.Message) {
	p, _ := r.Options().Path()
	p = "/" + strings.Trim(p, "/")
	switch {
	case p == "/rd" && r.Code() == codes.POST:
		s.register(w, r)
	case strings.HasPrefix(p, "/rd/") && r.Code() == codes.POST:
		s.update(w, r, p)
	case strings.HasPrefix(p, "/rd/") && r.Code() == codes.DELETE:
		s.deregister(w, p)
	case p == "/dp" && (r.Code() == codes.POST || r.Code() == codes.PUT):
		s.send(w, r)
	default:
		respond(w, codes.NotFound)
	}
}

// register handles Register (Core clause 6.2.1; Transport 6.2).
func (s *Server) register(w mux.ResponseWriter, m *mux.Message) {
	q := queries(m)
	ep := q["ep"]
	if ep == "" {
		respond(w, codes.BadRequest)
		return
	}
	id := peerIdentity(w.Conn())
	if s.cfg.Authorize != nil {
		if err := s.cfg.Authorize(ep, id); err != nil {
			s.log.Warn("lwm2m server: register refused", "endpoint", ep, "err", err)
			respond(w, codes.Forbidden)
			return
		}
	}
	reg := &Registration{srv: s, Endpoint: ep, Identity: id, Addr: w.Conn().RemoteAddr(), conn: w.Conn(),
		lifetime: 86400 * time.Second, version: "1.0", binding: "U"}
	if err := reg.apply(q, readBody(m), true); err != nil {
		respond(w, codes.BadRequest)
		return
	}
	reg.Location = "/rd/" + strconv.FormatUint(s.seq.Add(1), 10)
	s.mu.Lock()
	old := s.regs[ep]
	if old != nil {
		delete(s.byLoc, old.Location)
	}
	s.regs[ep] = reg
	s.byLoc[reg.Location] = reg
	s.mu.Unlock()
	if old != nil {
		old.stopTimer()
	}
	reg.arm()
	loc := strings.Split(strings.TrimPrefix(reg.Location, "/"), "/")
	respond(w, codes.Created, message.Option{ID: message.LocationPath, Value: []byte(loc[0])}, message.Option{ID: message.LocationPath, Value: []byte(loc[1])})
	s.log.Info("lwm2m server: registered", "endpoint", ep, "location", reg.Location)
	if s.cfg.OnRegister != nil {
		go s.cfg.OnRegister(reg)
	}
}

// apply takes the parameters and payload of a Register or Update.
func (r *Registration) apply(q map[string]string, body []byte, register bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := q["lt"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return errors.New("bad lifetime")
		}
		r.lifetime = time.Duration(n) * time.Second
	}
	if v, ok := q["lwm2m"]; ok {
		r.version = v
	}
	if v, ok := q["b"]; ok {
		r.binding = v
	}
	if v, ok := q["sms"]; ok {
		r.sms = v
	}
	_, qp := q["Q"]
	r.queue = qp || strings.Contains(r.binding, "Q")
	if len(body) > 0 || register {
		r.root, r.links = lwm2m.ParseRegistration(string(body))
		r.root = strings.TrimSuffix(r.root, "/")
	}
	r.updated = time.Now()
	return nil
}

// arm (re)starts the lifetime timer.
func (r *Registration) arm() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(r.lifetime, func() { r.srv.expire(r) })
}

func (s *Server) expire(r *Registration) {
	s.mu.Lock()
	cur := s.regs[r.Endpoint]
	if cur == r {
		delete(s.regs, r.Endpoint)
		delete(s.byLoc, r.Location)
	}
	s.mu.Unlock()
	if cur == r {
		s.log.Info("lwm2m server: registration expired", "endpoint", r.Endpoint)
		if s.cfg.OnDeregister != nil {
			s.cfg.OnDeregister(r)
		}
	}
}

// update handles Update (Core clause 6.2.2): the client's address may
// have changed, so the connection is taken from this request.
func (s *Server) update(w mux.ResponseWriter, m *mux.Message, loc string) {
	s.mu.Lock()
	reg := s.byLoc[loc]
	s.mu.Unlock()
	if reg == nil {
		respond(w, codes.NotFound)
		return
	}
	if err := reg.apply(queries(m), readBody(m), false); err != nil {
		respond(w, codes.BadRequest)
		return
	}
	reg.mu.Lock()
	reg.conn, reg.Addr = w.Conn(), w.Conn().RemoteAddr()
	reg.mu.Unlock()
	reg.arm()
	respond(w, codes.Changed)
	if s.cfg.OnUpdate != nil {
		go s.cfg.OnUpdate(reg)
	}
}

func (s *Server) deregister(w mux.ResponseWriter, loc string) {
	s.mu.Lock()
	reg := s.byLoc[loc]
	if reg != nil {
		delete(s.byLoc, loc)
		if s.regs[reg.Endpoint] == reg {
			delete(s.regs, reg.Endpoint)
		}
	}
	s.mu.Unlock()
	if reg == nil {
		respond(w, codes.NotFound)
		return
	}
	reg.stopTimer()
	respond(w, codes.Deleted)
	if s.cfg.OnDeregister != nil {
		go s.cfg.OnDeregister(reg)
	}
}

// send handles Send (Core clause 6.4.1) from a registered client.
func (s *Server) send(w mux.ResponseWriter, m *mux.Message) {
	var reg *Registration
	s.mu.Lock()
	for _, r := range s.regs {
		r.mu.Lock()
		same := r.conn == w.Conn()
		r.mu.Unlock()
		if same {
			reg = r
			break
		}
	}
	s.mu.Unlock()
	if reg == nil {
		respond(w, codes.Forbidden)
		return
	}
	cf, err := m.Options().ContentFormat()
	if err != nil {
		respond(w, codes.BadRequest)
		return
	}
	vals, err := lwm2m.Decode(int(cf), s.cfg.Model, lwm2m.Path{Obj: -1, Inst: -1, Res: -1, RI: -1}, readBody(m))
	if err != nil {
		respond(w, codes.BadRequest)
		return
	}
	respond(w, codes.Changed)
	if s.cfg.OnSend != nil {
		go s.cfg.OnSend(reg, vals)
	}
}

// CodeError is a client's answer other than the success code.
type CodeError struct{ Code codes.Code }

func (e *CodeError) Error() string { return "the client answered " + e.Code.String() }

// ErrGone is returned for a registration that has ended.
var ErrGone = errors.New("the registration has ended")

func (r *Registration) connection() (mux.Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		return nil, ErrGone
	}
	return r.conn, nil
}

// target is p under the client's alternate path.
func (r *Registration) target(p string) string {
	return r.RootPath() + p
}

func uintOpt(id message.OptionID, v uint32) message.Option {
	var b []byte
	for ; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return message.Option{ID: id, Value: b}
}

func (r *Registration) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.srv.cfg.Timeout)
}

func body(m *pool.Message) []byte {
	if m.Body() == nil {
		return nil
	}
	b, _ := io.ReadAll(m.Body())
	return b
}

func expect(m *pool.Message, err error, ok codes.Code) error {
	if err != nil {
		return err
	}
	if m.Code() != ok {
		return &CodeError{Code: m.Code()}
	}
	return nil
}

// decode reads the payload of an answer about base.
func (r *Registration) decode(m *pool.Message, base lwm2m.Path) ([]lwm2m.Value, error) {
	cf, err := m.Options().ContentFormat()
	if err != nil {
		cf = message.TextPlain
	}
	return lwm2m.Decode(int(cf), r.srv.cfg.Model, base, body(m))
}

// Read reads path in content format cf (0 lets the client choose; the
// lwm2m.CF* numbers otherwise).
func (r *Registration) Read(ctx context.Context, path string, cf int) ([]lwm2m.Value, error) {
	base, err := lwm2m.ParsePath(path)
	if err != nil {
		return nil, err
	}
	c, err := r.connection()
	if err != nil {
		return nil, err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var opts []message.Option
	if cf > 0 {
		opts = append(opts, uintOpt(message.Accept, uint32(cf)))
	}
	m, err := c.Get(ctx, r.target(path), opts...)
	if err := expect(m, err, codes.Content); err != nil {
		return nil, err
	}
	return r.decode(m, base)
}

// Discover returns the links of path's Discover answer (Core 6.3.2).
func (r *Registration) Discover(ctx context.Context, path string) ([]string, error) {
	c, err := r.connection()
	if err != nil {
		return nil, err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	m, err := c.Get(ctx, r.target(path), uintOpt(message.Accept, uint32(message.AppLinkFormat)))
	if err := expect(m, err, codes.Content); err != nil {
		return nil, err
	}
	return lwm2m.ParseLinks(string(body(m))), nil
}

// Write writes values under path in content format cf: replace true is
// a PUT (Replace), false a POST (Partial Update) (Core 6.3.3).
func (r *Registration) Write(ctx context.Context, path string, cf int, replace bool, values []lwm2m.Value) error {
	base, err := lwm2m.ParsePath(path)
	if err != nil {
		return err
	}
	b, err := lwm2m.Encode(cf, r.srv.cfg.Model, base, values)
	if err != nil {
		return err
	}
	c, err := r.connection()
	if err != nil {
		return err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var m *pool.Message
	if replace {
		m, err = c.Put(ctx, r.target(path), message.MediaType(cf), bytes.NewReader(b))
	} else {
		m, err = c.Post(ctx, r.target(path), message.MediaType(cf), bytes.NewReader(b))
	}
	return expect(m, err, codes.Changed)
}

// WriteAttributes sets notification attributes on path, query as
// "pmin=10&pmax=60" (Core 6.3.4).
func (r *Registration) WriteAttributes(ctx context.Context, path, query string) error {
	c, err := r.connection()
	if err != nil {
		return err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var opts []message.Option
	for _, q := range strings.Split(query, "&") {
		if q != "" {
			opts = append(opts, message.Option{ID: message.URIQuery, Value: []byte(q)})
		}
	}
	m, err := c.Put(ctx, r.target(path), message.TextPlain, nil, opts...)
	return expect(m, err, codes.Changed)
}

// Execute executes a resource with optional arguments (Core 6.3.5).
func (r *Registration) Execute(ctx context.Context, path, args string) error {
	c, err := r.connection()
	if err != nil {
		return err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	var payload io.ReadSeeker
	if args != "" {
		payload = strings.NewReader(args)
	}
	m, err := c.Post(ctx, r.target(path), message.TextPlain, payload)
	return expect(m, err, codes.Changed)
}

// Create creates an instance of object path with values (their paths
// under the new instance) and returns its location (Core 6.3.6).
func (r *Registration) Create(ctx context.Context, path string, cf int, values []lwm2m.Value) (string, error) {
	base, err := lwm2m.ParsePath(path)
	if err != nil {
		return "", err
	}
	b, err := lwm2m.Encode(cf, r.srv.cfg.Model, base, values)
	if err != nil {
		return "", err
	}
	c, err := r.connection()
	if err != nil {
		return "", err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	m, err := c.Post(ctx, r.target(path), message.MediaType(cf), bytes.NewReader(b))
	if err := expect(m, err, codes.Created); err != nil {
		return "", err
	}
	loc, _ := m.Options().LocationPath()
	return "/" + strings.Trim(loc, "/"), nil
}

// Delete deletes an object instance (Core 6.3.7).
func (r *Registration) Delete(ctx context.Context, path string) error {
	c, err := r.connection()
	if err != nil {
		return err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	m, err := c.Delete(ctx, r.target(path))
	return expect(m, err, codes.Deleted)
}

// ReadComposite reads paths in one request (Core 6.3.8), the request in
// SenML JSON or CBOR names (cf of the answer: lwm2m.CFSenMLJSON or
// lwm2m.CFSenMLCBOR).
func (r *Registration) ReadComposite(ctx context.Context, paths []string, cf int) ([]lwm2m.Value, error) {
	reqCF := lwm2m.CFSenMLEtchJSON
	if cf == lwm2m.CFSenMLCBOR {
		reqCF = lwm2m.CFSenMLEtchCBOR
	}
	b, err := lwm2m.EncodePaths(reqCF, paths)
	if err != nil {
		return nil, err
	}
	c, err := r.connection()
	if err != nil {
		return nil, err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	req, err := c.NewGetRequest(ctx, r.target("/"))
	if err != nil {
		return nil, err
	}
	req.SetCode(codes.Code(5)) // FETCH (RFC 8132)
	req.SetContentFormat(message.MediaType(reqCF))
	req.SetBody(bytes.NewReader(b))
	req.SetOptionUint32(message.Accept, uint32(cf))
	m, err := c.Do(req)
	if err := expect(m, err, codes.Content); err != nil {
		return nil, err
	}
	return r.decode(m, lwm2m.Path{Obj: -1, Inst: -1, Res: -1, RI: -1})
}

// WriteComposite writes values at several paths in one request (Core
// 6.3.9), in SenML JSON or CBOR.
func (r *Registration) WriteComposite(ctx context.Context, cf int, values []lwm2m.Value) error {
	b, err := lwm2m.Encode(cf, r.srv.cfg.Model, lwm2m.Path{Obj: -1, Inst: -1, Res: -1, RI: -1}, values)
	if err != nil {
		return err
	}
	c, err := r.connection()
	if err != nil {
		return err
	}
	ctx, cancel := r.ctx(ctx)
	defer cancel()
	req, err := c.NewGetRequest(ctx, r.target("/"))
	if err != nil {
		return err
	}
	req.SetCode(codes.Code(7)) // iPATCH (RFC 8132)
	req.SetContentFormat(message.MediaType(cf))
	req.SetBody(bytes.NewReader(b))
	m, err := c.Do(req)
	return expect(m, err, codes.Changed)
}

// Observation is a running observation.
type Observation struct {
	obs  mux.Observation
	stop sync.Once
}

// Cancel cancels the observation with a GET carrying Observe 1 (Core
// 6.3.10, Transport: the active cancellation).
func (o *Observation) Cancel(ctx context.Context) error {
	var err error
	o.stop.Do(func() { err = o.obs.Cancel(ctx) })
	return err
}

// Observe observes path in content format cf (0: the client's choice);
// notify gets the values of the first answer and every notification.
func (r *Registration) Observe(ctx context.Context, path string, cf int, notify func([]lwm2m.Value)) (*Observation, error) {
	base, err := lwm2m.ParsePath(path)
	if err != nil {
		return nil, err
	}
	c, err := r.connection()
	if err != nil {
		return nil, err
	}
	var opts []message.Option
	if cf > 0 {
		opts = append(opts, uintOpt(message.Accept, uint32(cf)))
	}
	first := make(chan error, 1)
	var once sync.Once
	obs, err := c.Observe(ctx, r.target(path), func(m *pool.Message) {
		if m.Code() != codes.Content {
			once.Do(func() { first <- &CodeError{Code: m.Code()} })
			return
		}
		once.Do(func() { first <- nil })
		vals, err := r.decode(m, base)
		if err != nil {
			r.srv.log.Warn("lwm2m server: notification", "endpoint", r.Endpoint, "err", err)
			return
		}
		notify(vals)
	}, opts...)
	if err != nil {
		return nil, err
	}
	select {
	case err := <-first:
		if err != nil {
			return nil, err
		}
	case <-time.After(r.srv.cfg.Timeout):
		_ = obs.Cancel(context.Background())
		return nil, errors.New("lwm2m server: no answer to Observe")
	}
	return &Observation{obs: obs}, nil
}
