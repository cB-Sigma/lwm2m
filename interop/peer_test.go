// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/plgd-dev/go-coap/v3/udp"
)

// image is the Leshan peer built from peer/Dockerfile.
const image = "sigma-lwm2m-leshan:2.0.0-M18"

// needDocker skips the test unless SIGMA_LWM2M_INTEROP=1 is set and
// Docker answers, and builds the peer image (from cache after the first
// run).
func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGMA_LWM2M_INTEROP") != "1" {
		t.Skip("set SIGMA_LWM2M_INTEROP=1 to run the Leshan interop tests (needs Docker)")
	}
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker does not answer: %v", err)
	}
	buildOnce.Do(func() {
		_, file, _, _ := runtime.Caller(0)
		out, err := exec.Command("docker", "build", "-q", "-t", image, filepath.Join(filepath.Dir(file), "peer")).CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("docker build: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
}

var (
	buildOnce sync.Once
	buildErr  error
)

// startContainer runs the Leshan image with args and stops it at the end
// of the test; the container reaches the host as host.docker.internal.
func startContainer(t *testing.T, name string, args ...string) {
	t.Helper()
	full := append([]string{"run", "--rm", "-d", "--name", name, "--add-host=host.docker.internal:host-gateway", image}, args...)
	if out, err := exec.Command("docker", full...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "60", name).CombinedOutput()
			t.Logf("%s logs:\n%s", name, out)
		}
		_ = exec.Command("docker", "stop", "-t", "2", name).Run()
	})
}

// registration is what a Register or Update brought.
type registration struct {
	query   []string
	payload string
	conn    mux.Conn
}

// lwm2mServer is a minimal LwM2M server in the test: it accepts Register,
// Update and De-register and hands the client's connection to the test,
// which then sends the device management requests itself.
type lwm2mServer struct {
	port int
	regs chan registration
	mu   sync.Mutex
	gone bool
}

func newServer(t *testing.T) *lwm2mServer {
	t.Helper()
	l, err := coapnet.NewListenUDP("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &lwm2mServer{port: l.LocalAddr().(*net.UDPAddr).Port, regs: make(chan registration, 16)}
	r := mux.NewRouter()
	r.DefaultHandle(mux.HandlerFunc(s.serve))
	srv := udp.NewServer(options.WithMux(r))
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { srv.Stop(); _ = l.Close() })
	return s
}

func (s *lwm2mServer) serve(w mux.ResponseWriter, r *mux.Message) {
	p, _ := r.Options().Path()
	p = strings.Trim(p, "/")
	switch {
	case p == "rd" && r.Code() == codes.POST:
		qs, _ := r.Options().Queries()
		var body []byte
		if r.Body() != nil {
			var b bytes.Buffer
			_, _ = b.ReadFrom(r.Body())
			body = b.Bytes()
		}
		s.regs <- registration{query: qs, payload: string(body), conn: w.Conn()}
		_ = w.SetResponse(codes.Created, message.TextPlain, nil, message.Option{ID: message.LocationPath, Value: []byte("rd")},
			message.Option{ID: message.LocationPath, Value: []byte("1")})
	case p == "rd/1" && r.Code() == codes.POST:
		_ = w.SetResponse(codes.Changed, message.TextPlain, nil)
	case p == "rd/1" && r.Code() == codes.DELETE:
		s.mu.Lock()
		s.gone = true
		s.mu.Unlock()
		_ = w.SetResponse(codes.Deleted, message.TextPlain, nil)
	default:
		_ = w.SetResponse(codes.NotFound, message.TextPlain, nil)
	}
}

// waitRegistration waits for the first Register.
func (s *lwm2mServer) waitRegistration(t *testing.T) registration {
	t.Helper()
	select {
	case reg := <-s.regs:
		return reg
	case <-time.After(60 * time.Second):
		t.Fatal("no registration within 60 s")
	}
	return registration{}
}

// uintOpt encodes a CoAP uint option value.
func uintOpt(id message.OptionID, v uint32) message.Option {
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	return message.Option{ID: id, Value: b}
}

func accept(cf int) message.Option { return uintOpt(message.Accept, uint32(cf)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}
