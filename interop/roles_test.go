// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/lwm2m"
	"github.com/cB-Sigma/lwm2m/server"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func containerName(t *testing.T, role string) string {
	return "sigma-lwm2m-interop-" + role + "-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
}

// lwm2mServerRole starts this module's server role on all interfaces.
func lwm2mServerRole(t *testing.T, scheme string, cfg server.Config) (*server.Server, int, chan *server.Registration) {
	t.Helper()
	regs := make(chan *server.Registration, 4)
	cfg.OnRegister = func(r *server.Registration) { regs <- r }
	cfg.Logger = quiet
	s := server.New(cfg)
	addr, err := s.Listen(scheme, "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, addr.(*net.UDPAddr).Port, regs
}

func waitReg(t *testing.T, regs chan *server.Registration) *server.Registration {
	t.Helper()
	select {
	case r := <-regs:
		return r
	case <-time.After(90 * time.Second):
		t.Fatal("no registration within 90 s")
	}
	return nil
}

// Leshan's demo client against this module's server role (package
// server): registration, reads in each format, discover, write
// attributes, a write it reads back, an observation with notifications,
// and an execute.
func TestLeshanClientAgainstServerRole(t *testing.T) {
	needDocker(t)
	_, port, regs := lwm2mServerRole(t, "coap", server.Config{})
	startContainer(t, containerName(t, "client"), "java", "-jar", "client.jar", "-u", fmt.Sprintf("coap://host.docker.internal:%d", port), "-n", "sigma-role", "-l", "120")
	reg := waitReg(t, regs)
	if reg.Endpoint != "sigma-role" || reg.Lifetime() != 120*time.Second {
		t.Fatalf("registration %s %v", reg.Endpoint, reg.Lifetime())
	}
	t.Logf("registered: lwm2m=%s b=%s links=%v", reg.Version(), reg.Binding(), reg.ObjectLinks())
	for _, f := range formats {
		vals, err := reg.Read(ctx(t), "/3/0", f.cf)
		var ce *server.CodeError
		if errors.As(err, &ce) {
			t.Logf("%s: Leshan answered %v", f.name, ce.Code)
			continue
		}
		if err != nil || flat(vals)["/3/0/0"] == nil {
			t.Errorf("%s read: %v %v", f.name, flat(vals), err)
		}
	}
	links, err := reg.Discover(ctx(t), "/3303/0")
	if err != nil || !contains(links, "/3303/0/5700") {
		t.Errorf("discover: %v %v", links, err)
	}
	if err := reg.WriteAttributes(ctx(t), "/3303/0/5700", "pmin=1&pmax=2"); err != nil {
		t.Errorf("write attributes: %v", err)
	}
	p, _ := lwm2m.ParsePath("/3/0/14")
	if err := reg.Write(ctx(t), "/3/0/14", lwm2m.CFSenMLCBOR, true, []lwm2m.Value{{Path: p, V: "+05:30"}}); err != nil {
		t.Errorf("write: %v", err)
	} else if v, err := reg.Read(ctx(t), "/3/0/14", lwm2m.CFText); err != nil || len(v) != 1 || v[0].V != "+05:30" {
		t.Errorf("read back: %v %v", v, err)
	}
	notes := make(chan []lwm2m.Value, 16)
	obs, err := reg.Observe(ctx(t), "/3303/0/5700", lwm2m.CFSenMLJSON, func(v []lwm2m.Value) { notes <- v })
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for i := 0; i < 3; i++ {
		select {
		case v := <-notes:
			if len(v) != 1 {
				t.Errorf("notification %d: %v", i, v)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("notification %d missing", i)
		}
	}
	if err := obs.Cancel(ctx(t)); err != nil {
		t.Errorf("cancel: %v", err)
	}
	if err := reg.Execute(ctx(t), "/3/0/4", ""); err != nil {
		t.Errorf("execute reboot: %v", err)
	}
}

// Leshan's demo client over DTLS with a pre-shared key against the server
// role; the PSK identity reaches Authorize.
func TestLeshanClientPSKAgainstServerRole(t *testing.T) {
	needDocker(t)
	key := []byte("leshan-psk-key-1")
	_, port, regs := lwm2mServerRole(t, "coaps", server.Config{
		Security: server.Security{PSK: func(id string) ([]byte, error) {
			if id != "sigma-psk-id" {
				return nil, errors.New("unknown identity")
			}
			return key, nil
		}},
		Authorize: func(ep, id string) error {
			if id != "sigma-psk-id" {
				return errors.New("wrong identity")
			}
			return nil
		},
	})
	startContainer(t, containerName(t, "client"), "java", "-jar", "client.jar", "-u", fmt.Sprintf("coaps://host.docker.internal:%d", port),
		"-n", "sigma-psk", "-i", "sigma-psk-id", "-p", hex.EncodeToString(key))
	reg := waitReg(t, regs)
	if reg.Identity != "sigma-psk-id" {
		t.Errorf("identity %q", reg.Identity)
	}
	if vals, err := reg.Read(ctx(t), "/3/0", lwm2m.CFTLV); err != nil || flat(vals)["/3/0/0"] == nil {
		t.Errorf("read over DTLS: %v %v", vals, err)
	}
}

// Leshan's demo client bootstraps from this module's bootstrap server
// role, which provisions the server role as its LwM2M server; the client
// then registers there.
func TestLeshanClientBootstrapsFromBootstrapRole(t *testing.T) {
	needDocker(t)
	_, port, regs := lwm2mServerRole(t, "coap", server.Config{})
	done := make(chan error, 2)
	for _, format := range []struct {
		name string
		cf   int
	}{{"TLV", lwm2m.CFTLV}, {"SenML CBOR", lwm2m.CFSenMLCBOR}} {
		t.Run(format.name, func(t *testing.T) {
			ep := "sigma-bs-" + strings.ReplaceAll(strings.ToLower(format.name), " ", "")
			bs := server.NewBootstrap(server.BootstrapConfig{Logger: quiet, Format: format.cf,
				Accounts: func(endpoint, _ string) ([]server.Account, error) {
					if endpoint != ep {
						return nil, errors.New("unknown endpoint")
					}
					return []server.Account{{URI: fmt.Sprintf("coap://host.docker.internal:%d", port), ShortServerID: 123,
						Mode: server.ModeNoSec, Lifetime: 100 * time.Second}}, nil
				},
				OnDone: func(_ string, err error) { done <- err }})
			baddr, err := bs.Listen("coap", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			defer bs.Close()
			startContainer(t, containerName(t, "client"), "java", "-jar", "client.jar", "-b", "-u",
				fmt.Sprintf("coap://host.docker.internal:%d", baddr.(*net.UDPAddr).Port), "-n", ep)
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("bootstrap: %v", err)
				}
			case <-time.After(90 * time.Second):
				t.Fatal("no bootstrap within 90 s")
			}
			reg := waitReg(t, regs)
			if reg.Endpoint != ep || reg.Lifetime() != 100*time.Second {
				t.Errorf("registered %s for %v", reg.Endpoint, reg.Lifetime())
			}
		})
	}
}
