// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

const testSource = "https://source.example.invalid/anonce/archive/test-revision.tar.gz"

func testConfig(role Role) Config {
	return Config{Role: role, Listen: role.DefaultListen(), SourceURL: testSource}
}

func TestConfig(t *testing.T) {
	t.Parallel()
	for _, role := range []Role{CA, Issuer, Submission} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			if err := testConfig(role).Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
	cases := []struct {
		name   string
		listen string
		valid  bool
	}{
		{"ipv4", "127.0.0.1:8080", true},
		{"ipv4 loopback range", "127.2.3.4:1", true},
		{"ipv6", "[::1]:65535", true},
		{"mapped loopback", "[::ffff:127.0.0.1]:8080", true},
		{"ephemeral", "127.0.0.1:0", true},
		{"empty", "", false},
		{"wildcard", ":8080", false},
		{"ipv4 wildcard", "0.0.0.0:8080", false},
		{"ipv6 wildcard", "[::]:8080", false},
		{"public", "192.0.2.1:8080", false},
		{"private network", "192.168.1.1:8080", false},
		{"hostname", "localhost:8080", false},
		{"zoned", "[::1%lo]:8080", false},
		{"missing port", "127.0.0.1", false},
		{"empty port", "127.0.0.1:", false},
		{"named port", "127.0.0.1:http", false},
		{"negative port", "127.0.0.1:-1", false},
		{"signed port", "127.0.0.1:+1", false},
		{"padded port", "127.0.0.1:08080", false},
		{"overflow port", "127.0.0.1:65536", false},
		{"oversize", strings.Repeat("x", 129), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(Submission)
			cfg.Listen = tc.listen
			if err := cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, tc.valid)
			}
		})
	}
	if err := testConfig(Role("unknown")).Validate(); err == nil {
		t.Fatal("accepted unknown role")
	}
}

func TestConfigSourceURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		url   string
		valid bool
	}{
		{"archive", testSource, true},
		{"escaped path", "https://source.example.invalid/a%20b.tar.gz", true},
		{"empty", "", false},
		{"relative", "/source", false},
		{"scheme relative", "//source.example.invalid/archive", false},
		{"cleartext", "http://source.example.invalid/archive", false},
		{"script", "javascript:alert(1)", false},
		{"opaque", "https:source.example.invalid", false},
		{"missing host", "https:///archive", false},
		{"userinfo", "https://synthetic-input@source.example.invalid/archive", false},
		{"password", "https://test:synthetic-input@source.example.invalid/archive", false},
		{"query", testSource + "?value=synthetic-input", false},
		{"empty query", testSource + "?", false},
		{"fragment", testSource + "#synthetic-input", false},
		{"empty fragment", testSource + "#", false},
		{"newline", testSource + "\nsynthetic-input", false},
		{"invalid escape", testSource + "%", false},
		{"invalid port", "https://source.example.invalid:invalid/archive", false},
		{"oversize", testSource + strings.Repeat("x", 2048), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(Submission)
			cfg.SourceURL = tc.url
			err := cfg.Validate()
			if (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, tc.valid)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-input") {
				t.Fatal("error reflected supplied value")
			}
		})
	}
}

func TestContainerNetwork(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		listen string
		valid  bool
	}{
		{"0.0.0.0:8080", true},
		{"0.0.0.0:0", true},
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"[::]:8080", false},
		{"[::ffff:0.0.0.0]:8080", false},
		{"192.168.1.1:8080", false},
		{"192.0.2.1:8080", false},
		{":8080", false},
		{"localhost:8080", false},
		{"0.0.0.0:08080", false},
		{"[::1%lo]:8080", false},
	} {
		t.Run(tc.listen, func(t *testing.T) {
			t.Parallel()
			for _, role := range []Role{CA, Issuer, Submission} {
				cfg := testConfig(role)
				cfg.Listen, cfg.ContainerNetwork = tc.listen, true
				if err := cfg.Validate(); (err == nil) != tc.valid {
					t.Fatalf("container bind validation: %v", err)
				}
				cfg.ContainerNetwork = false
				if tc.listen == "0.0.0.0:8080" && cfg.Validate() == nil {
					t.Fatal("wildcard accepted without explicit opt-in")
				}
			}
		})
	}
}

func FuzzContainerListen(f *testing.F) {
	f.Add("0.0.0.0:8080", true)
	f.Add("0.0.0.0:8080", false)
	f.Add("[::]:8080", true)
	f.Add("127.0.0.1:0", true)
	f.Fuzz(func(t *testing.T, listen string, enabled bool) {
		if len(listen) > 129 {
			return
		}
		cfg := testConfig(Submission)
		cfg.Listen, cfg.ContainerNetwork = listen, enabled
		if cfg.Validate() != nil {
			return
		}
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := netip.ParseAddr(host)
		allowed := ip.IsLoopback() || enabled && ip == netip.IPv4Unspecified()
		if err != nil || ip.Zone() != "" || !allowed {
			t.Fatal("container listen boundary escaped")
		}
	})
}

func FuzzConfig(f *testing.F) {
	f.Add(string(Submission), "127.0.0.1:8080", testSource, false)
	f.Add(string(Submission), "127.0.0.1:8080", testSource, true)
	f.Add(string(CA), "[::1]:0", testSource, true)
	f.Add(string(Issuer), "0.0.0.0:8081", "https://test:synthetic-input@source.example.invalid", false)
	f.Add("unknown", "", "", false)
	f.Add(string(Submission), "127.0.0.1:8080", "HTTPS://source.example.invalid/archive", false)
	f.Fuzz(func(t *testing.T, role, listen, source string, styleGuide bool) {
		// Bound parser work and allocations independently of the corpus generator.
		if len(role)+len(listen)+len(source) > 8192 {
			return
		}
		cfg := Config{Role: Role(role), Listen: listen, SourceURL: source, DevStyleGuide: styleGuide}
		if err := cfg.Validate(); err != nil {
			if len(err.Error()) > 128 {
				t.Fatal("validation returned an unbounded error")
			}
			return
		}
		if styleGuide && cfg.Role != Submission {
			t.Fatal("accepted identity-side development UI")
		}
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
			t.Fatal("accepted a non-loopback bind")
		}
		u, err := url.Parse(source)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			t.Fatal("accepted a non-HTTPS source URL")
		}
	})
}
