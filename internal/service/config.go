// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package service implements demonstration-only HTTP infrastructure. It contains
// no membership, issuance, submission, signing, or persistence implementation.
package service

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Role identifies a process boundary, not an administrative authorization role.
type Role string

const (
	CA         Role = "ca"
	Issuer     Role = "issuer"
	Submission Role = "submission"
)

// DefaultListen assigns distinct loopback ports without looking up hostnames.
func (r Role) DefaultListen() string {
	switch r {
	case CA:
		return "127.0.0.1:8082"
	case Issuer:
		return "127.0.0.1:8081"
	case Submission:
		return "127.0.0.1:8080"
	default:
		return ""
	}
}

// Config describes a local demonstration process. There are no secret settings.
type Config struct {
	Role             Role
	Listen           string
	SourceURL        string
	DevStyleGuide    bool
	ContainerNetwork bool
}

// Validate requires explicit container networking for IPv4 wildcard binds. Errors
// omit the supplied values, which might contain accidentally pasted credentials.
func (c Config) Validate() error {
	if c.Role.DefaultListen() == "" {
		return errors.New("unknown service role")
	}
	if c.DevStyleGuide && c.Role != Submission {
		return errors.New("development style guide is available only on the submission process")
	}
	if len(c.Listen) > 128 {
		return errors.New("listen address is too long")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("listen address must contain an IP literal and port")
	}
	ip, err := netip.ParseAddr(host)
	allowed := ip.IsLoopback() || c.ContainerNetwork && ip == netip.IPv4Unspecified()
	if err != nil || ip.Zone() != "" || !allowed {
		return errors.New("listen host requires loopback or explicit container IPv4 wildcard binding")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || strconv.FormatUint(n, 10) != port {
		return errors.New("listen port must be a canonical decimal integer from 0 to 65535")
	}
	if len(c.SourceURL) == 0 || len(c.SourceURL) > 2048 {
		return errors.New("source URL is required and must not exceed 2048 bytes")
	}
	u, err := url.Parse(c.SourceURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || strings.Contains(c.SourceURL, "#") {
		return errors.New("source URL must be absolute HTTPS without credentials, query, or fragment")
	}
	return nil
}
