// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce/internal/service"
)

const sourceArg = "https://source.example.invalid/anonce/archive/test-revision.tar.gz"

func TestParse(t *testing.T) {
	t.Parallel()
	for _, role := range []service.Role{service.CA, service.Issuer, service.Submission} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			cfg, err := parse(role, []string{"-source-url", sourceArg}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Role != role || cfg.Listen != role.DefaultListen() || cfg.SourceURL != sourceArg {
				t.Fatalf("unexpected config: %+v", cfg)
			}
		})
	}
	cfg, err := parse(service.Submission, []string{"-listen", "[::1]:8888", "-source-url", sourceArg}, io.Discard)
	if err != nil || cfg.Listen != "[::1]:8888" {
		t.Fatalf("listen override: config = %+v, err = %v", cfg, err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing source", nil},
		{"public bind", []string{"-listen", "0.0.0.0:8080", "-source-url", sourceArg}},
		{"invalid source", []string{"-source-url", "http://source.example.invalid"}},
		{"unknown flag", []string{"-unsupported"}},
		{"missing value", []string{"-source-url"}},
		{"positional", []string{"-source-url", sourceArg, "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parse(service.Submission, tc.args, io.Discard); err == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
}

func TestHelp(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	_, err := parse(service.Submission, []string{"-help"}, &output)
	if !errors.Is(err, flag.ErrHelp) || !strings.Contains(output.String(), "-source-url") {
		t.Fatal("help did not describe required source URL")
	}
}

func TestContainerNetworkFlag(t *testing.T) {
	t.Parallel()
	for _, role := range []service.Role{service.CA, service.Issuer, service.Submission} {
		for _, enabled := range []string{"true", "false"} {
			cfg, err := parse(role, []string{"-source-url", sourceArg, "-listen", "0.0.0.0:8080", "-container-network=" + enabled}, io.Discard)
			if enabled == "true" {
				if err != nil || !cfg.ContainerNetwork || cfg.Listen != "0.0.0.0:8080" {
					t.Fatalf("container opt-in rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("explicit false permitted wildcard")
			}
		}
	}
}

func TestDevelopmentStyleGuideFlag(t *testing.T) {
	t.Parallel()
	for _, role := range []service.Role{service.CA, service.Issuer, service.Submission} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			cfg, err := parse(role, []string{"-source-url", sourceArg, "-dev-styleguide"}, io.Discard)
			if role == service.Submission {
				if err != nil || !cfg.DevStyleGuide {
					t.Fatalf("style-guide flag not accepted: %v", err)
				}
			} else if err == nil {
				t.Fatal("identity command accepted a submission-only flag")
			}
		})
	}
	cfg, err := parse(service.Submission, []string{"-source-url", sourceArg, "-dev-styleguide=false"}, io.Discard)
	if err != nil || cfg.DevStyleGuide {
		t.Fatal("explicit false enabled the style guide")
	}
}

func TestRunRejectsConfigurationBeforeBinding(t *testing.T) {
	t.Parallel()
	if err := run(t.Context(), service.Submission, nil, io.Discard); err == nil {
		t.Fatal("started without required configuration")
	}
}
