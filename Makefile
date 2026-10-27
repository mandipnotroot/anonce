# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
.DEFAULT_GOAL := help
MDBOOK ?= .cache/mdbook/bin/mdbook
GO ?= go
export GOTOOLCHAIN := go1.27.3
FUZZTIME ?= 15s

.PHONY: help setup attribution commitlint policy-test reuse docs-setup docs-links docs-lint docs-external docs-build workflow-lint labels check build test lint fuzz vuln web-lint
help:
	@echo 'setup attribution commitlint policy-test reuse docs-setup docs-links docs-lint docs-external docs-build workflow-lint labels check'
	@echo 'build test lint fuzz vuln web-lint'

setup:
	git config --local core.hooksPath .githooks
	chmod +x .githooks/*

attribution:
	python3 scripts/policy.py --index --history

commitlint:
	python3 scripts/commit_lint.py

policy-test:
	python3 -m unittest discover -s scripts -p 'test_*.py' -v

reuse:
	reuse lint

docs-links:
	python3 scripts/docs_check.py --links

docs-lint:
	python3 scripts/docs_check.py --lint

docs-external:
	python3 scripts/docs_check.py --external

docs-setup:
	python3 scripts/install_mdbook.py

docs-build: docs-lint docs-links
	python3 scripts/build_docs.py --command '$(MDBOOK)'

workflow-lint:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12

labels:
	python3 scripts/sync_labels.py

build:
	$(GO) build -trimpath -o bin/ ./cmd/...

test:
	mkdir -p coverage
	$(GO) test -race -coverprofile=coverage/out ./...
	$(GO) tool cover -func=coverage/out

lint:
	$(GO) vet ./...
	$(GO) run mvdan.cc/gofumpt@v0.12.0 -d cmd internal web
	test -z "$$($(GO) run mvdan.cc/gofumpt@v0.12.0 -l cmd internal web)"
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run
	$(GO) mod tidy -diff
	$(GO) mod verify

fuzz:
	$(GO) test ./internal/service -run='^$$' -fuzz='^FuzzConfig$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/web -run='^$$' -fuzz='^FuzzLookup$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/keystore -run='^$$' -fuzz='^FuzzBackup$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/memberkey -run='^$$' -fuzz='^FuzzMemberKeyPayload$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/reviewerkey -run='^$$' -fuzz='^FuzzReviewerKeyPayload$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/clientcli -run='^$$' -fuzz='^FuzzClientArguments$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/clientcli -run='^$$' -fuzz='^FuzzClientPassword$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/clientcli -run='^$$' -fuzz='^FuzzClientRewrapPasswords$$' -fuzztime=$(FUZZTIME) -parallel=2

web-lint: build
	python3 scripts/web_check.py

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 ./...
	$(GO) mod verify
	$(GO) list -m all
	$(GO) run github.com/zricethezav/gitleaks/v8@v8.30.1 dir --redact --no-banner .

check: policy-test attribution commitlint reuse docs-lint docs-links build test lint fuzz vuln web-lint
