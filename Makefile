# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
.DEFAULT_GOAL := help
MDBOOK ?= .cache/mdbook/bin/mdbook
GO ?= go
export GOTOOLCHAIN := go1.27.3
FUZZTIME ?= 15s

.PHONY: help setup attribution commitlint policy-test reuse docs-setup docs-links docs-lint docs-external docs-build workflow-lint labels check build test lint fuzz vuln web-lint wasm wasm-test member-wasm member-wasm-test member-browser-test container-secrets container-config up down smoke container-test migrate-identity migrate-submission db-migration-test db-account-test db-member-backup-test db-submission-record-test
help:
	@echo 'setup attribution commitlint policy-test reuse docs-setup docs-links docs-lint docs-external docs-build workflow-lint labels check'
	@echo 'build test lint fuzz vuln web-lint'
	@echo 'wasm wasm-test'
	@echo 'member-wasm member-wasm-test'
	@echo 'member-browser-test (requires MEMBER_BROWSER; see docs/testing.md)'
	@echo 'container-secrets container-config up down smoke container-test (see docs/deployment.md)'
	@echo 'migrate-identity migrate-submission db-migration-test db-account-test db-member-backup-test (local PostgreSQL only)'
	@echo 'db-submission-record-test (atomic ciphertext persistence; local PostgreSQL only)'
	@echo 'browser-build browser-test (opt-in connected browser MVP; see docs/deployment.md and docs/testing.md)'
	@echo 'browser-unit-test (reviewer record isolation and cancellation checks)'

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

.PHONY: browser-build browser-test browser-profile-test browser-unit-test
browser-unit-test:
	node --test scripts/review_records_test.mjs scripts/review_worker_test.mjs

browser-build: build member-wasm
	python3 scripts/build_wasm.py --go '$(GO)' --component review
	python3 scripts/browser_notices.py

browser-test: browser-build
	$(GO) test -race -count=1 -tags=browsermvp ./internal/browserjourney

browser-profile-test:
	$(GO) test -race -count=1 ./internal/reviewprofile
	$(GO) test -count=1 -run='^TestVectors$$' github.com/cloudflare/circl/blindsign/blindrsa
	$(GO) test -count=1 -run='^TestVectors$$' crypto/hpke

wasm:
	python3 scripts/build_wasm.py --go '$(GO)'

wasm-test: wasm
	$(GO) test -race -count=1 -tags=wasmintegration -run='^TestClientNativeWASMCompatibility$$' ./internal/clientwasm
	GOOS=js GOARCH=wasm PATH="$$($(GO) env GOROOT)/lib/wasm:$$PATH" $(GO) test ./internal/clientwasm

member-wasm:
	python3 scripts/build_wasm.py --go '$(GO)' --component member

member-wasm-test: member-wasm
	node --test scripts/member_worker_test.mjs
	node --test scripts/member_forms_test.mjs
	$(GO) test -race -count=1 -tags=wasmintegration ./internal/memberwasm

member-browser-test: member-wasm
	$(GO) test -race -count=1 -tags=browserintegration -run='^TestMemberNativeBrowserCompatibility$$' ./internal/memberwasm

container-secrets:
	python3 scripts/containers.py secrets

container-config:
	python3 scripts/containers.py config

up:
	python3 scripts/containers.py up

down:
	python3 scripts/containers.py down

smoke:
	python3 scripts/containers.py smoke

container-test:
	python3 scripts/containers.py test

migrate-identity:
	python3 scripts/containers.py migrate-identity

migrate-submission:
	python3 scripts/containers.py migrate-submission

db-migration-test:
	python3 scripts/containers.py migration-test

db-account-test:
	python3 scripts/containers.py account-test

db-member-backup-test:
	python3 scripts/containers.py member-backup-test

db-submission-record-test:
	python3 scripts/containers.py submission-record-test

test:
	mkdir -p coverage
	$(GO) test -race -coverprofile=coverage/out ./...
	$(GO) tool cover -func=coverage/out

lint:
	$(GO) vet ./...
	GOOS=js GOARCH=wasm $(GO) vet ./cmd/wasm ./internal/clientwasm ./cmd/memberwasm ./internal/memberwasm ./cmd/reviewwasm ./internal/reviewwasm
	$(GO) run mvdan.cc/gofumpt@v0.12.0 -d cmd internal migrations web
	test -z "$$($(GO) run mvdan.cc/gofumpt@v0.12.0 -l cmd internal migrations web)"
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run
	$(GO) mod tidy -diff
	$(GO) mod verify

fuzz:
	$(GO) test ./internal/reviewprofile -run='^$$' -fuzz='^FuzzProfileRejection$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/browserhttp -run='^$$' -fuzz='^FuzzBrowserJSONAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/submission/records -run='^$$' -fuzz='^FuzzSubmissionAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/identity/accounts -run='^$$' -fuzz='^FuzzSessionDisableAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/identity/accounts -run='^$$' -fuzz='^FuzzAllSessionsAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/identity/accounts -run='^$$' -fuzz='^FuzzSelectedSessionAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/identity/accounts -run='^$$' -fuzz='^FuzzAccountSessionAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/identity/memberbackup -run='^$$' -fuzz='^FuzzMemberBackupSessionAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/identity/memberbackup -run='^$$' -fuzz='^FuzzMemberBackupAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/identity/accounts -run='^$$' -fuzz='^FuzzAccountToken$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/dbmigrate -run='^$$' -fuzz='^FuzzMigrationAdmission$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/service -run='^$$' -fuzz='^FuzzConfig$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/service -run='^$$' -fuzz='^FuzzContainerListen$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/web -run='^$$' -fuzz='^FuzzLookup$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/keystore -run='^$$' -fuzz='^FuzzBackup$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/memberkey -run='^$$' -fuzz='^FuzzMemberKeyPayload$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/membercsr -run='^$$' -fuzz='^FuzzMemberCSR$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/membersession -run='^$$' -fuzz='^FuzzMemberSessionUnlockInputs$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/membersession -run='^$$' -fuzz='^FuzzMemberSessionConfirmation$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/memberwasm -run='^$$' -fuzz='^FuzzMemberWASMSizes$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/memberwasm -run='^$$' -fuzz='^FuzzMemberBrowserManifest$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/clientwasm -run='^$$' -fuzz='^FuzzWASMRequest$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/clientwasm -run='^$$' -fuzz='^FuzzWASMExpectedKey$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/client/reviewerkey -run='^$$' -fuzz='^FuzzReviewerKeyPayload$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/clientcli -run='^$$' -fuzz='^FuzzClientArguments$$' -fuzztime=$(FUZZTIME) -parallel=2
	$(GO) test ./internal/clientcli -run='^$$' -fuzz='^FuzzClientPublicKeyLine$$' -fuzztime=$(FUZZTIME) -parallel=2
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

check: policy-test attribution commitlint reuse docs-lint docs-links build test lint fuzz vuln web-lint wasm-test member-wasm-test browser-unit-test
