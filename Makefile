# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
.DEFAULT_GOAL := help
MDBOOK ?= .cache/mdbook/bin/mdbook

.PHONY: help setup attribution commitlint policy-test reuse docs-setup docs-links docs-lint docs-external docs-build workflow-lint labels check
help:
	@echo 'setup attribution commitlint policy-test reuse docs-setup docs-links docs-lint docs-external docs-build workflow-lint labels check'

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
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12

labels:
	python3 scripts/sync_labels.py

check: policy-test attribution commitlint reuse docs-lint docs-links
