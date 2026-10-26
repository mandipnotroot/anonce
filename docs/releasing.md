<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Release and verification contract

Audience: release maintainers and users verifying future downloads.

Status: no published releases, tags, binaries, images, WASM, signatures, or SBOMs.
Commands below are planned verification, not available evidence.

## Maintainer release checklist

- Confirm the exact source revision, human-reviewed history, and clean worktree.
- Pass every required check, including full-history and artifact wording inspection.
- Resolve compatibility impact under [versioning](versioning.md).
- Curate the dated changelog section, compare links, and release notes.
- Validate the tag matches both the changelog and built version.
- Build Linux/macOS/Windows binaries for supported architectures and browser WASM
  with pinned Go, `-trimpath`, controlled version inputs, and documented build settings.
- Repeat builds in clean environments and compare unsigned artifact hashes.
- Build Linux amd64/arm64 images from pinned base digests; scan before publication.
- Produce checksums, a dependency SBOM, exact corresponding source, WASM manifest,
  and [SLSA](https://slsa.dev/spec/)-format provenance with source/toolchain/build inputs.
- Sign artifacts and images with keyless Cosign through a narrowly scoped OIDC job.
- Publish the matching curated changelog section without rewriting CHANGELOG.md.
- Independently verify the published assets before announcing availability.

Provenance must name the real builder and inputs. Claim a SLSA level only after
satisfying and documenting its requirements.

## User verification

1. Obtain repository, tag, signing workflow identity, and trust roots through a trusted channel.
2. Download checksums, artifacts, signature bundle, provenance, and SBOM from one reviewed release.
3. Verify signatures before trusting checksums.

Planned artifact names:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/mandipnotroot/anonce/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check checksums.txt
```

- **Images:** `cosign verify` the digest with the exact workflow identity, then check
  provenance/SBOM attestations against expected source revision and subject digest.
  No broad identity regex accepting arbitrary forks or workflows.
- **WASM:** verify signed manifest/bundle hash with the independent CLI or trusted
  local verifier. Compare against an independently trusted log checkpoint, not only
  the serving page. Rebuild with the recorded toolchain where reproducibility is claimed.
- **Limits:** SBOMs are inventories, not safety proofs; review licenses/advisories.
  Signatures prove authorized publication identity, not security or protocol correctness.

## Withdrawal and compromise

- Mark withdrawals `[YANKED]`, retain history, stop recommending affected artifacts,
  and publish actionable security guidance.
- Never replace bytes under an existing checksum/tag.
- Compromised signing/source credentials require trust-root recovery and an incident notice.
