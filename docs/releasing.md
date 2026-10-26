<!-- SPDX-FileCopyrightText: 2026 Anonce Contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Release and verification contract

Audience: release maintainers and users verifying future downloads.

Status: no release, tag, binary, container image, WASM artifact, signature, or SBOM
has been published. Commands below define intended verification, not currently
available release evidence.

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
  and SLSA-format provenance with source/toolchain/build inputs.
- Sign artifacts and images with keyless Cosign through a narrowly scoped OIDC job.
- Publish the matching curated changelog section without rewriting CHANGELOG.md.
- Independently verify the published assets before announcing availability.

Provenance attestations must describe the real builder and inputs. Do not claim a
SLSA assurance level without satisfying and documenting that level's requirements.

## User verification

Obtain the expected repository, tag, signing workflow identity, and trust-root
material through a trusted channel. Download the checksum file, artifacts, signature
bundle, provenance, and SBOM from the same reviewed release. Verify signatures
before trusting checksums.

The planned artifact naming permits verification along these lines:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/mandipnotroot/anonce/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check checksums.txt
```

For an image, verify its digest with the same exact workflow identity using
`cosign verify`, then verify attached provenance and SBOM attestations against the
expected source revision and subject digest. Do not use a broad identity regex that
accepts arbitrary forks or workflow paths.

For WASM, verify the signed manifest and bundle hash using the independent CLI or
another trusted local verifier. Compare the hash with the independently trusted log
checkpoint entry, not just a value shown by the serving web page. Rebuild with the
recorded toolchain to compare hashes where reproducibility is claimed.

An SBOM is an inventory, not proof of safety. Review component licenses and current
advisories. A valid signature proves an authorized publication identity, not absence
of vulnerabilities or correctness of the protocol.

## Withdrawal and compromise

Mark withdrawn versions `[YANKED]`, retain their documented history, stop recommending
affected artifacts, and publish actionable security guidance. Do not replace release
bytes under an existing checksum/tag. Compromised signing or source credentials
require trust-root recovery and an explicit incident notice.
