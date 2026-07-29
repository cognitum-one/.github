# Org security scanning

Self-hosted secret + dependency scanning for all `cognitum-one` repos. Runs on
our own CI — **no GitHub paid Advanced Security / auto-protection required.**

## Layers

1. **Pre-commit** (`templates/.pre-commit-config.yaml`) — gitleaks + private-key
   detection before a commit is created. Cheapest place to stop a leak.
2. **CI** (`.github/workflows/security-scan.yml`) — reusable workflow:
   blocking gitleaks over current files, blocking OSV policy over every
   discovered lockfile, plus an informational full-history secret audit on
   scheduled/manual runs.
3. **Org sweep** — the weekly `schedule:` trigger gives every repo a recurring
   drift check; results feed the weekly QE report.

## Rollout (per repo)

```bash
# CI: add the caller workflow
mkdir -p .github/workflows
curl -fsSL https://raw.githubusercontent.com/cognitum-one/.github/main/workflow-templates/security.yml \
  -o .github/workflows/security.yml

# Local: install pre-commit
curl -fsSL https://raw.githubusercontent.com/cognitum-one/.github/main/templates/.pre-commit-config.yaml \
  -o .pre-commit-config.yaml
pre-commit install
```

Or add the CI workflow from the GitHub UI: **Actions → New workflow →
"Security scan (cognitum-one)"**.

## Allowlist

The organization `gitleaks.toml` extends the default ruleset with a
hand-verified allowlist of known test fixtures (benchmark constants, doc
placeholders, test-only keys). The reusable CI workflow always uses that
independently reviewed, commit-pinned, hash-verified policy. It intentionally
ignores a caller repository's candidate-controlled `.gitleaks.toml`, because a
pull request must not be able to relax the gate that reviews that same pull
request. Adding an organization entry is a security decision — verify the match
is genuinely not a secret before allowlisting it.

## Scanner supply chain and failure policy

The reusable workflow is immutable only when callers pin its full commit SHA.
It in turn:

- pins `actions/checkout` by full SHA;
- pins Gitleaks and OSV-Scanner to exact versions and verified release-asset
  SHA-256 digests;
- fetches the mandatory organization Gitleaks policy from an exact commit,
  verifies its SHA-256 digest, and ignores candidate-controlled replacements;
- fetches the mandatory OSV policy and its negative tests from an exact commit,
  verifies every SHA-256 digest, and executes the tests before evaluating the
  candidate's scanner report;
- runs OSV through the pinned organization wrapper with the pinned,
  ignore-free organization config, `--no-ignore`, and `--all-vulns`; a
  candidate `osv-scanner.toml`, `.gitignore`, lockfile `dev` flag, scanner
  binary, config, or report path cannot suppress or replace evidence;
- keeps scanner binaries, policies, and machine reports outside the untrusted
  checkout and rejects symlinks, unexpected process statuses, empty or
  malformed reports, and command-grammar drift;
- treats a missing, invalid, or failed machine-readable OSV result as a failed
  security gate.

Version inputs are intentionally unsupported: changing a scanner requires a
reviewed workflow commit that updates both its version and digest. The
full-history job is informational with respect to findings, but tool download,
integrity, and parse failures still fail that job rather than manufacturing a
clean result. Every fixable High/Critical OSV finding blocks, including a
finding whose candidate-controlled lock metadata labels it development-only.
Fix or remove such dependencies rather than weakening the shared scanner.

## Reviewed OSV database correction

The only scanner-database correction is the React Router advisory
`GHSA-qwww-vcr4-c8h2` at version `7.18.2`. The upstream maintainer advisory
identifies `7.18.2` as patched, while the current OSV range still reports it as
affected. The correction is intentionally narrower than a general allowlist:

- only `cognitum-one/website` at `package-lock.json` and
  `cognitum-one/management` at `management-ui/package-lock.json` are eligible;
- the lock root must declare `react-router-dom` exactly as `7.18.2`, and both
  resolved `react-router` and `react-router-dom` nodes must be exactly `7.18.2`;
- neither lock may contain a second router copy or any React Server Components
  package; the exact application manifest, scripts, shipped source tree, and
  Vite configuration must contain no RSC dependency, condition, entry point,
  or unstable API surface;
- only that advisory/package/version tuple is corrected;
- the correction expires at the start of `2026-08-15` UTC.

Wrong repositories, paths, versions, dependency ranges, nested copies,
advisory IDs, RSC surfaces, symlinks, oversized/unreadable source, duplicate
JSON keys, malformed severity/report data, or an expired correction remain
blocking. The organization security/release maintainers own the exception.
Before expiry they must recheck the upstream maintainer advisory and OSV data,
then either remove the correction or land a newly reviewed policy commit,
expiry, hashes, and adversarial tests. Expiry itself blocks; it never silently
extends.

## metaharness / qe-harness integration (planned)

The same gitleaks + OSV steps wrap as a `qe-harness` security template, emitting
an **Ed25519-signed witness manifest** per scan (tamper-evident "repo X clean at
SHA Y"). `metaharness` mints one worker-harness per repo to fan the scan across
the whole org in parallel and aggregate into a single signed report.
