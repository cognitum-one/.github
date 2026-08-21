# Org security scanning

Self-hosted secret + dependency scanning for all `cognitum-one` repos. Runs on
our own CI — **no GitHub paid Advanced Security / auto-protection required.**

## Where it runs, and why that changed (2026-08-20)

All three jobs are `runs-on: [self-hosted, gcp-bypass]`. They were
`ubuntu-latest` / `ubuntu-24.04` until the org-wide Actions billing stop, under
which **no hosted job can start at all** — every `security` run in the
organization failed in about four seconds without scanning anything. That is
worth stating precisely because it does not look like an outage: the check goes
red instantly and reads like a finding, and a repository whose scan never ran is
indistinguishable from one that passed unless you look at the annotation.

Two consequences that are easy to get wrong:

- **Consumers pin this workflow by full commit sha**, so a repository stays on
  whatever version it pinned. Moving the jobs here does not move them for a
  caller until that caller re-pins. A green-looking repo may simply never have
  run.
- **`concurrency` is not optional for this workflow.** Each run builds a
  container image for the static-UI receipt, so without a group four merges
  inside two minutes produce four simultaneous docker builds. Measured on
  website: 13 of 13 runners busy and production publishes queued behind them for
  about an hour. Callers should set

  ```yaml
  concurrency:
    group: security-${{ github.ref }}
    cancel-in-progress: false
  ```

  `cancel-in-progress: false` is load-bearing. These scans are **required status
  checks**, and required checks bind per-commit: cancelling a superseded run
  leaves that commit permanently without a passing scan, which is exactly the
  state that blocks a back-merge to `rc`.

## `security/static-ui-runtime-profiles.json` is a FIXTURE, not the policy

It is still here and still hash-pinned, but since 2026-08-20 **its digests gate
nothing.** Enforcement reads `.github/static-ui-profile.json` from the candidate
repository. This copy exists only because the organization self-test suite loads
it by default — 2 of its 39 tests fail without it.

Do not advance a digest here expecting it to affect a scan, and do not read it
to learn what a repository currently pins; read that repository's own file. The
name is misleading and should be changed to say `-fixture`. That rename is not
free — it touches `DEFAULT_POLICY`, `osv_gate.py`, three test files, the
`POLICY_ARTIFACTS` and `EXPECTED_ORG_POLICY` tables, and the `curl` plus sha
pins in three workflows, and every consumer must then re-pin — so it is
deliberately left as a named follow-up rather than done quietly.

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
- downloads the official Buildx `v0.33.0` Linux AMD64 release asset into
  runner-temporary storage, verifies the independently recomputed SHA-256
  `9426a15411f35f635afef3f5d3bae53155c3e30d26dee430cc968e13d34be49f`
  before making or executing a plugin, installs it only under an initially
  empty job-scoped `DOCKER_CONFIG`, and asserts both the direct plugin and
  Docker CLI report revision
  `f7897eba028583e0071642db3c011e860444f8cf`;
- pins the official `moby/buildkit:v0.30.0` OCI index by immutable digest,
  requires its `linux/amd64` platform manifest through the
  `docker-container` driver, isolates both the daemon container and OCI worker
  on bridge networks, replaces the Buildx action's insecure-entitlement
  defaults with the safe `--oci-worker-net=bridge` daemon flag, and forbids
  the deprecated `docker build` install alias;
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
- downloads the static-UI receipt script, trusted builder, and their
  adversarial tests from the same immutable policy commit, verifies every
  digest, and runs each test file directly. The SCRIPT is organization-owned;
  the PROFILE is not — since 2026-08-20 each candidate owns
  `.github/static-ui-profile.json` in its own repository, so a repository
  chooses *what* it declares but never *how* the declaration is enforced;
- for the exact `cognitum-one/website` and `cognitum-one/management` profiles,
  exports a committed-only context, performs a no-cache `linux/amd64` build,
  inventories the resulting root filesystem, and supplies the receipt,
  inventory, independently generated nonce, image name, image config digest,
  and complete GitHub replay tuple to the OSV exception gate;
- treats a missing, invalid, or failed machine-readable OSV result as a failed
  security gate;
- passes a repository that has no dependency manifests at all. `osv-scanner`
  exits `128` with `No package sources found` in that case, which is the correct
  answer for a documentation repository rather than a scan failure. The wrapper
  accepts `128` **only** when both the human-readable and machine-readable
  invocations return it *and* no report file was produced; if a report exists the
  two signals contradict each other and the gate fails closed. Every other
  non-zero status — `127`, `129`, a negative code, or a missing one — still fails,
  so a general scanner error cannot be mistaken for an empty repository.

Version inputs are intentionally unsupported: changing a scanner requires a
reviewed workflow commit that updates both its version and digest. The
full-history job is informational with respect to findings, but tool download,
integrity, and parse failures still fail that job rather than manufacturing a
clean result. Every fixable High/Critical OSV finding blocks, including a
finding whose candidate-controlled lock metadata labels it development-only.
Fix or remove such dependencies rather than weakening the shared scanner. The
gate validates every affected range before evaluating severity. A severityless
advisory whose ranges contain no fixed version is informational under this
specific High/Critical-with-fix policy; it is not an advisory allowlist or an
invented CVSS score. Any advisory with a fixed version still requires a valid,
finite OSV severity from 0.0 through 10.0 and fails closed when that severity is
missing or invalid. A non-empty malformed severity remains a malformed report
even when the advisory has no fix.

The SHA-pinned `docker/setup-buildx-action` commit
`37fe631027851001ddb9b187196cc803df7f5f0e` is deliberately given no
`version` or `cache-binary` input. Its packaged
`@docker/actions-toolkit` 0.95.0 resolves release information from
`buildx-releases.json` on the toolkit's mutable `main` branch and downloads
GitHub release assets without checking a release checksum. A
`version: v0.33.0` input would therefore execute downloaded bytes before this
policy could verify them. The workflow instead installs the hash-verified
client first; the action detects that exact job-scoped plugin and skips its
downloader. GitHub release hosting remains an availability and asset mutability
dependency, but replacement bytes cannot execute unless they still match the
locally pinned SHA-256. The checksum was independently recomputed from the
reviewed Linux AMD64 asset; it is not treated as immutable metadata supplied by
the same release endpoint.

Buildx container drivers may independently append the daemon compatibility
flag `--allow-insecure-entitlement=network.host` even after the setup action's
two insecure defaults have been replaced. That daemon capability is not a
client grant: every trusted build uses the exact organization command without
`--allow`, and the static verifier rejects workflow-authored
`--allow network.host`, `--allow security.insecure`, host-network selections,
or daemon insecure-entitlement flags. The daemon container uses Docker's
bridge network and the OCI worker uses BuildKit's bridge network. The residual
daemon-level compatibility flag remains upstream behavior; any future client
entitlement or host-network requirement requires a new reviewed policy change.

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
- the correction expires at the start of `2026-11-15` UTC.

Wrong repositories, paths, versions, dependency ranges, nested copies,
advisory IDs, RSC surfaces, symlinks, oversized/unreadable source, duplicate
JSON keys, malformed report data, missing/invalid severity on a fixable
finding, or an expired correction remain blocking. The organization
security/release maintainers own the exception. Before expiry they must recheck
the upstream maintainer advisory and OSV data, then either remove the
correction or land a newly reviewed policy commit, expiry, hashes, and
adversarial tests. Expiry itself blocks; it never silently extends.

## Static-UI runtime evidence

The Router correction is not a package-version allowlist. It is usable only
when the same `deps` job proves that the reviewed repository produces the
reviewed runtime. The evidence is generated under `$RUNNER_TEMP`, outside the
candidate checkout, and is replay-bound to repository/owner numeric IDs,
visibility, source SHA, workflow SHA/ref, run ID/attempt, job, image config,
packaging hashes, and a fresh external 256-bit nonce.

Runtime evidence is optional for repositories outside the two approved static
UI profiles. Only the five `OSV_RUNTIME_*` receipt, inventory, nonce, image
name, and image ID fields activate receipt verification; the `GITHUB_*` run
tuple that Actions supplies to every repository does not. Once any runtime
evidence field is non-empty, all five evidence fields and the complete GitHub
run tuple are mandatory and verification fails closed on every omission.

Website proof additionally checks out the profile-pinned private Beacon commit
outside the candidate using the narrowly scoped
`STATIC_UI_BEACON_READ_TOKEN`. The caller maps only that secret:

```yaml
permissions:
  contents: read

jobs:
  security:
    permissions:
      contents: read
    uses: cognitum-one/.github/.github/workflows/security-scan.yml@<FULL_ORG_SHA>
    secrets:
      static_ui_beacon_read_token: ${{ secrets.STATIC_UI_BEACON_READ_TOKEN }}
```

Management pre-merge builds use an exact organization-profiled public browser
configuration fixture. The receipt labels it `premerge-fixture`,
`public-nonrelease`, and `organization-profile`; the verifier recomputes its
variable and content digests. It never authenticates to GCP and can never be
replayed as release evidence. Release mode rejects that fixture and reads every
profiled Secret Manager value at the committed numeric version using the
dedicated staging builder identity. Missing secrets or identity bindings fail
closed. Organization policy
`16eb59995aa7378380c9b471ecd164cef42f8a87` additionally validates each
release value against its variable-specific canonical alphabet (API key,
reCAPTCHA key, app ID, DNS hostname, numeric sender ID, or Firebase project
ID), while pre-merge values must match the narrower
`premerge-fixture-[a-z0-9.-]+` grammar. This excludes dotenv delimiters and
comment syntax such as `#`, so the bytes hashed in the receipt are exactly the
bytes consumed by Vite.

## Trusted staging image and attestation

`.github/workflows/static-ui-release.yml` is the organization-owned release
builder for the two approved profiles. A caller must pin it by the final full
organization commit, grant only `contents: read`, `id-token: write`,
and `attestations: write`, and map the exact staging WIF, builder service
account, and (for website) Beacon read token. Artifact Registry authentication
comes only from that dedicated GCP WIF identity; the workflow has no GitHub
Packages write permission. Both the calling workflow and GCP WIF policy must
identify the reusable workflow by its exact `job_workflow_ref`. The workflow
rejects any identity other than
`website-frontend-deploy-stg@cognitum-20260110.iam.gserviceaccount.com` or
`management-ui-deploy-stg@cognitum-20260110.iam.gserviceaccount.com` with its
matching environment-isolated provider.

The workflow's `STATIC_UI_WORKFLOW_COMMIT` is a content commit used only to
fetch and hash-check `static_ui_release_gate.py` and its tests without a
self-referential Git commit. The caller pins the subsequent pin-only commit.
The OIDC `job_workflow_sha`, `job_workflow_ref`, attestation signer digest, and
verification flags bind that actually executed final reusable-workflow commit;
they are not derived from the content commit.

The workflow:

1. requires current `refs/heads/main`, `workflow_sha == source_sha`, the
   approved caller workflow/event/job, and the profile's exact Artifact
   Registry repository;
2. runs every immutable policy test directly, creates a fresh nonce outside
   the output, builds with the organization grammar, and pushes only
   `<approved-repository>:<source-sha>`;
3. pulls and inventories `repository@sha256:digest` again, requiring the same
   image config ID and byte-for-byte semantic inventory;
4. signs the complete custom receipt with pinned `actions/attest` using
   predicate type
   `https://cognitum.one/attestations/static-ui-runtime/v1`;
5. verifies the exact bundle with `gh attestation verify`, enforcing the
   reusable signer workflow and signer digest, caller source digest/ref,
   subject digest, predicate type, GitHub-hosted runner, and trusted timestamp;
6. compares the verified statement's exact subject and predicate to the
   independently revalidated release receipt and uploads non-secret evidence.

This reusable workflow builds, pushes, attests, and verifies. It contains no
Cloud Run deploy, traffic, invoker, IAM, billing, Secret Manager mutation, or
production authority. A caller must make any later staging deploy/promotion job
depend on the successful reusable job and must consume its exact
`image_name@image_digest` output. Production remains separately authorized and
is not enabled by this contract.

## Cloud Run revision verification

`.github/workflows/static-ui-revision.yml` is a read-only post-deployment gate.
It authenticates a dedicated verifier and runs only `gcloud run revisions
describe` and `gcloud run services describe`. It requires a pre-deployment
expected environment contract plus the canonical spec digest captured from the
Ready no-traffic candidate before promotion, then verifies:

- the organization-owned staging service, runtime service account, one
  container, image digest, default image command, and HTTP port 8080;
- the exact configured environment set, with literal values represented only
  by SHA-256 digests and secret references bound to positive numeric versions;
- no volumes, volume mounts, startup dependencies, or forbidden runtime
  environment;
- unique `Ready=True` on both Revision and Service, exact
  `status.imageDigest`, latest-created/latest-ready revision, approved ingress,
  and a single untagged 100% revision traffic allocation.

Deployment commands are caller-owned and must explicitly clear inherited state
with `--clear-volumes`, `--clear-volume-mounts`, and the reviewed secret/env
grammar before this verifier runs. Until a real staging revision passes this
gate, no production promotion is implied or authorized.

The read-only target identities are
`website-release-verify-stg@cognitum-20260110.iam.gserviceaccount.com` and
`management-ui-release-verify-stg@cognitum-20260110.iam.gserviceaccount.com`.
They require only Artifact Registry metadata read plus Cloud Run Service and
Revision `get`; they receive no deploy, traffic, actAs, IAM, Secret Manager, or
production role. Their WIF bindings and secrets are intentionally external
provisioning prerequisites, not changes performed by this repository.

## Workflow mutation boundary

`security/verify_static_ui_workflows.py` statically enforces the evidence path,
test execution, immutable action/policy/BuildKit pins, the hash-before-execution
Buildx client install and exact Docker plugin resolution, safe BuildKit daemon
flags, absence of setup-action binary overrides and the deprecated install
alias, nonce location, complete OSV environment tuple, release attestation
flags, exact-digest inventory, read-only revision commands, and prohibited
cloud mutations.
`security/test_verify_static_ui_workflows.py` removes or weakens those controls
one at a time and requires every mutation to fail. The
`static-ui-policy-selftest` workflow runs all policy tests, the strict static
verifier, actionlint, and ShellCheck. The bootstrap zero self-pin is accepted
only by an explicit local review flag; the final branch check rejects it.

## metaharness / qe-harness integration (planned)

The same gitleaks + OSV steps wrap as a `qe-harness` security template, emitting
an **Ed25519-signed witness manifest** per scan (tamper-evident "repo X clean at
SHA Y"). `metaharness` mints one worker-harness per repo to fan the scan across
the whole org in parallel and aggregate into a single signed report.
