# Org security scanning

Self-hosted secret + dependency scanning for all `cognitum-one` repos. Runs on
our own CI — **no GitHub paid Advanced Security / auto-protection required.**

## Layers

1. **Pre-commit** (`templates/.pre-commit-config.yaml`) — gitleaks + private-key
   detection before a commit is created. Cheapest place to stop a leak.
2. **CI** (`.github/workflows/security-scan.yml`) — reusable workflow: gitleaks
   over full history + OSV-Scanner over every lockfile. Runs on push, PR, and a
   weekly Monday sweep.
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

`gitleaks.toml` extends the default ruleset with a hand-verified allowlist of
known test fixtures (benchmark constants, doc placeholders, test-only keys).
Adding an entry is a security decision — verify the match is genuinely not a
secret before allowlisting it.

## metaharness / qe-harness integration (planned)

The same gitleaks + OSV steps wrap as a `qe-harness` security template, emitting
an **Ed25519-signed witness manifest** per scan (tamper-evident "repo X clean at
SHA Y"). `metaharness` mints one worker-harness per repo to fan the scan across
the whole org in parallel and aggregate into a single signed report.
