#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import {
  mutableActionReferences,
  mutablePackageExecutions,
  persistingCheckoutReferences,
  unsafeGitPushes,
  verifyRepository,
} from "./verify_workflow_pins.mjs";

const checkoutSha = "11d5960a326750d5838078e36cf38b85af677262";

test("accepts immutable actions, local actions, and non-persisting checkout", () => {
  const source = `steps:
  - uses: actions/checkout@${checkoutSha}
    with:
      persist-credentials: false
  - uses: ./.github/actions/local
  - uses: docker://alpine@sha256:${"a".repeat(64)}
`;
  assert.deepEqual(mutableActionReferences(source), []);
  assert.deepEqual(persistingCheckoutReferences(source), []);
});

test("rejects mutable action, reusable workflow, and container references", () => {
  assert.equal(mutableActionReferences("uses: actions/checkout@v4\n").length, 1);
  assert.equal(
    mutableActionReferences(
      "uses: cognitum-one/.github/.github/workflows/security-scan.yml@main\n",
    ).length,
    1,
  );
  assert.equal(mutableActionReferences("uses: docker://alpine:latest\n").length, 1);
});

test("rejects checkout credentials unless an explicit bounded push exemption exists", () => {
  assert.equal(
    persistingCheckoutReferences(`steps:
  - uses: actions/checkout@${checkoutSha}
`).length,
    1,
  );
  assert.deepEqual(
    persistingCheckoutReferences(`jobs:
  release:
    steps:
      - name: Push bounded release tag
        # workflow-pin-policy: allow-persist-credentials release-tag
        uses: actions/checkout@${checkoutSha}
        with:
          token: \${{ secrets.RELEASE_PUSH_TOKEN }}
          persist-credentials: true
      - name: Push
        run: git push origin release-tag
`),
    [],
  );
});

test("rejects persistent or credential-bearing Git push paths", () => {
  assert.equal(unsafeGitPushes("run: gh auth setup-git\n").length, 1);
  assert.equal(
    unsafeGitPushes("run: git push https://token:secret@github.com/org/repo.git\n").length,
    1,
  );
});

test("accepts command-scoped GitHub credential helper", () => {
  const source = `jobs:
  write:
    steps:
      - name: Push
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          git \\
            -c credential.helper= \\
            -c "credential.https://github.com.helper=!gh auth git-credential" \\
            push origin branch
`;
  assert.deepEqual(unsafeGitPushes(source), []);
});

test("rejects registry executions with mutable or absent versions", () => {
  assert.equal(
    mutablePackageExecutions("run: npx --yes firebase-tools@latest emulators:exec\n").length,
    1,
  );
  assert.equal(mutablePackageExecutions("run: pnpm dlx cowsay\n").length, 1);
  assert.deepEqual(
    mutablePackageExecutions("run: npx --yes firebase-tools@15.27.0 emulators:exec\n"),
    [],
  );
  assert.deepEqual(mutablePackageExecutions("run: npx vitest run\n"), []);
});

test("line continuations and comments cannot hide mutable package execution", () => {
  const source = `run: |
  # Windows path C:\\Users\\dev\\ \\
  npx --yes \\
    package@latest
`;
  assert.equal(mutablePackageExecutions(source).length, 1);
});

test("controlled repository harness passes clean and rejects a mutable fixture", async () => {
  const root = await mkdtemp(join(tmpdir(), "workflow-pin-policy-"));
  try {
    const workflows = join(root, ".github", "workflows");
    await mkdir(workflows, { recursive: true });
    const candidate = join(workflows, "security.yml");
    await writeFile(
      candidate,
      `jobs:\n  scan:\n    steps:\n      - uses: actions/checkout@${checkoutSha}\n        with:\n          persist-credentials: false\n`,
    );
    await verifyRepository(root);
    await writeFile(candidate, "jobs:\n  scan:\n    steps:\n      - uses: actions/checkout@v4\n");
    await assert.rejects(verifyRepository(root), /mutable GitHub Actions reference/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
