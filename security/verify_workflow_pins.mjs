#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const defaultRoot = resolve(process.cwd());
const yamlExtensions = new Set([".yml", ".yaml"]);

export function mutableActionReferences(source, path = "workflow.yml") {
  const findings = [];
  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)['"]?/u);
    if (!match) continue;
    const reference = match[1];
    if (reference.startsWith("./")) continue;
    if (reference.startsWith("docker://")) {
      if (!/@sha256:[0-9a-f]{64}$/u.test(reference)) {
        findings.push({ path, line: index + 1, reference });
      }
      continue;
    }
    const separator = reference.lastIndexOf("@");
    const revision = separator >= 0 ? reference.slice(separator + 1) : "";
    if (!/^[0-9a-f]{40}$/u.test(revision)) {
      findings.push({ path, line: index + 1, reference });
    }
  }
  return findings;
}

export function persistingCheckoutReferences(source, path = "workflow.yml") {
  const lines = source.split(/\r?\n/u);
  const findings = [];
  for (const [index, line] of lines.entries()) {
    if (
      !/^\s*(?:-\s*)?uses:\s*['"]?actions\/checkout@[0-9a-f]{40}['"]?(?:\s+#.*)?\s*$/u
        .test(line)
    ) {
      continue;
    }
    const usesIndent = line.match(/^\s*/u)[0].length;
    let start = index;
    let stepIndent = usesIndent;
    for (let cursor = index; cursor >= 0; cursor -= 1) {
      const step = lines[cursor].match(/^(\s*)-\s+(?:name|uses):/u);
      if (step && step[1].length <= usesIndent) {
        start = cursor;
        stepIndent = step[1].length;
        break;
      }
    }
    let end = lines.length;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const next = lines[cursor].match(/^(\s*)-\s+(?:name|uses):/u);
      if (next && next[1].length <= stepIndent) {
        end = cursor;
        break;
      }
    }
    const block = lines.slice(start, end).join("\n");
    if (/^\s*persist-credentials:\s*false\s*$/mu.test(block)) continue;

    const jobsIndex = lines.findIndex((candidate) => /^jobs:\s*(?:#.*)?$/u.test(candidate));
    let jobStart = jobsIndex;
    for (let cursor = index; cursor > jobsIndex; cursor -= 1) {
      if (/^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/u.test(lines[cursor])) {
        jobStart = cursor;
        break;
      }
    }
    let jobEnd = lines.length;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      if (/^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/u.test(lines[cursor])) {
        jobEnd = cursor;
        break;
      }
    }
    const jobBlock = lines.slice(jobStart, jobEnd).join("\n");
    const documentedPushExemption =
      /#\s*workflow-pin-policy:\s*allow-persist-credentials\s+\S/u.test(block) &&
      /^\s*persist-credentials:\s*true\s*$/mu.test(block) &&
      /^\s*token:\s*\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}\s*$/mu.test(block) &&
      /^\s*(?:run:\s*)?git\s+push(?:\s|$)/mu.test(jobBlock);
    if (!documentedPushExemption) {
      findings.push({
        path,
        line: index + 1,
        reference: "actions/checkout",
      });
    }
  }
  return findings;
}

/**
 * Mutable PACKAGE references executed inside `run:` blocks.
 *
 * `mutableActionReferences` above pins `uses:` — GitHub Actions. It never looked
 * at what a step actually runs, and on 2026-08-17 that blind spot was holding
 * exactly one live example: ci-guard.yml's Cogs suite invoked
 * `npx --yes firebase-tools@latest`, downloading and executing whatever that tag
 * resolved to on the day, inside the job that gates merges. The repo's whole
 * pinning discipline — 40-hex action SHAs, a `docker://` digest rule, a pinned
 * reusable-workflow caller — exists to stop precisely that, and this was simply
 * out of the checker's field of view.
 *
 * WHAT COUNTS AS A DOWNLOAD. `npx tsc` and `npx vitest` are NOT findings: with no
 * `--yes`, npx resolves the binary out of `node_modules/.bin`, so the version is
 * already fixed by `package-lock.json` — the lockfile is the pin. It is `--yes`
 * / `-y` that authorises npx to fetch from the registry, and that is the case
 * this checks. A first draft flagged every bare `npx <tool>` and produced NINE
 * false positives — five in ci-guard.yml (`tsc`, `vitest`) and four in
 * e2e-regression.yml (`playwright`) — before the rule was narrowed. That is the
 * dominant invocation pattern in this repo's own workflows, so shipping the
 * noisy rule into a merge gate would have taught readers to ignore the check.
 *
 * So: with `--yes`, require an exact version — `@latest`, `@next`, `@canary`,
 * `@beta`, `@alpha`, `@dev`, `@*` and a missing version are all findings. Without
 * `--yes`, only an explicitly mutable tag is a finding (`npx tsc@latest` really
 * does fetch). Local paths and `$VARIABLE` interpolations are ignored — the
 * former are in-repo and the latter resolve elsewhere, so flagging them is noise.
 */
export function mutablePackageExecutions(source, path = "workflow.yml") {
  const findings = [];
  const MUTABLE_TAG = /^(?:latest|next|canary|beta|alpha|dev|\*)$/u;

  // Fold shell line-continuations into one logical line, keeping the FIRST
  // physical line number so a finding still points somewhere useful. Without
  // this, `npx --yes \` on one line and `firebase-tools@latest` on the next slips
  // through entirely: the per-line regex sees a trailing backslash on one side
  // and a bare package name on the other, and matches neither.
  const physical = source.split(/\r?\n/u);
  const logical = [];
  const isComment = (text) => /^\s*#/u.test(text);
  for (let index = 0; index < physical.length; index += 1) {
    let text = physical[index];
    const start = index;
    // A `#` comment does NOT continue across a newline, even ending in `\` —
    // verified in bash: the following line is an ordinary statement and runs.
    // Comment-ness is therefore decided BEFORE folding and such a line is never
    // joined to its successor.
    //
    // Folding first was a real, demonstrated bypass, found by adversarial review
    // of this very commit: a comment ending in a backslash — a Windows path, a
    // regex, a typo, or one placed deliberately — glued itself to the command
    // below, the fold then began with `#`, and BOTH were skipped as commentary.
    // That silently hid whatever unpinned invocation followed, inside the job
    // this checker is being turned into a merge gate for.
    if (!isComment(text)) {
      while (
        /\\\s*$/u.test(text) &&
        index + 1 < physical.length &&
        !isComment(physical[index + 1])
      ) {
        index += 1;
        text = `${text.replace(/\\\s*$/u, " ")}${physical[index].trim()}`;
      }
    }
    logical.push({ text, line: start + 1 });
  }

  const record = (line, reference, installs) => {
    if (reference.startsWith(".") || reference.startsWith("/")) return;
    if (reference.includes("$")) return;
    // Scoped packages start with @; their version separator is the LAST @.
    const separator = reference.lastIndexOf("@");
    const version = separator > 0 ? reference.slice(separator + 1) : "";
    if (version === "") {
      if (installs) findings.push({ path, line, reference, reason: "no version pinned" });
      return;
    }
    if (MUTABLE_TAG.test(version)) {
      findings.push({ path, line, reference, reason: `mutable tag @${version}` });
    }
  };

  for (const { text, line } of logical) {
    // Whole-line comments explain these commands at length, including the
    // forbidden spellings. Matching them would fail on the prose that documents
    // why the call is pinned.
    if (/^\s*#/u.test(text)) continue;

    // `npx --package=<ref> -c '...'` names the package in the FLAG, so the
    // positional capture below never sees it. Scanned separately, and always
    // treated as installing — that is what --package means.
    for (const match of text.matchAll(/\bnpx\b[^\n]*?--package=([^\s'"|;&]+)/gu)) {
      record(line, match[1], true);
    }

    // `pnpm dlx` and `yarn dlx` are the same act under different names: both
    // always fetch, so there is no local-resolution case to exempt.
    for (const match of text.matchAll(
      /\b(?:pnpm|yarn)\s+dlx\s+([@\w][^\s'"|;&]*)/gu,
    )) {
      record(line, match[1], true);
    }

    for (const match of text.matchAll(
      /\bnpx\s+((?:(?:--yes|-y|--no-install|--package=\S+|--quiet|--silent)\s+)*)([@\w][^\s'"|;&]*)/gu,
    )) {
      const flags = match[1] ?? "";
      // Already handled above, and the positional token here is the COMMAND
      // (`-c`), not the package.
      if (/--package=/u.test(flags)) continue;
      record(line, match[2], /(?:^|\s)(?:--yes|-y)(?:\s|$)/u.test(flags));
    }
  }
  return findings;
}

export function unsafeGitPushes(source, path = "workflow.yml") {
  const lines = source.split(/\r?\n/u);
  const findings = [];
  for (const [index, line] of lines.entries()) {
    // Comments are deliberately NOT stripped here, unlike in
    // mutablePackageExecutions above. The selftest pins both cases: a
    // credential-bearing URL is a leaked credential whether or not someone
    // commented it out, and the rule is kept uniform rather than carving out the
    // setup-git line. Workflows that need to explain why they avoid the
    // persistent helper should describe it without writing the literal command.
    if (/\bgh\s+auth\s+setup-git\b/u.test(line)) {
      findings.push({ path, line: index + 1, reason: "persistent gh credential helper" });
    }
    if (/https:\/\/[^\s/@]+(?::[^\s/@]*)?@github\.com/u.test(line)) {
      findings.push({ path, line: index + 1, reason: "credential-bearing Git URL" });
    }

    const trimmed = line.trim();
    const pushCommand =
      /^push(?:\s|$)/u.test(trimmed) ||
      (/^git(?:\s|$)/u.test(trimmed) && /\bpush(?:\s|$)/u.test(trimmed));
    if (!pushCommand) continue;

    const lineIndent = line.match(/^\s*/u)[0].length;
    let start = index;
    let stepIndent = lineIndent;
    for (let cursor = index; cursor >= 0; cursor -= 1) {
      const step = lines[cursor].match(/^(\s*)-\s+(?:name|uses|run):/u);
      if (step && step[1].length < lineIndent) {
        start = cursor;
        stepIndent = step[1].length;
        break;
      }
    }
    let end = lines.length;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const next = lines[cursor].match(/^(\s*)-\s+(?:name|uses|run):/u);
      if (next && next[1].length <= stepIndent) {
        end = cursor;
        break;
      }
    }
    const block = lines.slice(start, end).join("\n");
    const normalized = block.replace(/\\\s*\n\s*/gu, " ").replace(/\s+/gu, " ");
    const scopedHelper =
      normalized.includes(
        'git -c credential.helper= -c "credential.https://github.com.helper=!gh auth git-credential" push',
      );
    const repositoryToken =
      /^\s*GH_TOKEN:\s*\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}\s*$/mu.test(block);
    const appToken = block.match(
      /^\s*GH_TOKEN:\s*\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.token\s*\}\}\s*$/mu,
    );
    const pinnedAppToken = appToken !== null && new RegExp(
      `^\\s*id:\\s*${appToken[1]}\\s*$[\\s\\S]*?^\\s*uses:\\s*actions/create-github-app-token@d72941d797fd3113feb6b93fd0dec494b13a2547\\s*$`,
      'mu',
    ).test(source);
    const stepToken = repositoryToken || pinnedAppToken;
    const barePush = /^git\s+push(?:\s|$)/u.test(trimmed);
    if (barePush || !scopedHelper || !stepToken) {
      findings.push({
        path,
        line: index + 1,
        reason: "git push is not bound to the reviewed command-scoped gh helper and step token",
      });
    }
  }
  return findings;
}

async function yamlFilesBelow(directory) {
  const files = [];
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return files;
    throw error;
  }
  for (const entry of entries) {
    const target = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await yamlFilesBelow(target));
    else if (entry.isFile() && yamlExtensions.has(extname(entry.name))) files.push(target);
  }
  return files;
}

export async function collectRepositoryFindings(root = defaultRoot) {
  const files = [
    ...await yamlFilesBelow(join(root, ".github/workflows")),
    ...await yamlFilesBelow(join(root, ".github/actions")),
  ];
  const findings = [];
  const credentialFindings = [];
  const pushFindings = [];
  const packageFindings = [];
  for (const file of files) {
    const source = await readFile(file, "utf8");
    findings.push(...mutableActionReferences(
      source,
      relative(root, file),
    ));
    credentialFindings.push(...persistingCheckoutReferences(
      source,
      relative(root, file),
    ));
    pushFindings.push(...unsafeGitPushes(source, relative(root, file)));
    packageFindings.push(...mutablePackageExecutions(source, relative(root, file)));
  }
  return [
    ...findings.map((finding) => ({
      kind: "mutable-action", path: finding.path, line: finding.line,
      reason: "mutable action or reusable workflow reference",
    })),
    ...credentialFindings.map((finding) => ({
      kind: "checkout-credentials", path: finding.path, line: finding.line,
      reason: "checkout may persist a repository credential",
    })),
    ...pushFindings.map((finding) => ({
      kind: "unsafe-git-push", path: finding.path, line: finding.line,
      reason: finding.reason,
    })),
    ...packageFindings.map((finding) => ({
      kind: "mutable-package", path: finding.path, line: finding.line,
      reason: finding.reason,
    })),
  ];
}

export async function verifyRepository(root = defaultRoot) {
  const allFindings = await collectRepositoryFindings(root);
  const findings = allFindings.filter((finding) => finding.kind === "mutable-action");
  const credentialFindings = allFindings.filter((finding) => finding.kind === "checkout-credentials");
  const pushFindings = allFindings.filter((finding) => finding.kind === "unsafe-git-push");
  const packageFindings = allFindings.filter((finding) => finding.kind === "mutable-package");
  if (findings.length > 0) {
    for (const finding of findings) {
      console.error(`${finding.path}:${finding.line}: mutable action reference`);
    }
    throw new Error(`${findings.length} mutable GitHub Actions reference(s) found`);
  }
  if (credentialFindings.length > 0) {
    for (const finding of credentialFindings) {
      console.error(
        `${finding.path}:${finding.line}: checkout may persist a repository credential`,
      );
    }
    throw new Error(
      `${credentialFindings.length} credential-persisting checkout reference(s) found`,
    );
  }
  if (pushFindings.length > 0) {
    for (const finding of pushFindings) {
      console.error(`${finding.path}:${finding.line}: ${finding.reason}`);
    }
    throw new Error(`${pushFindings.length} unsafe Git push path(s) found`);
  }
  if (packageFindings.length > 0) {
    for (const finding of packageFindings) {
      console.error(
        `${finding.path}:${finding.line}: mutable package execution (${finding.reason})`,
      );
    }
    throw new Error(
      `${packageFindings.length} mutable package execution(s) found`,
    );
  }
  console.log("workflow pin policy: passed");
}


if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const json = process.argv[2] === "--findings-json";
  const root = process.argv[json ? 3 : 2] ? resolve(process.argv[json ? 3 : 2]) : defaultRoot;
  if (json) console.log(JSON.stringify(await collectRepositoryFindings(root)));
  else await verifyRepository(root);
}
