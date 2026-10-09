#!/usr/bin/env node
/** Real Renovate extraction/RE2/replacement/rule-order contracts. No platform operations. */
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const renovateRoot = path.join(root, ".ci-tools/renovate");
const require = createRequire(path.join(renovateRoot, "package.json"));
const load = (name) =>
  import(pathToFileURL(path.join(renovateRoot, "dist", name)));
const { parse } = require("yaml");
const { GlobalConfig } = await load("config/global.js");
GlobalConfig.set({ localDir: root });
process.env.LOG_LEVEL = "fatal";
const { init } = await load("logger/index.js");
await init();
const { regEx, regexEngineStatus } = await load("util/regex.js");
const { matchRegexOrGlob } = await load("util/string-match.js");
const { validateConfig } = await load("config/validation.js");
const { applyPackageRules } = await load("util/package-rules/index.js");
const { resolveConfigPresets } = await load("config/presets/index.js");
const { doAutoReplace } = await load(
  "workers/repository/update/branch/auto-replace.js",
);
const custom = await load("modules/manager/custom/regex/index.js");
const actions = await load("modules/manager/github-actions/extract.js");
const rust = await load("modules/manager/rust-toolchain/extract.js");
const cargo = await load("modules/manager/cargo/extract.js");
const config = JSON.parse(
  await fs.readFile(path.join(root, ".github/renovate.json"), "utf8"),
);
const toolImage = JSON.parse(
  await fs.readFile(path.join(root, "scripts/renovate-tool.json"), "utf8"),
).image;
const toolVersion = toolImage.split(":")[1].split("@")[0];
assert.equal(
  (
    await fs.readFile(path.join(renovateRoot, "source-image.txt"), "utf8")
  ).trim(),
  toolImage,
  "extracted runtime must record the same reviewed immutable OCI source",
);
assert.equal(
  JSON.parse(await fs.readFile(path.join(renovateRoot, "package.json"), "utf8"))
    .version,
  toolVersion,
  "test runtime must match the exact declared Renovate pin",
);
assert.equal(
  regexEngineStatus.type,
  "available",
  "actual Renovate RE2 engine from the immutable OCI artifact is mandatory",
);
assert.throws(
  () => regEx("a(?=b)", undefined, false),
  /regular expression|config-validation/,
  "RE2 must reject unsupported lookahead",
);
assert.throws(
  () => regEx("(a)\\1", undefined, false),
  /regular expression|config-validation/,
  "RE2 must reject backreferences",
);
const validated = await validateConfig("repository", config);
assert.deepEqual(
  validated.errors,
  [],
  "production config must pass the supported Renovate validator",
);
assert.deepEqual(
  validated.warnings,
  [],
  "production config must have no validation warnings",
);
const { config: effectiveConfig, visitedPresets } = await resolveConfigPresets(
  structuredClone(config),
);
assert(
  visitedPresets.merged.includes("config:best-practices"),
  "actual configured preset must participate",
);
assert(
  !effectiveConfig.extends,
  "all bundled production presets must be resolved",
);
assert(
  effectiveConfig.packageRules.length > config.packageRules.length,
  "inherited generic preset rules must participate",
);
assert(
  config.enabledManagers.includes("custom.regex"),
  "restricted manager list must enable custom.regex",
);
for (const manager of config.customManagers) {
  for (const pattern of manager.matchStrings) regEx(pattern);
  for (const pattern of manager.managerFilePatterns)
    assert(pattern.startsWith("/") && pattern.endsWith("/"));
}

const workflowFiles = (await fs.readdir(path.join(root, ".github/workflows")))
  .filter((f) => /\.ya?ml$/.test(f))
  .map((f) => `.github/workflows/${f}`);
const files = new Map(
  await Promise.all(
    [
      ...workflowFiles,
      "scripts/renovate-tool.json",
      "rust-toolchain.toml",
      "Cargo.toml",
    ].map(async (f) => [f, await fs.readFile(path.join(root, f), "utf8")]),
  ),
);
const ignored = (file, cfg) =>
  cfg.ignorePaths.some((pattern) => matchRegexOrGlob(file, pattern));
const key = (file, dep) =>
  JSON.stringify([
    file,
    dep.depName,
    dep.currentValue,
    dep.currentDigest ?? null,
    dep.datasource,
  ]);
async function inventory(input = files, cfg = config) {
  const out = [];
  for (const [file, content] of input) {
    if (ignored(file, cfg)) continue;
    for (const [manager, implementation, applicable] of [
      [
        "github-actions",
        actions,
        /^\.github\/workflows\/.*\.ya?ml$/.test(file),
      ],
      ["rust-toolchain", rust, file === "rust-toolchain.toml"],
      ["cargo", cargo, file === "Cargo.toml"],
    ]) {
      if (!applicable || !cfg.enabledManagers.includes(manager)) continue;
      const result = await implementation.extractPackageFile(content, file, {});
      for (const dep of result?.deps ?? []) {
        if (dep.currentValue?.includes("${{")) {
          assert.equal(dep.depType, "uses-with");
          assert.equal(
            dep.currentValue,
            "${{ steps.shared-node.outputs.version }}",
          );
          continue; // derived runtime has no second local version pin
        }
        out.push({ file, manager, dep, extraction: result });
      }
    }
    if (cfg.enabledManagers.includes("custom.regex"))
      for (const definition of cfg.customManagers) {
        if (
          !definition.managerFilePatterns.some((pattern) =>
            matchRegexOrGlob(file, pattern),
          )
        )
          continue;
        const result = custom.extractPackageFile(content, file, definition);
        for (const dep of result?.deps ?? [])
          out.push({ file, manager: "custom.regex", dep, extraction: result });
      }
  }
  return out;
}
function expected(input = files) {
  const out = [];
  for (const [file, text] of input) {
    if (/^\.github\/workflows\/.*\.ya?ml$/.test(file)) {
      const workflow = parse(text);
      // Renovate owns each literal declaration once. YAML aliases share that source pin.
      for (const match of text.matchAll(
        /uses:\s+([^@\s]+)@([a-f0-9]{40}) # (v[0-9.]+)/g,
      )) {
        out.push(
          key(file, {
            depName: match[1],
            currentDigest: match[2],
            currentValue: match[3],
            datasource: "github-tags",
          }),
        );
      }
      for (const job of Object.values(workflow.jobs)) {
        if (job["runs-on"]) {
          const [name, ...version] = job["runs-on"].split("-");
          out.push(
            key(file, {
              depName: name,
              currentValue: version.join("-"),
              datasource: "github-runners",
            }),
          );
        }
        for (const step of job.steps ?? []) {
          if (step.with?.repository && /^[0-9a-f]{40}$/.test(step.with.ref)) {
            out.push(
              key(file, {
                depName: step.with.repository,
                currentValue: "main",
                currentDigest: step.with.ref,
                datasource: "github-digest",
              }),
            );
          }
        }
      }
    } else if (file === "Cargo.toml") {
      // Independent finite Cargo declaration inventory, including exact inline-table pins.
      for (const section of text.matchAll(
        /\[(?:dependencies|target\.[^\n]+\.dependencies)\]\n([\s\S]*?)(?=\n\[|$)/g,
      )) {
        for (const match of section[1].matchAll(
          /^([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]+)"|\{[^\n]*version\s*=\s*"([^"]+)")/gm,
        )) {
          const currentValue = match[2] ?? match[3];
          assert(
            /^=\d+\.\d+\.\d+$/.test(currentValue),
            "product Cargo dependencies must be exact",
          );
          out.push(
            key(file, { depName: match[1], currentValue, datasource: "crate" }),
          );
        }
      }
    } else if (file === "rust-toolchain.toml") {
      out.push(
        key(file, {
          depName: "rust",
          currentValue: text.match(/channel = "([^"]+)"/)[1],
          datasource: "rust-version",
        }),
      );
    } else if (file === "scripts/renovate-tool.json") {
      const image = JSON.parse(text).image;
      const match = image.match(
        /^(ghcr\.io\/renovatebot\/renovate):([0-9.]+)@(sha256:[a-f0-9]{64})$/,
      );
      assert(
        match,
        "operational image must have one immutable version/digest pair",
      );
      out.push(
        key(file, {
          depName: match[1],
          currentValue: match[2],
          currentDigest: match[3],
          datasource: "docker",
        }),
      );
    }
  }
  return out.sort();
}
function ownership(actual, expectedPins = expected()) {
  assert.deepEqual(
    actual.map((row) => key(row.file, row.dep)).sort(),
    expectedPins,
    "every operational pin must be extracted exactly once, by one manager",
  );
  const owners = new Map();
  for (const row of actual) {
    const id = key(row.file, row.dep);
    const owner = owners.get(id);
    assert(
      !owner || owner === row.manager,
      `native/custom manager overlap for ${id}`,
    );
    owners.set(id, row.manager);
  }
}
const actual = await inventory();
ownership(actual);
assert(
  actual.filter((row) => row.manager === "cargo").length >= 3,
  "foundation parser Cargo dependencies must be owned",
);
const timezoneOwners = actual.filter((row) => row.dep.depName === "jiff-tzdb");
assert.equal(timezoneOwners.length, 1, "bundled timezone pin has exactly one owner");
assert.equal(timezoneOwners[0].manager, "cargo");
const withoutCargo = structuredClone(config);
withoutCargo.enabledManagers = withoutCargo.enabledManagers.filter(
  (manager) => manager !== "cargo",
);
const missingCargo = await inventory(files, withoutCargo);
assert.throws(() => ownership(missingCargo));

// Meaningful negative manager mutations: they must fail the same production inventory assertion.
const withoutCustom = structuredClone(config);
withoutCustom.enabledManagers = withoutCustom.enabledManagers.filter(
  (m) => m !== "custom.regex",
);
const missingCustom = await inventory(files, withoutCustom);
assert.throws(() => ownership(missingCustom));
assert.throws(() =>
  ownership([...actual, actual.find((r) => r.manager === "custom.regex")]),
);
assert.throws(() =>
  ownership([
    ...actual,
    {
      ...actual.find((r) => r.manager === "github-actions"),
      manager: "custom.regex",
    },
  ]),
);
assert.throws(() => ownership(missingCustom));
const duplicated = structuredClone(config);
duplicated.customManagers.push(structuredClone(duplicated.customManagers[0]));
const duplicateExtraction = await inventory(files, duplicated);
assert.throws(() => ownership(duplicateExtraction));
const wrongPath = structuredClone(config);
wrongPath.customManagers[0].managerFilePatterns = ["/^moved\/.*$/"];
const missingExtraction = await inventory(files, wrongPath);
assert.throws(() => ownership(missingExtraction));
const movedFiles = new Map(files);
const movedContent = movedFiles.get(".github/workflows/ci.yml");
movedFiles.delete(".github/workflows/ci.yml");
movedFiles.set(".github/workflows/renamed.yml", movedContent);
ownership(await inventory(movedFiles), expected(movedFiles));
const noDatasource = structuredClone(config.customManagers[0]);
delete noDatasource.datasourceTemplate;
assert.equal(
  custom.extractPackageFile(
    movedContent,
    ".github/workflows/ci.yml",
    noDatasource,
  ),
  null,
  "missing required datasource must not extract a valid dependency",
);
const historical = new Map([
  ["fixtures/old-workflow.yml", movedContent],
  ["docs/evidence/old.yml", movedContent],
  [".shared-tools/.github/workflows/ci.yml", movedContent],
]);
assert.deepEqual(
  await inventory(historical),
  [],
  "historical evidence and nested upstream pins must not auto-advance",
);
assert(
  !config.customManagers.some((m) =>
    m.matchStrings.some((s) => /1\\\.20|checksum|FROM /.test(s)),
  ),
  "future compatibility anchors and upstream checksums are not local custom-manager pins",
);

// Frozen sources/versions are explicit exclusions even if future managers recognize them.
const frozenFiles = new Map([
  ["docs/compatibility/historical-anchor.md", movedContent],
  ["schemas/capabilities/kubernetes-1.20-1.37.json", movedContent],
]);
const broaderManager = structuredClone(config);
broaderManager.customManagers[0].managerFilePatterns = [
  "/^(?:docs\\/compatibility|schemas\\/capabilities)\\/.*$/",
];
for (const file of frozenFiles.keys())
  assert(
    ignored(file, config),
    "frozen contract paths must be explicitly excluded",
  );
assert.deepEqual(
  await inventory(frozenFiles, broaderManager),
  [],
  "actual engine must preserve compatibility anchors",
);
const missingExclusions = structuredClone(broaderManager);
missingExclusions.ignorePaths = missingExclusions.ignorePaths.filter(
  (pattern) =>
    !["docs/compatibility/**", "schemas/capabilities/**"].includes(pattern),
);
assert(
  (await inventory(frozenFiles, missingExclusions)).length > 0,
  "removing frozen exclusions must expose real dependency extraction",
);
const frozenLedger = JSON.parse(
  await fs.readFile(
    path.join(root, "schemas/capabilities/kubernetes-1.20-1.37.json"),
    "utf8",
  ),
);
assert.deepEqual(frozenLedger.frozen_scope.claimable_supported_minors, []);
assert.equal(
  frozenLedger.canonical_tool_owner.commit.length,
  40,
  "operational tools retain one immutable external owner",
);

// Real replacement writes only to a disposable scratch tree, then re-extracts using production managers.
const scratch = await fs.mkdtemp(
  path.join(os.tmpdir(), "kubernetes-lens-renovate-"),
);
try {
  GlobalConfig.set({ localDir: scratch });
  const sharedRows = actual.filter(
    (row) => row.dep.datasource === "github-digest",
  );
  assert(
    sharedRows.length >= 2,
    "both shared tools and policy commits must have owners",
  );
  for (const row of [
    sharedRows[0],
    actual.find((r) => r.dep.depType === "action"),
  ]) {
    const original = files.get(row.file);
    await fs.mkdir(path.join(scratch, path.dirname(row.file)), {
      recursive: true,
    });
    await fs.writeFile(path.join(scratch, row.file), original);
    const newDigest = "a".repeat(40);
    const upgrade = {
      ...row.extraction,
      ...row.dep,
      manager: row.manager === "custom.regex" ? "regex" : row.manager,
      packageFile: row.file,
      depIndex: 0,
      newDigest,
      newValue: row.dep.currentValue,
      autoReplaceGlobalMatch: false,
    };
    // Select the right extracted index; other refs in the same file must not be touched.
    upgrade.depIndex = row.extraction.deps.indexOf(row.dep);
    const updated = await doAutoReplace(upgrade, original, false);
    assert(
      updated && updated !== original,
      "actual Renovate digest-only replacement must change the pin",
    );
    const extraction =
      row.manager === "custom.regex"
        ? custom.extractPackageFile(updated, row.file, config.customManagers[0])
        : await actions.extractPackageFile(updated, row.file, {});
    const dep = extraction.deps[upgrade.depIndex];
    assert.equal(dep.depName, row.dep.depName);
    assert.equal(
      dep.currentValue,
      row.dep.currentValue,
      "digest-only changes preserve the existing version/tag",
    );
    assert.equal(dep.currentDigest, newDigest);
    if (row.manager === "github-actions") {
      await fs.writeFile(path.join(scratch, row.file), original);
      const bumped = await doAutoReplace(
        { ...upgrade, newValue: "v7.0.2" },
        original,
        false,
      );
      const after = await actions.extractPackageFile(bumped, row.file, {});
      assert.equal(after.deps[upgrade.depIndex].currentValue, "v7.0.2");
      assert.equal(
        after.deps[upgrade.depIndex].currentDigest,
        newDigest,
        "Action SHA and exact release comment advance together",
      );
    }
  }
  const imageRow = actual.find((row) => row.dep.datasource === "docker");
  const originalImage = files.get(imageRow.file);
  await fs.mkdir(path.join(scratch, path.dirname(imageRow.file)), {
    recursive: true,
  });
  for (const newValue of [toolVersion, "44.139.1"]) {
    await fs.writeFile(path.join(scratch, imageRow.file), originalImage);
    const newDigest = "sha256:" + "a".repeat(64);
    const updated = await doAutoReplace(
      {
        ...imageRow.extraction,
        ...imageRow.dep,
        manager: "regex",
        packageFile: imageRow.file,
        depIndex: 0,
        newValue,
        newDigest,
      },
      originalImage,
      false,
    );
    const after = custom.extractPackageFile(
      updated,
      imageRow.file,
      config.customManagers[1],
    );
    assert.equal(
      after.deps[0].currentValue,
      newValue,
      "actual image replacement handles tag changes and digest-only updates",
    );
    assert.equal(
      after.deps[0].currentDigest,
      newDigest,
      "image tag/digest remain a coupled immutable pair",
    );
  }
} finally {
  GlobalConfig.set({ localDir: root });
  await fs.rm(scratch, { recursive: true, force: true });
}

async function policy(dep, cfg = effectiveConfig) {
  return applyPackageRules(
    { ...cfg, ...dep, packageName: dep.packageName ?? dep.depName },
    "update",
  );
}
for (const updateType of ["minor", "patch", "pin", "digest", "pinDigest"]) {
  const normal = await policy({
    manager: "cargo",
    datasource: "crate",
    depName: "serde",
    updateType,
  });
  assert.equal(normal.groupName, "Rust dependencies");
  assert.equal(normal.automerge, true);
  assert.equal(normal.minimumReleaseAge, "3 days");
  const timezone = await policy({ manager: "cargo", datasource: "crate", depName: "jiff-tzdb", updateType });
  assert.equal(timezone.groupName, "Native timezone data");
  assert.equal(timezone.automerge, false);
  assert.equal(timezone.dependencyDashboardApproval, true);
  assert.equal(timezone.minimumReleaseAge, "3 days");
  const toolchain = await policy({
    manager: "rust-toolchain",
    datasource: "rust-version",
    depName: "rust",
    updateType,
  });
  assert.equal(toolchain.groupName, "Rust toolchain");
  assert.equal(toolchain.automerge, false);
  assert.equal(toolchain.dependencyDashboardApproval, true);
  for (const row of actual.filter((r) =>
    ["github-digest", "github-runners", "docker"].includes(r.dep.datasource),
  )) {
    const effective = await policy({
      ...row.dep,
      manager: row.manager,
      packageFile: row.file,
      updateType,
    });
    assert.equal(
      effective.automerge,
      false,
      "later integrity rules must override broad non-major automerge",
    );
    assert.equal(effective.dependencyDashboardApproval, true);
    assert.equal(effective.minimumReleaseAge, "3 days");
    if (row.dep.datasource === "docker")
      assert.equal(effective.pinDigests, true);
    assert.equal(
      effective.groupName,
      row.dep.datasource === "github-digest"
        ? "Shared workspace tooling and policy"
        : row.dep.datasource === "docker"
          ? "Operational test tools"
          : "GitHub-hosted runners",
    );
  }
}
const toolPolicy = await policy({
  manager: "custom.regex",
  datasource: "docker",
  depName: "ghcr.io/renovatebot/renovate",
  updateType: "patch",
});
assert.equal(toolPolicy.groupName, "Operational test tools");
assert.equal(toolPolicy.automerge, false);
assert.equal(toolPolicy.dependencyDashboardApproval, true);
assert.equal(toolPolicy.pinDigests, true);
const derivedNode = await policy({
  manager: "github-actions",
  datasource: "github-releases",
  depName: "node",
  packageName: "actions/node-versions",
  depType: "uses-with",
  updateType: "patch",
});
assert.equal(
  derivedNode.enabled,
  false,
  "derived shared Node input must not become a duplicate local pin",
);
const actionPolicy = await policy({
  manager: "github-actions",
  datasource: "github-tags",
  depName: "actions/checkout",
  depType: "action",
  updateType: "patch",
});
assert.equal(actionPolicy.pinDigests, true);
assert.equal(actionPolicy.groupName, "GitHub Actions");
const lockPolicy = await policy({
  manager: "cargo",
  depName: "serde",
  updateType: "lockFileMaintenance",
});
assert.equal(lockPolicy.minimumReleaseAge, "0 days");
assert.equal(lockPolicy.automerge, true);
const major = await policy({
  manager: "cargo",
  depName: "serde",
  updateType: "major",
});
assert.notEqual(
  major.automerge,
  true,
  "major updates cannot inherit non-major automerge",
);
const reordered = structuredClone(effectiveConfig);
const broad = reordered.packageRules.find(
  (r) => r.automerge === true && r.matchUpdateTypes.includes("digest"),
);
reordered.packageRules.push(structuredClone(broad));
const unsafePolicy = await policy(
  {
    manager: "custom.regex",
    datasource: "github-digest",
    depName: "Strukturpiloten/boxferry",
    updateType: "digest",
  },
  reordered,
);
assert.equal(
  unsafePolicy.automerge,
  true,
  "negative rule-order mutation must expose the dangerous override",
);
assert.throws(() => assert.equal(unsafePolicy.automerge, false));
const unsafeTimezone = await policy({ manager: "cargo", datasource: "crate", depName: "jiff-tzdb", updateType: "patch" }, reordered);
assert.equal(unsafeTimezone.automerge, true, "negative rule-order mutation exposes unsafe timezone updates");
assert.throws(() => assert.equal(unsafeTimezone.automerge, false));
const unsafeImage = await policy(
  {
    manager: "custom.regex",
    datasource: "docker",
    depName: "ghcr.io/renovatebot/renovate",
    updateType: "digest",
  },
  reordered,
);
assert.equal(unsafeImage.automerge, true);
assert.throws(
  () => assert.equal(unsafeImage.automerge, false),
  "negative generic-rule reorder must expose image digest automerge regression",
);
console.log(
  `Renovate ${toolVersion}: RE2 available; ${actual.length} actual pins with exclusive owners; extraction, replacement, rule-order and mutation regressions passed.`,
);
