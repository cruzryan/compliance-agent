// Refuses a release whose notes are missing, old or malformed.
//
//   node scripts/check-release-notes.mjs                 format only (pull requests)
//   node scripts/check-release-notes.mjs --tag desktop-v0.2.0
//   node scripts/check-release-notes.mjs --version 0.2.0
//
// With a version it also checks that desktop/RELEASE_NOTES.md is written for
// that version and is not the previous release's notes again. It runs first in
// the release workflow, before anything is built, so a release without new
// notes never reaches a single agent. The reason is printed and written to the
// run summary.
import { readFileSync, appendFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseReleaseNotesFile } from "../desktop/src/notes.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const NOTES_PATH = "desktop/RELEASE_NOTES.md";
const args = process.argv.slice(2);
const flag = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const tag = flag("--tag");
let version = flag("--version");
const errors = [];
if (tag !== undefined) {
  if (/^desktop-v\d+\.\d+\.\d+$/.test(tag)) version = tag.replace(/^desktop-v/, "");
  else errors.push(`Releases are made from a desktop-vX.Y.Z tag, not "${tag}". Run npm run release in desktop/.`);
}

let text = "";
try {
  text = readFileSync(join(root, NOTES_PATH), "utf8");
} catch {
  errors.push(`${NOTES_PATH} is missing. Write 3 to 5 short lines about what changed.`);
}

const parsed = parseReleaseNotesFile(text);
if (text) errors.push(...parsed.errors.map((error) => `${NOTES_PATH}: ${error}`));

const compare = (a, b) => {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);
  for (let i = 0; i < 3; i += 1) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
};

if (version && text) {
  if (parsed.version && parsed.version !== version) {
    errors.push(`${NOTES_PATH} is written for ${parsed.version}, but this release is ${version}. Write the notes for ${version}.`);
  }
  // The newest earlier release, and its notes when it had the file.
  let tags = [];
  try {
    tags = execFileSync("git", ["tag", "--list", "desktop-v*"], { cwd: root, encoding: "utf8" })
      .split("\n").map((t) => t.trim()).filter((t) => /^desktop-v\d+\.\d+\.\d+$/.test(t));
  } catch {
    errors.push("Could not list the earlier releases (git tags). The release job needs the full history.");
  }
  const earlier = tags.map((t) => t.replace("desktop-v", "")).filter((v) => compare(v, version) < 0).sort(compare);
  const previous = earlier.at(-1);
  if (previous) {
    let previousText = "";
    try {
      previousText = execFileSync("git", ["show", `desktop-v${previous}:${NOTES_PATH}`], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    } catch {
      // The previous release had no notes file yet.
    }
    if (previousText) {
      const before = parseReleaseNotesFile(previousText).notes;
      if (before.length && before.join("\n") === parsed.notes.join("\n")) {
        errors.push(`${NOTES_PATH} still has the notes of ${previous}. Write what changed in ${version}.`);
      }
    }
  }
}

const summary = process.env.GITHUB_STEP_SUMMARY;
if (errors.length) {
  const message = ["Release notes check failed. Nothing was built or published.", "", ...errors.map((e) => `- ${e}`)].join("\n");
  console.error(message);
  if (summary) appendFileSync(summary, `## Release stopped: release notes\n\n${message}\n`);
  process.exit(1);
}
const ok = `Release notes OK${version ? ` for ${version}` : ""}:\n${parsed.notes.map((n) => `- ${n}`).join("\n")}`;
console.log(ok);
if (summary) appendFileSync(summary, `## Release notes\n\n${ok}\n`);
