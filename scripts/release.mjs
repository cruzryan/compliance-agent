// The one way to release the Compliance Agent: `npm run release -- 0.2.0`
// (from desktop/). It refuses unless the release notes for that version are
// ready, the tree is clean and on main, and the version is new. Only then it
// tags desktop-v0.2.0 and pushes the tag, which starts the release workflow.
// Every installed agent receives the release: there are no test releases.
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const version = process.argv[2];
const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
const stop = (message) => {
  console.error(`Not released: ${message}`);
  process.exit(1);
};

if (!/^\d+\.\d+\.\d+$/.test(version || "")) stop("give the version, like: npm run release -- 0.2.0");
const tag = `desktop-v${version}`;
if (git("branch", "--show-current") !== "main") stop("release from main.");
if (git("status", "--porcelain")) stop("commit or remove your local changes first.");
git("fetch", "origin", "main", "--tags");
if (git("rev-parse", "HEAD") !== git("rev-parse", "origin/main")) stop("your main is not the same as origin/main. Pull first.");
if (git("tag", "--list", tag)) stop(`${tag} already exists.`);
try {
  execFileSync("node", [join(root, "scripts/check-release-notes.mjs"), "--version", version], { cwd: root, stdio: "inherit" });
} catch {
  stop("fix desktop/RELEASE_NOTES.md, commit it, then run this again.");
}
git("tag", "-a", tag, "-m", `Compliance Agent ${version}`);
git("push", "origin", tag);
console.log(`Tagged and pushed ${tag}. The release workflow builds it and every installed agent updates.`);
