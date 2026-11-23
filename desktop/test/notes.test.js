import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseReleaseNotesFile, parseReleaseNotes, notesForManifest, NOTES_FALLBACK } from "../src/notes.js";

const good = `version: 0.2.0

- See your company's compliance dates right in the agent.
- One notification when a new task appears, never twice.
- Web filtering check for ISO 27001 workspaces.
`;

test("a good notes file passes", () => {
  const parsed = parseReleaseNotesFile(good);
  assert.deepEqual(parsed.errors, []);
  assert.equal(parsed.version, "0.2.0");
  assert.equal(parsed.notes.length, 3);
});

test("the repo's own RELEASE_NOTES.md passes", () => {
  const parsed = parseReleaseNotesFile(readFileSync(new URL("../RELEASE_NOTES.md", import.meta.url), "utf8"));
  assert.deepEqual(parsed.errors, []);
});

test("missing version, too few notes, markup, long and duplicate notes are refused", () => {
  assert.match(parseReleaseNotesFile("- a\n- b\n- c").errors.join(" "), /version/);
  assert.match(parseReleaseNotesFile("version: 0.2.0\n- a\n- b").errors.join(" "), /3 to 5 notes; found 2/);
  assert.match(parseReleaseNotesFile("version: 0.2.0\n- a\n- b\n- c\n- d\n- e\n- f").errors.join(" "), /found 6/);
  assert.match(parseReleaseNotesFile('version: 0.2.0\n- a\n- b\n- <img src=x onerror="alert(1)">').errors.join(" "), /plain text/);
  assert.match(parseReleaseNotesFile(`version: 0.2.0\n- a\n- b\n- ${"x".repeat(121)}`).errors.join(" "), /121 characters/);
  assert.match(parseReleaseNotesFile("version: 0.2.0\n- a\n- a\n- b").errors.join(" "), /twice/);
  assert.match(parseReleaseNotesFile("version: 0.2.0\n- a\n- b\nc").errors.join(" "), /starts with/);
});

test("the manifest carries one line per note and reads back the same", () => {
  const { notes } = parseReleaseNotesFile(good);
  assert.deepEqual(parseReleaseNotes(notesForManifest(notes)), notes);
});

test("the window shows at most 5 notes and a fallback for old releases", () => {
  assert.deepEqual(parseReleaseNotes("Signed Compliance Agent update."), NOTES_FALLBACK);
  assert.deepEqual(parseReleaseNotes(undefined), NOTES_FALLBACK);
  assert.equal(parseReleaseNotes(Array.from({ length: 9 }, (_, i) => `- note ${i}`).join("\n")).length, 5);
});

test("markup in a note stays text: it is returned as characters, never parsed", () => {
  const [note] = parseReleaseNotes("- <img src=x onerror=alert(1)>");
  assert.equal(note, "<img src=x onerror=alert(1)>");
});
