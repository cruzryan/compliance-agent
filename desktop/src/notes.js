// Release notes: the 3 to 5 short lines a person sees before an update.
//
// They are written in desktop/RELEASE_NOTES.md, checked before any release is
// built (scripts/check-release-notes.mjs), copied into the signed update
// manifest, and shown in the update window as plain text, one <p> each, with
// textContent. They are never read as HTML, so a note can never run code.
//
// The file looks like this:
//
//   version: 0.2.0
//
//   - See your company's compliance dates right in the agent.
//   - One notification when a new task appears, never twice.
//   - Web filtering check for ISO 27001 workspaces.

export const MIN_NOTES = 3;
export const MAX_NOTES = 5;
export const MAX_NOTE_CHARS = 120;
export const NOTES_FALLBACK = ["Security and reliability fixes."];

const VERSION_LINE = /^version:\s*(\d{1,4}\.\d{1,4}\.\d{1,6})\s*$/i;
const BULLET = /^[-*]\s+(.*)$/;

// eslint-disable-next-line no-control-regex
const plain = (text) => String(text).replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();

/** Strict reading of RELEASE_NOTES.md, for the release check. */
export function parseReleaseNotesFile(text) {
  const errors = [];
  let version = "";
  const notes = [];
  const lines = String(text ?? "").split(/\r?\n/);
  for (const [index, raw] of lines.entries()) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const versionMatch = VERSION_LINE.exec(line);
    if (versionMatch) {
      if (version) errors.push(`Line ${index + 1}: the version is written twice.`);
      version = versionMatch[1];
      continue;
    }
    const bullet = BULLET.exec(line);
    if (!bullet) {
      errors.push(`Line ${index + 1}: every note starts with "- ". Found: ${line.slice(0, 60)}`);
      continue;
    }
    const note = plain(bullet[1]);
    if (!note) errors.push(`Line ${index + 1}: the note is empty.`);
    else if (note.length > MAX_NOTE_CHARS) errors.push(`Line ${index + 1}: the note is ${note.length} characters; the most is ${MAX_NOTE_CHARS}.`);
    else if (/[<>]/.test(note)) errors.push(`Line ${index + 1}: notes are plain text; remove < and >.`);
    else if (notes.includes(note)) errors.push(`Line ${index + 1}: the same note is written twice.`);
    notes.push(note);
  }
  if (!version) errors.push('The first line must be the version, like "version: 0.2.0".');
  if (notes.length < MIN_NOTES || notes.length > MAX_NOTES) {
    errors.push(`Write ${MIN_NOTES} to ${MAX_NOTES} notes; found ${notes.length}.`);
  }
  return { version, notes, errors };
}

/** The notes as the update manifest carries them: one "- " line each. */
export function notesForManifest(notes) {
  return notes.map((note) => `- ${note}`).join("\n");
}

/**
 * The lines the update window shows, from the manifest's notes. Lenient: an
 * older release without real notes shows one fallback line.
 */
export function parseReleaseNotes(body) {
  if (typeof body !== "string") return NOTES_FALLBACK;
  const notes = body
    .split(/\r?\n/)
    .map((line) => BULLET.exec(line.trim()))
    .filter(Boolean)
    .map((match) => plain(match[1]))
    .filter(Boolean)
    .map((note) => (note.length > MAX_NOTE_CHARS + 20 ? `${note.slice(0, MAX_NOTE_CHARS + 17)}...` : note))
    .slice(0, MAX_NOTES);
  return notes.length ? notes : NOTES_FALLBACK;
}
