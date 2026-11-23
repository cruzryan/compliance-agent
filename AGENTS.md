# Working on the Compliance Agent

Rules for anyone changing this repo, people and coding agents alike.

## Every change that ships in the agent updates the release notes

`desktop/RELEASE_NOTES.md` is what people read in the update window before
they install. It must describe the next release, so a change that ships in the
agent (Go collector, Tauri app or window) also updates it in the same pull
request:

```
version: 0.2.1

- One short line per change a person would notice.
- 3 to 5 lines. Plain text: no < or >, at most 120 characters each.
- Say what the person gets, not how it was built.
```

- Bump `version:` to the version you will release when the notes still name a
  released version.
- The release cannot ship without it. `scripts/check-release-notes.mjs` runs
  first in the release workflow and stops the release, before anything is
  built, if the notes are missing, malformed, written for another version, or
  the same as the previous release's. CI runs the format check on every pull
  request.
- The window shows each note as plain text (`textContent`, one `<p>` each).
  Never render release notes as HTML.

## Releasing

From `desktop/`, on an up-to-date `main`: `npm run release -- 0.2.1`. It
refuses unless the notes for that version pass, then tags `desktop-v0.2.1` and
pushes the tag. Every installed agent receives every release: there are no test
releases.

## Changing the computer

The agent reads settings. It changes one only when the person presses that
setting's button and agrees (web filtering is the only one today), and it never
reapplies a change on its own.
