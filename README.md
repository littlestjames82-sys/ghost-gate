# Ghost Gate

**Nothing reaches GitHub un-scanned, un-diffed, or un-recorded.**

One gate between a local folder and GitHub, from Ghost Developer
Studio. Pure Python standard library, one file, no installs. A
PyUI-style desktop window plus a CLI with exit codes scripts can
gate on.

## The flow

1. **Scan.** Before anything moves, the tree is checked for
   credential-shaped strings (GitHub tokens, cloud keys, private key
   blocks, shaped API keys), filename classes that are blocked
   outright (`.env`, `*.pem`, `*.key`, `id_rsa*`, credentials files,
   keystores), oversize files, and per-repo **watch-strings**: literal
   strings that stop the push on sight (an address, a phone number,
   anything that must never be public). Archives in the tree (`.zip`,
   `.apk`, `.jar`, `.tar.gz`) are opened and deep-scanned too: a key
   baked into a shipped binary is the worst leak. `.gitignore` and
   `.ghostgateignore` are respected. A finding names the shape and
   the line, never the secret itself, and carries a fingerprint so a
   false positive can be overridden by exact fingerprint plus a
   written reason in `.ghostgate.json` (auditable overrides). A
   per-repo **gate command** (the project's own tests) must pass
   before the scan even starts.
2. **Diff.** Local tree vs remote tree compared by real git blob
   hashes: added, changed, deleted, unchanged, listed up front.
3. **Rehearsed push.** The commit is built server-side first (blobs,
   tree, commit) without moving the branch. The delta files are
   re-hashed at the last second; anything that changed since the
   scan aborts the landing. Landing is a single ref update to that
   exact commit, then the remote tree is read back and compared
   hash-for-hash, and key files are pulled back from the raw public
   URL and hash-matched, proving the world sees the push. If a
   changed file carries a version that moved, the commit is named
   for it (and a release draft is prepared in `~/ghost-gate-drafts`;
   Gate never publishes a release). If the branch moved outside Gate
   since the last gated push, non-overlapping remote work is
   **absorbed** (your delta is applied on top of it); only files
   changed on both sides stop the push.
4. **Journal + rollback.** Every gated push is written to a
   hash-chained SQLite journal (`~/.ghost-gate.db`): repo, branch,
   commits before and after, delta counts, scan verdict. Rollback
   resets the branch to the journal's previous commit.

Per-repo rules live in an optional `.ghostgate.json` in the folder:
`watch_strings`, `must_stay_private`, `protected_branches`,
`gate_command`, `overrides`. First contact with a repo can be
**observe-only** (`--observe`): Gate profiles it and drafts proposed
guardrails for your approval. `--history` audits a repo's past
commits for the same shapes, because a secret deleted today is
still public in history. `--batch` runs the full gate over a list
of folder/repo pairs and prints one verdict board.

## Usage

```
python3 ghost_gate.py                      # GUI
python3 ghost_gate.py --scan FOLDER
python3 ghost_gate.py --diff FOLDER owner/repo [branch]
python3 ghost_gate.py --push FOLDER owner/repo [branch] [--message M]
python3 ghost_gate.py --rollback owner/repo [branch]
python3 ghost_gate.py --journal [N]
python3 ghost_gate.py --history owner/repo [branch]
python3 ghost_gate.py --observe FOLDER owner/repo
python3 ghost_gate.py --batch BATCHFILE
python3 ghost_gate.py --init-repo NAME [--public]
python3 ghost_gate.py --selftest
```

Exit codes: 0 ok, 1 blocked or mismatch, 2 usage or IO error.

The GitHub credential is never stored by the tool: it uses
`GITHUB_TOKEN` from the environment when present, otherwise the
workspace GitHub connector route.

`--selftest` plants canary fixtures (fake GitHub and AWS example
keys, a `.env`, a watch-string, an ignored file with a token inside,
a token sealed in a zip) and proves the scanner catches every plant,
respects the ignore, and that overrides, the gate command, and the
last-second re-check behave.

## Design

The full spec (three design rounds) lives in
[DESIGN.md](DESIGN.md). Version 1.0 shipped the core four plus
hygiene, watch-strings, the divergence guard, protected branches
and must-stay-private. Version 1.1 adds the rest of the spec:
archive deep-scan, auditable overrides, project gate commands,
absorb, last-second re-check, version-drafted commit messages,
post-push pull-back, release draft preparation (never published),
history sweep, observe-first onboarding, and batch sweeps.

Ghost Gate's own pushes to this repository are made through
Ghost Gate; the 1.1 push was named by its own version drafting and
verified by its own pull-back.
