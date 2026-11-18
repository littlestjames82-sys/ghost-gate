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
   anything that must never be public). `.gitignore` and
   `.ghostgateignore` are respected. A finding names the shape and
   the line, never the secret itself.
2. **Diff.** Local tree vs remote tree compared by real git blob
   hashes: added, changed, deleted, unchanged, listed up front.
3. **Rehearsed push.** The commit is built server-side first (blobs,
   tree, commit) without moving the branch. Landing is a single ref
   update to that exact commit, then the remote tree is read back and
   compared hash-for-hash. Landed commit must equal rehearsed commit.
4. **Journal + rollback.** Every gated push is written to a
   hash-chained SQLite journal (`~/.ghost-gate.db`): repo, branch,
   commits before and after, delta counts, scan verdict. Rollback
   resets the branch to the journal's previous commit. If the branch
   moved outside Gate since the last gated push, the divergence guard
   stops the push until a human looks.

Per-repo rules live in an optional `.ghostgate.json` in the folder:
`watch_strings`, `must_stay_private`, `protected_branches`.

## Usage

```
python3 ghost_gate.py                      # GUI
python3 ghost_gate.py --scan FOLDER
python3 ghost_gate.py --diff FOLDER owner/repo [branch]
python3 ghost_gate.py --push FOLDER owner/repo [branch] [--message M]
python3 ghost_gate.py --rollback owner/repo [branch]
python3 ghost_gate.py --journal [N]
python3 ghost_gate.py --init-repo NAME [--public]
python3 ghost_gate.py --selftest
```

Exit codes: 0 ok, 1 blocked or mismatch, 2 usage or IO error.

The GitHub credential is never stored by the tool: it uses
`GITHUB_TOKEN` from the environment when present, otherwise the
workspace GitHub connector route.

`--selftest` plants canary fixtures (fake GitHub and AWS example
keys, a `.env`, a watch-string, an ignored file with a token inside)
and proves the scanner catches every plant and respects the ignore.

## Design

The full spec (three design rounds: divergence guard, guardrails,
rehearsed commits, archive deep-scan, history sweep, absorb,
auditable overrides, watch-strings, observe-first onboarding,
authority boundary) lives in [DESIGN.md](DESIGN.md). Version 1.0
ships the core four plus hygiene, watch-strings, the divergence
guard, protected branches and must-stay-private.

Ghost Gate's own first push to this repository was made through
Ghost Gate.
