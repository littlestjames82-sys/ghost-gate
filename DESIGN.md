# Ghost Gate — design spec (Ryan's design rounds, Nov 18, 2026)

One gate between a local folder and GitHub. Nothing reaches GitHub
un-scanned, un-diffed, or un-recorded. Pure Python stdlib, one file,
GUI + CLI, in the Ghost Verify house style.

## Core four (v1.0)
1. **Scan** — credential-shaped patterns (GitHub tokens, cloud keys,
   private key blocks, shaped API keys), filename classes blocked
   outright (.env, *.pem, *.key, id_rsa*, credentials files, keystores),
   generic secret assignments as warnings. Respects .gitignore plus
   .ghostgateignore.
2. **Diff** — local tree vs remote tree by real git blob hashes:
   added / changed / deleted / unchanged, listed before anything moves.
3. **Rehearsed push** — blobs + tree + commit are built server-side
   WITHOUT moving the ref; landing is one ref update to the rehearsed
   commit; read-back compares the full remote tree hash-for-hash;
   landed commit must equal rehearsed commit.
4. **Journal + rollback** — every push written to a hash-chained
   SQLite journal (~/.ghost-gate.db): repo, branch, folder, commits
   before/after, delta counts, scan verdict. Rollback resets the ref
   to the journal's previous commit.

## Round 1 additions
- **Divergence guard** — journal remembers the last remote tree seen
  per repo+branch; if the remote moved outside Gate, stop and show
  the remote delta first (the README-clobber lesson, Oct 2026).
- **Repo guardrails** — per-repo rules file (.ghostgate.json):
  forbidden remotes, must-stay-private (checked before AND after),
  protected branches, required files (e.g. LICENSE).
- **Project gate command** — each folder may name a check command;
  the push cannot start until it exits green (GhostIDE DOM-stub rule).
- **Tree hygiene** — .gitignore respected, >50 MB files flagged
  before GitHub rejects the push, filename classes blocked outright.
- **Batch sweep mode** — queue several folders, one verdict board.

## Round 2 additions
- **Deep scan inside archives** — .apk/.zip/.tar.gz contents scanned
  for the same shapes (a key baked into a shipped binary is the worst
  leak). [Ghost Verify's APK reading is the donor.]
- **History sweep** — audit the remote repo's PAST commits for the
  same patterns; a secret deleted today is still public in history.
  Output names which credential needs rotating.
- **Absorb** — if remote moved but changed-file sets do not overlap,
  rebase the rehearsed commit onto the new remote tree and proceed;
  only true overlap blocks.
- **Auditable overrides** — a finding is overridden by fingerprint +
  written reason, recorded in the journal. Never per-pattern.
- **Canary self-test** — fixture tree with planted fake secrets
  (including providers' documented example keys) + one inside a zip;
  --selftest must catch all before Gate trusts itself.

## Round 3 additions
- **Watch-strings** — literal strings that stop the push on sight
  (Ryan's mailing address, do-not-publish phone numbers), scanned
  like credentials in text and archives.
- **Observe-first onboarding** — first run on an unmanaged repo is
  observe-only; Gate drafts a proposed guardrails file and waits for
  Ryan's approval. Rules are proposed, never self-granted.
- **Last-second re-check** — delta files re-hashed right before the
  ref moves; any change since rehearsal aborts and re-rehearses.
- **Commit messages as public copy** — drafted from the delta
  (version-named when a version file changed), linted against Ryan's
  copy rules (no em dashes). Atomic commits replace per-file noise.
- **Post-push pull-back** — key changed files fetched from the raw
  public URL and hash-matched, proving the world sees the push.
- **Authority boundary** — on a version bump Gate PREPARES a release
  draft (notes from the journal + push note) and stops. A push is
  not a release; Gate never creates one.

## Posture
- Gate never stores a GitHub token; it uses the environment token or
  the workspace connector route, same as the other tools.
- Exit codes: 0 clean/done, 1 blocked or no-match, 2 usage/IO error.

## Shipped
- **v1.0 (Nov 18, 2026)** — core four + hygiene, watch-strings,
  divergence guard (hard stop), protected branches,
  must-stay-private. Proven end-to-end on a scratch repo (push,
  diff, push, rollback) and dogfooded for this repo's first push.
- **v1.1 (Nov 18, 2026)** — everything else in this spec: archive
  deep-scan, auditable overrides, project gate commands, absorb
  (non-overlap proceeds, true overlap stops), last-second re-check,
  version-drafted commit messages, post-push pull-back, release
  draft preparation, history sweep, observe-first onboarding,
  batch sweeps. Each proven live against test repos before the
  1.1 dogfood push.
