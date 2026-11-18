#!/usr/bin/env python3
"""Ghost Gate 1.0 - one gate between a local folder and GitHub.

Nothing reaches GitHub un-scanned, un-diffed, or un-recorded:
  scan     credential-shaped patterns, blocked filename classes and
           watch-strings are checked before anything moves
  diff     local tree vs remote tree, compared by git blob hashes
  push     the commit is rehearsed server-side (blobs + tree + commit
           built, ref untouched), landed with one ref update, then
           read back hash-for-hash before it is called done
  journal  every push lands in a hash-chained SQLite journal, and a
           rollback resets the branch to the journal's previous commit

Pure Python standard library. The GitHub credential is never stored:
Gate uses GITHUB_TOKEN from the environment when present, otherwise
the workspace GitHub connector route.

Usage:
  python3 ghost_gate.py                      (GUI)
  python3 ghost_gate.py --scan FOLDER
  python3 ghost_gate.py --diff FOLDER owner/repo [branch]
  python3 ghost_gate.py --push FOLDER owner/repo [branch] [--message M]
  python3 ghost_gate.py --rollback owner/repo [branch]
  python3 ghost_gate.py --journal [N]
  python3 ghost_gate.py --init-repo NAME [--public]
  python3 ghost_gate.py --selftest
Exit codes: 0 ok, 1 blocked / mismatch, 2 usage or IO error.
"""

import base64
import fnmatch
import hashlib
import json
import os
import queue
import re
import sqlite3
import sys
import threading
import urllib.parse

VERSION = "1.0"
DB_PATH = os.path.expanduser("~/.ghost-gate.db")
GH2_PATH = os.path.expanduser(
    "~/workspace/custom-connectors/custom.legacy-github/bin/gh2.py")
MAX_SCAN_BYTES = 2_000_000          # per-file content scan cap
WARN_SIZE = 50 * 1024 * 1024        # GitHub warns past 50 MB
BLOCK_SIZE = 100 * 1024 * 1024      # GitHub refuses past 100 MB

BG = "#121214"
SURFACE = "#242428"
OVERLAY = "#17171A"
ACCENT = "#6716F3"
TEXT1 = "#F2F2F5"
TEXT2 = "#9A9AA3"
GOOD = "#3FB96B"
BAD = "#E5534B"


class GateError(Exception):
    pass


# --------------------------------------------------------------------------
# Tree walking, ignore rules, blob hashing
# --------------------------------------------------------------------------

def blob_sha(data):
    """The git blob SHA-1 of a byte string."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def load_ignore_patterns(folder):
    pats = []
    for name in (".gitignore", ".ghostgateignore"):
        p = os.path.join(folder, name)
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.strip()
                    if line and not line.startswith("#"):
                        pats.append(line)
    return pats


def is_ignored(rel, is_dir, patterns):
    """A small, honest subset of gitignore: basename globs, path globs,
    dir-only patterns (trailing /), root-anchored (leading /), and
    negation (!). Last matching pattern wins."""
    ignored = False
    parts = rel.split("/")
    for pat in patterns:
        neg = pat.startswith("!")
        p = pat[1:] if neg else pat
        dir_only = p.endswith("/")
        p = p.strip("/")
        if not p:
            continue
        if dir_only and not is_dir:
            continue
        if "/" in p:
            hit = fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/**")
        else:
            hit = any(fnmatch.fnmatch(part, p) for part in parts)
        if hit:
            ignored = not neg
    return ignored


def local_tree(folder):
    """{relpath: {sha, size, mode}} for every file Gate would push."""
    patterns = load_ignore_patterns(folder)
    out = {}
    for root, dirs, files in os.walk(folder):
        rel_root = os.path.relpath(root, folder)
        rel_root = "" if rel_root == "." else rel_root.replace(os.sep, "/")
        dirs[:] = [d for d in sorted(dirs)
                   if d != ".git" and not is_ignored(
                       (rel_root + "/" + d).strip("/"), True, patterns)]
        for name in sorted(files):
            rel = (rel_root + "/" + name).strip("/")
            if is_ignored(rel, False, patterns):
                continue
            full = os.path.join(root, name)
            with open(full, "rb") as fh:
                data = fh.read()
            mode = "100755" if os.access(full, os.X_OK) else "100644"
            out[rel] = {"sha": blob_sha(data), "size": len(data),
                        "mode": mode}
    return out


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

BLOCK_PATTERNS = [
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("github-fine-grained-token",
     re.compile(r"github_pat_[A-Za-z0-9_]{40,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("stripe-secret", re.compile(r"[sr]k_live_[A-Za-z0-9]{16,}")),
    ("stripe-webhook-secret", re.compile(r"whsec_[A-Za-z0-9]{16,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("gitlab-token", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("private-key-block",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
WARN_PATTERNS = [
    ("secret-assignment", re.compile(
        r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|"
        r"auth[_-]?token|password|passwd|secret)\s*[:=]\s*"
        r"[\"'][^\"'\n]{8,}[\"']")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}")),
]
BLOCK_BASENAMES = {
    ".env", ".netrc", "credentials", "credentials.json",
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
}
BLOCK_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".jks")
WARN_BASENAMES = {".npmrc", ".env.example", ".env.sample", ".env.template"}


def filename_verdict(rel):
    base = os.path.basename(rel).lower()
    if base in BLOCK_BASENAMES or base.startswith("id_rsa") \
            or base.startswith("id_ed25519") \
            or base == ".env" or (base.startswith(".env.")
                                  and base not in WARN_BASENAMES) \
            or base.startswith("service-account") \
            or base.endswith("-service-account.json"):
        return "block"
    if base.endswith(BLOCK_SUFFIXES) and not base.endswith(".pub"):
        return "block"
    if base in WARN_BASENAMES:
        return "warn"
    return None


def load_rules(folder):
    p = os.path.join(folder, ".ghostgate.json")
    if os.path.isfile(p):
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def scan_tree(folder, tree, rules):
    """Findings: {path, line, kind, severity}. Matched text is never
    stored or printed; a finding names the shape, not the secret."""
    findings = []
    watch = [w for w in rules.get("watch_strings", []) if w]
    for rel in sorted(tree):
        info = tree[rel]
        verdict = filename_verdict(rel)
        if verdict:
            findings.append({"path": rel, "line": 0,
                             "kind": "filename-class",
                             "severity": verdict})
        if info["size"] > BLOCK_SIZE:
            findings.append({"path": rel, "line": 0, "kind": "oversize",
                             "severity": "block"})
        elif info["size"] > WARN_SIZE:
            findings.append({"path": rel, "line": 0, "kind": "oversize",
                             "severity": "warn"})
        if info["size"] > MAX_SCAN_BYTES:
            continue
        full = os.path.join(folder, rel.replace("/", os.sep))
        with open(full, "rb") as fh:
            raw = fh.read()
        if b"\0" in raw[:8192]:
            continue  # binary: filename rules still applied above
        text = raw.decode("utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, rx in BLOCK_PATTERNS:
                if rx.search(line):
                    findings.append({"path": rel, "line": lineno,
                                     "kind": name, "severity": "block"})
            for name, rx in WARN_PATTERNS:
                if rx.search(line):
                    findings.append({"path": rel, "line": lineno,
                                     "kind": name, "severity": "warn"})
            for idx, w in enumerate(watch):
                if w in line:
                    findings.append({"path": rel, "line": lineno,
                                     "kind": "watch-string #%d" % (idx + 1),
                                     "severity": "block"})
    return findings


def blocks(findings):
    return [f for f in findings if f["severity"] == "block"]


def warns(findings):
    return [f for f in findings if f["severity"] == "warn"]


# --------------------------------------------------------------------------
# Journal (hash-chained, like the Ghost Verify ledger)
# --------------------------------------------------------------------------

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries ("
        "id INTEGER PRIMARY KEY, ts TEXT, kind TEXT, repo TEXT, "
        "branch TEXT, folder TEXT, prev_commit TEXT, new_commit TEXT, "
        "tree_sha TEXT, added INT, changed INT, deleted INT, "
        "blocks INT, warns INT, prev_hash TEXT, entry_hash TEXT)")
    return conn


def _now():
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def journal_add(kind, repo, branch, folder, prev_commit, new_commit,
                tree_sha, added, changed, deleted, nblocks, nwarns):
    conn = _db()
    row = conn.execute(
        "SELECT entry_hash FROM entries ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row[0] if row else ""
    ts = _now()
    canon = "|".join([prev_hash, ts, kind, repo, branch,
                      new_commit or "", tree_sha or ""])
    entry_hash = hashlib.sha256(canon.encode()).hexdigest()
    conn.execute(
        "INSERT INTO entries (ts, kind, repo, branch, folder, "
        "prev_commit, new_commit, tree_sha, added, changed, deleted, "
        "blocks, warns, prev_hash, entry_hash) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, kind, repo, branch, folder, prev_commit, new_commit,
         tree_sha, added, changed, deleted, nblocks, nwarns,
         prev_hash, entry_hash))
    conn.commit()
    conn.close()
    return entry_hash


def journal_verify():
    conn = _db()
    rows = conn.execute(
        "SELECT id, ts, kind, repo, branch, new_commit, tree_sha, "
        "prev_hash, entry_hash FROM entries ORDER BY id").fetchall()
    conn.close()
    prev = ""
    for r in rows:
        canon = "|".join([prev, r[1], r[2], r[3], r[4], r[5] or "",
                          r[6] or ""])
        if hashlib.sha256(canon.encode()).hexdigest() != r[8] or r[7] != prev:
            return False, len(rows), r[0]
        prev = r[8]
    return True, len(rows), None


def journal_recent(limit=20):
    conn = _db()
    rows = conn.execute(
        "SELECT id, ts, kind, repo, branch, prev_commit, new_commit, "
        "added, changed, deleted, blocks, warns FROM entries "
        "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def journal_last_for(repo, branch):
    conn = _db()
    row = conn.execute(
        "SELECT id, ts, kind, prev_commit, new_commit FROM entries "
        "WHERE repo = ? AND branch = ? ORDER BY id DESC LIMIT 1",
        (repo, branch)).fetchone()
    conn.close()
    return row


# --------------------------------------------------------------------------
# GitHub client (env token, else the workspace connector route)
# --------------------------------------------------------------------------

class GH:
    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN")
        self._gh2 = None

    def call(self, method, path, data=None):
        if self.token:
            import urllib.request
            import urllib.error
            req = urllib.request.Request(
                "https://api.github.com" + path, method=method)
            body = None
            if data is not None:
                body = json.dumps(data).encode()
                req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", "Bearer " + self.token)
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            req.add_header("User-Agent", "GhostGate/" + VERSION)
            try:
                with urllib.request.urlopen(req, data=body,
                                            timeout=60) as resp:
                    raw = resp.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:400]
                raise GateError("GitHub API %d on %s %s: %s"
                                % (e.code, method, path, detail))
        if self._gh2 is None:
            import importlib.util
            spec = importlib.util.spec_from_file_location("gh2", GH2_PATH)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self._gh2 = mod
        try:
            return self._gh2.call(method, path, data)
        except BaseException as e:  # gh2 raises SystemExit on API errors
            raise GateError(str(e))

    def repo_info(self, repo):
        return self.call("GET", "/repos/" + repo)

    def create_repo(self, name, private=True):
        return self.call("POST", "/user/repos",
                         {"name": name, "private": private})

    def get_ref(self, repo, branch):
        try:
            r = self.call("GET", "/repos/%s/git/ref/heads/%s"
                          % (repo, urllib.parse.quote(branch, safe="/")))
            return r["object"]["sha"]
        except GateError as e:
            # 404: no such ref. 409: "Git Repository is empty."
            if "404" in str(e) or "409" in str(e):
                return None
            raise

    def commit_tree_sha(self, repo, commit_sha):
        r = self.call("GET", "/repos/%s/git/commits/%s" % (repo, commit_sha))
        return r["tree"]["sha"]

    def tree_map(self, repo, tree_sha):
        r = self.call("GET", "/repos/%s/git/trees/%s?recursive=1"
                      % (repo, tree_sha))
        if r.get("truncated"):
            raise GateError("remote tree is truncated; repo too large "
                            "for a single recursive read")
        return {e["path"]: e["sha"] for e in r.get("tree", [])
                if e["type"] == "blob"}

    def remote_state(self, repo, branch):
        """(head_commit, tree_sha, {path: sha}) or (None, None, {})."""
        head = self.get_ref(repo, branch)
        if head is None:
            return None, None, {}
        tree_sha = self.commit_tree_sha(repo, head)
        return head, tree_sha, self.tree_map(repo, tree_sha)

    def create_blob(self, repo, data):
        r = self.call("POST", "/repos/%s/git/blobs" % repo,
                      {"content": base64.b64encode(data).decode(),
                       "encoding": "base64"})
        return r["sha"]

    def create_tree(self, repo, base_tree, entries):
        payload = {"tree": entries}
        if base_tree:
            payload["base_tree"] = base_tree
        r = self.call("POST", "/repos/%s/git/trees" % repo, payload)
        return r["sha"]

    def create_commit(self, repo, message, tree_sha, parents):
        r = self.call("POST", "/repos/%s/git/commits" % repo,
                      {"message": message, "tree": tree_sha,
                       "parents": parents})
        return r["sha"]

    def put_content(self, repo, path, message, data, branch):
        """Contents API write; the only way to make the very first
        commit in an empty repository."""
        return self.call(
            "PUT", "/repos/%s/contents/%s"
            % (repo, urllib.parse.quote(path, safe="/")),
            {"message": message,
             "content": base64.b64encode(data).decode(),
             "branch": branch})

    def update_ref(self, repo, branch, sha, force=False):
        return self.call(
            "PATCH", "/repos/%s/git/refs/heads/%s"
            % (repo, urllib.parse.quote(branch, safe="/")),
            {"sha": sha, "force": force})


# --------------------------------------------------------------------------
# Diff, rehearse, land, rollback
# --------------------------------------------------------------------------

def diff_trees(local, remote):
    added = sorted(p for p in local if p not in remote)
    deleted = sorted(p for p in remote if p not in local)
    changed = sorted(p for p in local
                     if p in remote and local[p]["sha"] != remote[p])
    unchanged = sum(1 for p in local
                    if p in remote and local[p]["sha"] == remote[p])
    return {"added": added, "changed": changed, "deleted": deleted,
            "unchanged": unchanged}


def rehearse(gh, repo, folder, local, delta, base_tree, head, message):
    """Build blobs + tree + commit server-side. The ref does not move.
    Returns (commit_sha, tree_sha)."""
    entries = []
    for rel in delta["added"] + delta["changed"]:
        full = os.path.join(folder, rel.replace("/", os.sep))
        with open(full, "rb") as fh:
            data = fh.read()
        sha = gh.create_blob(repo, data)
        if sha != local[rel]["sha"]:
            raise GateError("blob read-back mismatch for " + rel)
        entries.append({"path": rel, "mode": local[rel]["mode"],
                        "type": "blob", "sha": sha})
    for rel in delta["deleted"]:
        entries.append({"path": rel, "mode": "100644", "type": "blob",
                        "sha": None})
    tree_sha = gh.create_tree(repo, base_tree, entries)
    parents = [head] if head else []
    commit_sha = gh.create_commit(repo, message, tree_sha, parents)
    return commit_sha, tree_sha


def push_flow(folder, repo, branch="main", message=None, gh=None,
              progress=None):
    """The full gate. Returns a summary dict; raises GateError when the
    gate stops the push."""
    def note(msg):
        if progress:
            progress(msg)
    gh = gh or GH()
    rules = load_rules(folder)
    if branch in rules.get("protected_branches", []):
        raise GateError("branch %s is protected in .ghostgate.json"
                        % branch)
    note("Walking local tree...")
    local = local_tree(folder)
    note("Scanning %d files..." % len(local))
    findings = scan_tree(folder, local, rules)
    bl = blocks(findings)
    if bl:
        raise GateError("scan blocked the push: %d blocking finding(s)"
                        % len(bl))
    info = gh.repo_info(repo)
    if rules.get("must_stay_private") and not info.get("private"):
        raise GateError("guardrail: %s must stay private but is public"
                        % repo)
    head, base_tree, remote = gh.remote_state(repo, branch)
    last = journal_last_for(repo, branch)
    if last and head and last[4] and head != last[4]:
        raise GateError(
            "divergence guard: %s@%s moved outside Ghost Gate since "
            "the last gated push (journal head %s, remote head %s). "
            "Review the remote before pushing."
            % (repo, branch, last[4][:8], head[:8]))
    delta = diff_trees(local, remote)
    if not (delta["added"] or delta["changed"] or delta["deleted"]):
        return {"status": "clean", "findings": findings, "delta": delta,
                "head": head}
    if message is None:
        message = ("Ghost Gate push: %d added, %d changed, %d deleted"
                   % (len(delta["added"]), len(delta["changed"]),
                      len(delta["deleted"])))
    if "—" in message:
        raise GateError("commit message contains an em dash; "
                        "public copy rule")
    orig_head = head
    boot_count = 0
    if head is None:
        # The Git Data API refuses an empty repository ("Git
        # Repository is empty"), so the first file lands through the
        # Contents API and the rest is rehearsed on top of it.
        first = sorted(local)[0]
        note("Empty repo: bootstrapping with %s..." % first)
        full = os.path.join(folder, first.replace("/", os.sep))
        with open(full, "rb") as fh:
            boot = gh.put_content(repo, first,
                                  message + " (bootstrap)", fh.read(),
                                  branch)
        head = boot["commit"]["sha"]
        boot_count = 1
        head, base_tree, remote = gh.remote_state(repo, branch)
        delta = diff_trees(local, remote)
        if not (delta["added"] or delta["changed"] or delta["deleted"]):
            entry_hash = journal_add(
                "push", repo, branch, folder, None, head, base_tree,
                1, 0, 0, 0, len(warns(findings)))
            return {"status": "pushed", "findings": findings,
                    "delta": delta, "head": head, "tree": base_tree,
                    "journal": entry_hash}
    note("Rehearsing commit (%d added, %d changed, %d deleted)..."
         % (len(delta["added"]), len(delta["changed"]),
            len(delta["deleted"])))
    commit_sha, tree_sha = rehearse(gh, repo, folder, local, delta,
                                    base_tree, head, message)
    note("Landing rehearsed commit %s..." % commit_sha[:8])
    gh.update_ref(repo, branch, commit_sha)
    new_head, _t, new_remote = gh.remote_state(repo, branch)
    local_map = {p: v["sha"] for p, v in local.items()}
    if new_head != commit_sha:
        raise GateError("read-back failed: branch head %s is not the "
                        "rehearsed commit %s"
                        % (new_head, commit_sha))
    if new_remote != local_map:
        raise GateError("read-back failed: remote tree does not match "
                        "the local tree hash-for-hash")
    entry_hash = journal_add("push", repo, branch, folder, orig_head,
                             commit_sha, tree_sha,
                             len(delta["added"]) + boot_count,
                             len(delta["changed"]), len(delta["deleted"]),
                             0, len(warns(findings)))
    note("Landed and verified.")
    return {"status": "pushed", "findings": findings, "delta": delta,
            "head": commit_sha, "tree": tree_sha, "journal": entry_hash}


def rollback(repo, branch="main", gh=None):
    gh = gh or GH()
    last = journal_last_for(repo, branch)
    if not last:
        raise GateError("no journal entry for %s@%s" % (repo, branch))
    prev_commit = last[3]
    if not prev_commit:
        raise GateError("the last gated push created this branch; "
                        "there is no earlier commit to roll back to")
    head, _t, _m = gh.remote_state(repo, branch)
    gh.update_ref(repo, branch, prev_commit, force=True)
    new_head, _t2, _m2 = gh.remote_state(repo, branch)
    if new_head != prev_commit:
        raise GateError("rollback read-back failed: head is %s, "
                        "expected %s" % (new_head, prev_commit))
    journal_add("rollback", repo, branch, "", head, prev_commit, None,
                0, 0, 0, 0, 0)
    return {"status": "rolled-back", "from": head, "to": prev_commit}


# --------------------------------------------------------------------------
# Self-test (canary fixtures: planted fakes must all be caught)
# --------------------------------------------------------------------------

def selftest():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok = ok and cond

    root = tempfile.mkdtemp(prefix="ghostgate-selftest-")
    clean = os.path.join(root, "clean")
    bad = os.path.join(root, "bad")
    os.makedirs(clean)
    os.makedirs(bad)
    with open(os.path.join(clean, "hello.txt"), "w") as fh:
        fh.write("hello world\n")
    f = scan_tree(clean, local_tree(clean), {})
    check("clean tree has no findings", f == [])
    with open(os.path.join(bad, "tokens.txt"), "w") as fh:
        fh.write("key = ghp_" + "A" * 36 + "\n")
        fh.write("aws example: " + "AKIA" + "IOSFODNN7EXAMPLE\n")
    with open(os.path.join(bad, ".env"), "w") as fh:
        fh.write("SOME=value\n")
    with open(os.path.join(bad, ".ghostgate.json"), "w") as fh:
        json.dump({"watch_strings": ["999 TEST LANE"]}, fh)
    with open(os.path.join(bad, "watched.txt"), "w") as fh:
        fh.write("ship it to 999 TEST LANE please\n")
    with open(os.path.join(bad, ".gitignore"), "w") as fh:
        fh.write("skip.txt\n")
    with open(os.path.join(bad, "skip.txt"), "w") as fh:
        fh.write("hidden ghp_" + "B" * 36 + "\n")
    tree = local_tree(bad)
    check("ignored file is not in the tree", "skip.txt" not in tree)
    f = scan_tree(bad, tree, load_rules(bad))
    kinds = {(x["path"], x["kind"]) for x in blocks(f)}
    check("github token caught",
          ("tokens.txt", "github-token") in kinds)
    check("aws example key caught",
          ("tokens.txt", "aws-access-key") in kinds)
    check(".env filename class caught",
          any(p == ".env" for p, _k in kinds))
    check("watch-string caught",
          any(k.startswith("watch-string") for _p, k in kinds))
    check("ignored file never scanned",
          all(x["path"] != "skip.txt" for x in f))
    okc, count, bad_id = journal_verify()
    check("journal chain verifies (%d entries)" % count,
          okc or count == 0)
    print("SELFTEST " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _print_findings(findings):
    for f in findings:
        loc = f["path"] + ((":%d" % f["line"]) if f["line"] else "")
        print("  [%s] %s (%s)" % (f["severity"].upper(), loc, f["kind"]))


def _print_delta(delta):
    for p in delta["added"]:
        print("  + " + p)
    for p in delta["changed"]:
        print("  ~ " + p)
    for p in delta["deleted"]:
        print("  - " + p)
    print("  = %d unchanged" % delta["unchanged"])


def cli(argv):
    try:
        if argv[0] == "--selftest":
            return selftest()
        if argv[0] == "--scan" and len(argv) == 2:
            folder = argv[1]
            tree = local_tree(folder)
            findings = scan_tree(folder, tree, load_rules(folder))
            print("Scanned %d files in %s" % (len(tree), folder))
            _print_findings(findings)
            print("%d blocking, %d warning(s)"
                  % (len(blocks(findings)), len(warns(findings))))
            return 1 if blocks(findings) else 0
        if argv[0] == "--init-repo" and len(argv) >= 2:
            private = "--public" not in argv
            r = GH().create_repo(argv[1], private=private)
            print("Created %s (%s)" % (r["full_name"],
                                       "private" if private else "public"))
            return 0
        if argv[0] == "--journal":
            n = int(argv[1]) if len(argv) > 1 else 20
            okc, count, bad_id = journal_verify()
            print("Journal chain: %s (%d entries%s)"
                  % ("INTACT" if okc else "BROKEN at entry %s" % bad_id,
                     count, "" if okc else ""))
            for row in journal_recent(n):
                print("  #%d %s %s %s@%s +%d ~%d -%d -> %s"
                      % (row[0], row[1], row[2], row[3], row[4],
                         row[7], row[8], row[9],
                         (row[6] or "")[:8]))
            return 0 if okc else 1
        if argv[0] == "--diff" and len(argv) >= 3:
            folder, repo = argv[1], argv[2]
            branch = argv[3] if len(argv) > 3 else "main"
            gh = GH()
            _h, _t, remote = gh.remote_state(repo, branch)
            delta = diff_trees(local_tree(folder), remote)
            _print_delta(delta)
            return 0
        if argv[0] == "--push" and len(argv) >= 3:
            folder, repo = argv[1], argv[2]
            rest = argv[3:]
            branch = "main"
            message = None
            if rest and not rest[0].startswith("--"):
                branch = rest[0]
                rest = rest[1:]
            if "--message" in rest:
                message = rest[rest.index("--message") + 1]
            result = push_flow(folder, repo, branch, message,
                               progress=lambda m: print("  " + m))
            if result["status"] == "clean":
                print("Nothing to push; remote already matches.")
            else:
                print("Pushed %s@%s -> %s"
                      % (repo, branch, result["head"][:12]))
            wn = warns(result["findings"])
            if wn:
                print("Warnings:")
                _print_findings(wn)
            return 0
        if argv[0] == "--rollback" and len(argv) >= 2:
            repo = argv[1]
            branch = argv[2] if len(argv) > 2 else "main"
            r = rollback(repo, branch)
            print("Rolled back %s@%s: %s -> %s"
                  % (repo, branch, (r["from"] or "")[:12],
                     r["to"][:12]))
            return 0
    except GateError as e:
        print("GATE STOPPED: " + str(e))
        return 1
    except (OSError, json.JSONDecodeError) as e:
        print("ERROR: " + str(e))
        return 2
    print(__doc__)
    return 2


# --------------------------------------------------------------------------
# GUI (PyUI Builder style: generated layout, handlers as methods)
# --------------------------------------------------------------------------

def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    class GateApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Ghost Gate " + VERSION + " - scan, diff, push")
            self.geometry("760x680")
            self.minsize(640, 560)
            self.configure(bg=BG)
            self.events = queue.Queue()
            self._build()
            self.after(60, self.poll_events)

        def _build(self):
            style = ttk.Style(self)
            style.theme_use("clam")
            style.configure("TEntry", fieldbackground=OVERLAY,
                            foreground=TEXT1, insertcolor=TEXT1)
            hdr = tk.Frame(self, bg=BG)
            hdr.pack(fill="x", padx=16, pady=(14, 2))
            tk.Label(hdr, text="GHOST GATE", bg=BG, fg=TEXT1,
                     font=("TkDefaultFont", 16, "bold")).pack(side="left")
            tk.Label(hdr, text=" " + VERSION + " ", bg=ACCENT, fg="white",
                     font=("TkDefaultFont", 9, "bold")).pack(side="left",
                                                              padx=8)
            tk.Label(hdr, text="Ghost Developer Studio", bg=BG,
                     fg=TEXT2).pack(side="right")
            tk.Frame(self, bg=ACCENT, height=2).pack(fill="x", padx=16,
                                                    pady=(4, 10))

            form = tk.Frame(self, bg=BG)
            form.pack(fill="x", padx=16)
            self.folder = tk.StringVar()
            self.repo = tk.StringVar()
            self.branch = tk.StringVar(value="main")
            self.message = tk.StringVar()
            rows = [("Folder", self.folder, True),
                    ("Repo (owner/name)", self.repo, False),
                    ("Branch", self.branch, False),
                    ("Commit message (optional)", self.message, False)]
            for i, (label, var, browse) in enumerate(rows):
                tk.Label(form, text=label, bg=BG, fg=TEXT2).grid(
                    row=i, column=0, sticky="w", pady=3)
                tk.Entry(form, textvariable=var, bg=OVERLAY, fg=TEXT1,
                         insertbackground=TEXT1, relief="flat").grid(
                    row=i, column=1, sticky="ew", pady=3, padx=(8, 0))
                if browse:
                    tk.Button(form, text="Browse", bg=SURFACE, fg=TEXT1,
                              relief="flat",
                              command=self.on_browse).grid(
                        row=i, column=2, padx=(8, 0))
            form.columnconfigure(1, weight=1)

            btns = tk.Frame(self, bg=BG)
            btns.pack(fill="x", padx=16, pady=10)
            for text, cmd in [("Scan", self.on_scan),
                              ("Diff", self.on_diff),
                              ("Push through the gate", self.on_push),
                              ("Journal", self.on_journal),
                              ("Rollback", self.on_rollback)]:
                tk.Button(btns, text=text, bg=SURFACE, fg=TEXT1,
                          relief="flat", padx=10, pady=4,
                          command=cmd).pack(side="left", padx=(0, 8))
            self.status = tk.Label(self, text="Ready.", bg=BG, fg=TEXT2,
                                   anchor="w")
            self.status.pack(fill="x", padx=16)
            self.out = tk.Text(self, bg=OVERLAY, fg=TEXT1, relief="flat",
                               insertbackground=TEXT1, wrap="word",
                               font=("TkFixedFont", 10))
            self.out.pack(fill="both", expand=True, padx=16,
                          pady=(6, 14))

        # -- helpers ------------------------------------------------------
        def say(self, text):
            self.out.insert("end", text + "\n")
            self.out.see("end")

        def set_status(self, text):
            self.status.config(text=text)

        def inputs(self):
            folder = self.folder.get().strip()
            repo = self.repo.get().strip()
            branch = self.branch.get().strip() or "main"
            if not folder or not os.path.isdir(folder):
                raise GateError("pick a folder first")
            return folder, repo, branch

        def run_worker(self, fn):
            def work():
                try:
                    self.events.put(("result", fn()))
                except GateError as e:
                    self.events.put(("error", str(e)))
                except Exception as e:  # surface, never swallow
                    self.events.put(("error", "%s: %s"
                                     % (type(e).__name__, e)))
            threading.Thread(target=work, daemon=True).start()

        def poll_events(self):
            try:
                while True:
                    kind, payload = self.events.get_nowait()
                    if kind == "note":
                        self.set_status(payload)
                    elif kind == "result":
                        self.say(payload)
                        self.set_status("Done.")
                    elif kind == "error":
                        self.say("GATE STOPPED: " + payload)
                        self.set_status("Stopped.")
            except queue.Empty:
                pass
            self.after(60, self.poll_events)

        # -- actions ------------------------------------------------------
        def on_browse(self):
            path = filedialog.askdirectory()
            if path:
                self.folder.set(path)

        def on_scan(self):
            try:
                folder, _r, _b = self.inputs()
            except GateError as e:
                messagebox.showerror("Ghost Gate", str(e))
                return

            def fn():
                tree = local_tree(folder)
                findings = scan_tree(folder, tree, load_rules(folder))
                lines = ["Scanned %d files." % len(tree)]
                for f in findings:
                    loc = f["path"] + ((":%d" % f["line"])
                                       if f["line"] else "")
                    lines.append("  [%s] %s (%s)"
                                 % (f["severity"].upper(), loc, f["kind"]))
                lines.append("%d blocking, %d warning(s)."
                             % (len(blocks(findings)),
                                len(warns(findings))))
                return "\n".join(lines)
            self.run_worker(fn)

        def on_diff(self):
            try:
                folder, repo, branch = self.inputs()
                if not repo:
                    raise GateError("enter a repo (owner/name)")
            except GateError as e:
                messagebox.showerror("Ghost Gate", str(e))
                return

            def fn():
                gh = GH()
                _h, _t, remote = gh.remote_state(repo, branch)
                d = diff_trees(local_tree(folder), remote)
                lines = ["Diff vs %s@%s:" % (repo, branch)]
                lines += ["  + " + p for p in d["added"]]
                lines += ["  ~ " + p for p in d["changed"]]
                lines += ["  - " + p for p in d["deleted"]]
                lines.append("  = %d unchanged" % d["unchanged"])
                return "\n".join(lines)
            self.run_worker(fn)

        def on_push(self):
            try:
                folder, repo, branch = self.inputs()
                if not repo:
                    raise GateError("enter a repo (owner/name)")
            except GateError as e:
                messagebox.showerror("Ghost Gate", str(e))
                return
            msg = self.message.get().strip() or None

            def fn():
                result = push_flow(
                    folder, repo, branch, msg,
                    progress=lambda m: self.events.put(("note", m)))
                if result["status"] == "clean":
                    return "Nothing to push; remote already matches."
                d = result["delta"]
                return ("Pushed %s@%s -> %s\n  +%d ~%d -%d, read-back "
                        "verified hash-for-hash."
                        % (repo, branch, result["head"][:12],
                           len(d["added"]), len(d["changed"]),
                           len(d["deleted"])))
            self.run_worker(fn)

        def on_journal(self):
            def fn():
                okc, count, bad_id = journal_verify()
                lines = ["Journal chain: %s (%d entries)"
                         % ("INTACT" if okc
                            else "BROKEN at entry %s" % bad_id, count)]
                for row in journal_recent(20):
                    lines.append(
                        "  #%d %s %s %s@%s +%d ~%d -%d -> %s"
                        % (row[0], row[1], row[2], row[3], row[4],
                           row[7], row[8], row[9], (row[6] or "")[:8]))
                return "\n".join(lines)
            self.run_worker(fn)

        def on_rollback(self):
            try:
                _f, repo, branch = self.inputs()
                if not repo:
                    raise GateError("enter a repo (owner/name)")
            except GateError as e:
                messagebox.showerror("Ghost Gate", str(e))
                return
            if not messagebox.askyesno(
                    "Ghost Gate",
                    "Roll back %s@%s to the previous gated commit?"
                    % (repo, branch)):
                return

            def fn():
                r = rollback(repo, branch)
                return "Rolled back: %s -> %s" % ((r["from"] or "")[:12],
                                                  r["to"][:12])
            self.run_worker(fn)

    GateApp().mainloop()


def main():
    argv = sys.argv[1:]
    if argv:
        return cli(argv)
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
