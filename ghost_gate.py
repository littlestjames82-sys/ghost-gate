#!/usr/bin/env python3
"""Ghost Gate 1.1 - one gate between a local folder and GitHub.

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
  python3 ghost_gate.py --history owner/repo [branch]
  python3 ghost_gate.py --observe FOLDER owner/repo
  python3 ghost_gate.py --batch BATCHFILE
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

VERSION = "1.1"
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


def _finding(path, line, kind, severity, line_text=None):
    """A finding names the shape, never the secret. Its fingerprint is
    a hash of path + kind + the flagged line's hash, so an override
    can name one exact finding without storing what it matched."""
    basis = line_text if line_text is not None else "filename"
    digest = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()
    fp = hashlib.sha256(
        ("%s|%s|%s" % (path, kind, digest)).encode()).hexdigest()
    return {"path": path, "line": line, "kind": kind,
            "severity": severity, "fp": fp}


def _scan_text(findings, path, text, watch):
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, rx in BLOCK_PATTERNS:
            if rx.search(line):
                findings.append(_finding(path, lineno, name, "block",
                                         line))
        for name, rx in WARN_PATTERNS:
            if rx.search(line):
                findings.append(_finding(path, lineno, name, "warn",
                                         line))
        for idx, w in enumerate(watch):
            if w in line:
                findings.append(_finding(
                    path, lineno, "watch-string #%d" % (idx + 1),
                    "block", line))


ARCHIVE_SUFFIXES = (".zip", ".apk", ".jar", ".tar.gz", ".tgz")


def _scan_archive(findings, rel, full, watch):
    """Deep scan: a key baked into a shipped archive is the worst
    leak, so zip-family and tar entries are opened and their text
    entries scanned with the same shapes. Entry paths are reported
    as archive.zip!entry."""
    import io
    import tarfile
    import zipfile
    try:
        if rel.lower().endswith((".zip", ".apk", ".jar")):
            with zipfile.ZipFile(full) as zf:
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    verdict = filename_verdict(name)
                    if verdict:
                        findings.append(_finding(
                            rel + "!" + name, 0, "filename-class",
                            verdict))
                    try:
                        raw = zf.read(name)
                    except Exception:
                        continue
                    if len(raw) > MAX_SCAN_BYTES or b"\0" in raw[:8192]:
                        continue
                    _scan_text(findings, rel + "!" + name,
                               raw.decode("utf-8", errors="replace"),
                               watch)
        else:
            with tarfile.open(full, "r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    verdict = filename_verdict(member.name)
                    if verdict:
                        findings.append(_finding(
                            rel + "!" + member.name, 0,
                            "filename-class", verdict))
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    raw = fh.read(MAX_SCAN_BYTES + 1)
                    if len(raw) > MAX_SCAN_BYTES or b"\0" in raw[:8192]:
                        continue
                    _scan_text(findings, rel + "!" + member.name,
                               raw.decode("utf-8", errors="replace"),
                               watch)
    except Exception:
        findings.append(_finding(rel, 0, "archive-unreadable", "warn"))


def scan_tree(folder, tree, rules):
    """Findings: {path, line, kind, severity, fp}. Matched text is
    never stored or printed; a finding names the shape, not the
    secret."""
    findings = []
    watch = [w for w in rules.get("watch_strings", []) if w]
    for rel in sorted(tree):
        info = tree[rel]
        verdict = filename_verdict(rel)
        if verdict:
            findings.append(_finding(rel, 0, "filename-class", verdict))
        if info["size"] > BLOCK_SIZE:
            findings.append(_finding(rel, 0, "oversize", "block"))
        elif info["size"] > WARN_SIZE:
            findings.append(_finding(rel, 0, "oversize", "warn"))
        full = os.path.join(folder, rel.replace("/", os.sep))
        if rel.lower().endswith(ARCHIVE_SUFFIXES):
            _scan_archive(findings, rel, full, watch)
            continue
        if info["size"] > MAX_SCAN_BYTES:
            continue
        with open(full, "rb") as fh:
            raw = fh.read()
        if b"\0" in raw[:8192]:
            continue  # binary: filename rules still applied above
        _scan_text(findings, rel, raw.decode("utf-8", errors="replace"),
                   watch)
    return findings


def is_overridden(finding, rules):
    """An override names one finding by fingerprint (prefix match)
    and must carry a written reason; both live in .ghostgate.json.
    Returns the reason or None."""
    for ov in rules.get("overrides", []):
        fp = (ov.get("fp") or "").strip()
        reason = (ov.get("reason") or "").strip()
        if fp and reason and finding["fp"].startswith(fp):
            return reason
    return None


def partition_overrides(findings, rules):
    active, overridden = [], []
    for f in findings:
        reason = is_overridden(f, rules)
        if reason:
            g = dict(f)
            g["reason"] = reason
            overridden.append(g)
        else:
            active.append(f)
    return active, overridden


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


def run_gate_command(folder, rules, note):
    cmd = rules.get("gate_command")
    if not cmd:
        return
    import subprocess
    note("Running project gate: %s" % cmd)
    proc = subprocess.run(cmd, shell=True, cwd=folder,
                          capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-5:]
        raise GateError("project gate failed (exit %d): %s"
                        % (proc.returncode, " | ".join(tail)))


def recheck_delta(folder, local, delta):
    """Last-second re-check: the delta files are re-hashed right
    before the ref moves. Anything that changed since the scan aborts
    the landing; the rehearsed commit is simply never landed."""
    for rel in delta["added"] + delta["changed"]:
        full = os.path.join(folder, rel.replace("/", os.sep))
        if not os.path.isfile(full):
            raise GateError("re-check: %s vanished since the scan"
                            % rel)
        with open(full, "rb") as fh:
            if blob_sha(fh.read()) != local[rel]["sha"]:
                raise GateError(
                    "re-check: %s changed since the scan; aborting "
                    "before the ref moves" % rel)
    for rel in delta["deleted"]:
        full = os.path.join(folder, rel.replace("/", os.sep))
        if os.path.isfile(full):
            raise GateError("re-check: %s reappeared since the scan"
                            % rel)


VERSION_RXS = [
    re.compile(r'VERSION\s*=\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"'),
    re.compile(r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"'),
    re.compile(r'versionName\s*=?\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"'),
    re.compile(r'(?m)^version\s*=\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"'),
]


def extract_version(text):
    for rx in VERSION_RXS:
        m = rx.search(text)
        if m:
            return m.group(1)
    return None


def fetch_blob(gh, repo, sha):
    r = gh.call("GET", "/repos/%s/git/blobs/%s" % (repo, sha))
    if r.get("encoding") == "base64":
        return base64.b64decode(r["content"])
    return (r.get("content") or "").encode()


def draft_message(gh, repo, folder, local, remote, delta):
    """If a changed file carries a version that moved, the commit is
    named for it ('Ghost Gate 1.1'); otherwise (None, None) and the
    caller falls back to the delta summary."""
    display = repo.split("/")[-1].replace("-", " ").replace("_", " ")
    display = display.title()
    for rel in delta["changed"] + delta["added"]:
        if local[rel]["size"] > MAX_SCAN_BYTES:
            continue
        full = os.path.join(folder, rel.replace("/", os.sep))
        with open(full, "rb") as fh:
            raw = fh.read()
        if b"\0" in raw[:8192]:
            continue
        new_v = extract_version(raw.decode("utf-8", errors="replace"))
        if not new_v:
            continue
        old_v = None
        if rel in remote:
            try:
                old_raw = fetch_blob(gh, repo, remote[rel])
                old_v = extract_version(
                    old_raw.decode("utf-8", errors="replace"))
            except GateError:
                old_v = None
        if new_v != old_v:
            return "%s %s" % (display, new_v), new_v
    return None, None


def pull_back(gh, repo, branch, local, delta, is_private, note):
    """Fetch key changed files from the raw public URL, the way a
    visitor would, and hash-match them. Proves the world sees the
    push, not just the API."""
    import urllib.request
    import urllib.error
    targets = (delta["added"] + delta["changed"])[:3]
    if not targets:
        return
    if is_private and not gh.token:
        note("Pull-back skipped: private repo, no token route.")
        return
    for rel in targets:
        url = "https://raw.githubusercontent.com/%s/%s/%s" % (
            repo, urllib.parse.quote(branch, safe="/"),
            urllib.parse.quote(rel, safe="/"))
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "GhostGate/" + VERSION)
        if gh.token:
            req.add_header("Authorization", "Bearer " + gh.token)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
        except urllib.error.URLError as e:
            raise GateError(
                "push landed and is journaled, but the pull-back "
                "could not fetch %s (%s)" % (rel, e))
        if blob_sha(data) != local[rel]["sha"]:
            raise GateError(
                "push landed and is journaled, but the pull-back of "
                "%s does not hash-match the pushed file" % rel)
    note("Pull-back verified %d file(s) from the raw URL."
         % len(targets))


def release_draft(repo, branch, version, result, delta):
    """On a version bump, prepare the release draft and STOP. A push
    is not a release; Gate never creates one."""
    draft_dir = os.path.expanduser("~/ghost-gate-drafts")
    os.makedirs(draft_dir, exist_ok=True)
    name = repo.split("/")[-1]
    path = os.path.join(draft_dir, "%s-%s.md" % (name, version))
    lines = [
        "# %s %s - release draft (prepared by Ghost Gate, NOT "
        "published)" % (name.replace("-", " ").title(), version),
        "",
        "Push note: %s@%s -> %s" % (repo, branch,
                                    (result["head"] or "")[:12]),
        "Journal entry: %s" % result.get("journal", ""),
        "",
        "Changes in this push:",
    ]
    lines += ["- added: " + p for p in delta["added"]]
    lines += ["- changed: " + p for p in delta["changed"]]
    lines += ["- deleted: " + p for p in delta["deleted"]]
    lines += ["", "Release notes:", "",
              "(write the notes, then create the release yourself; "
              "Ghost Gate prepared this draft and stopped, per the "
              "authority boundary.)"]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def push_flow(folder, repo, branch="main", message=None, gh=None,
              progress=None):
    """The full gate. Returns a summary dict; raises GateError when
    the gate stops the push."""
    def note(msg):
        if progress:
            progress(msg)
    gh = gh or GH()
    rules = load_rules(folder)
    if branch in rules.get("protected_branches", []):
        raise GateError("branch %s is protected in .ghostgate.json"
                        % branch)
    run_gate_command(folder, rules, note)
    note("Walking local tree...")
    local = local_tree(folder)
    local_map = {p: v["sha"] for p, v in local.items()}
    note("Scanning %d files..." % len(local))
    findings, overridden = partition_overrides(
        scan_tree(folder, local, rules), rules)
    for f in overridden:
        note("Override applied: %s (%s) - %s"
             % (f["path"], f["kind"], f["reason"]))
    bl = blocks(findings)
    if bl:
        raise GateError("scan blocked the push: %d blocking finding(s)"
                        % len(bl))
    info = gh.repo_info(repo)
    if rules.get("must_stay_private") and not info.get("private"):
        raise GateError("guardrail: %s must stay private but is public"
                        % repo)
    head, base_tree, remote = gh.remote_state(repo, branch)
    absorbed = 0
    expected = local_map
    delta = diff_trees(local, remote)
    last = journal_last_for(repo, branch)
    if last and head and last[4] and head != last[4]:
        # The remote moved outside Gate. Absorb when the changed
        # sets do not truly overlap; stop only on a real conflict.
        # Absorbing means the local delta is measured against the
        # journal base and applied ONTO the current remote tree, so
        # remote-only work survives the push.
        base_map = gh.tree_map(repo, gh.commit_tree_sha(repo, last[4]))
        remote_changed = {p for p in set(remote) | set(base_map)
                          if remote.get(p) != base_map.get(p)}
        local_changed = {p for p in set(local_map) | set(base_map)
                         if local_map.get(p) != base_map.get(p)}
        overlap = sorted(p for p in remote_changed & local_changed
                         if local_map.get(p) != remote.get(p))
        if overlap:
            raise GateError(
                "divergence guard: %s@%s moved outside Ghost Gate "
                "and %d file(s) changed on both sides: %s"
                % (repo, branch, len(overlap), ", ".join(overlap[:10])))
        absorbed = len(remote_changed)
        if absorbed:
            note("Absorbing %d remote change(s) made outside the "
                 "gate (no overlap)." % absorbed)
            delta = diff_trees(local, base_map)
            expected = dict(remote)
            for p in delta["added"] + delta["changed"]:
                expected[p] = local_map[p]
            for p in delta["deleted"]:
                expected.pop(p, None)
    if not (delta["added"] or delta["changed"] or delta["deleted"]):
        return {"status": "clean", "findings": findings,
                "overridden": overridden, "delta": delta, "head": head,
                "absorbed": absorbed}
    version = None
    if message is None:
        message, version = draft_message(gh, repo, folder, local,
                                         remote, delta)
        if message is None:
            message = ("Ghost Gate push: %d added, %d changed, "
                       "%d deleted" % (len(delta["added"]),
                                       len(delta["changed"]),
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
            result = {"status": "pushed", "findings": findings,
                      "overridden": overridden, "delta": delta,
                      "head": head, "tree": base_tree,
                      "journal": entry_hash, "absorbed": absorbed,
                      "version": version, "message": message}
            pull_back(gh, repo, branch, local,
                      {"added": [first], "changed": [], "deleted": []},
                      info.get("private"), note)
            if version:
                result["release_draft"] = release_draft(
                    repo, branch, version, result, delta)
            return result
    note("Rehearsing commit (%d added, %d changed, %d deleted)..."
         % (len(delta["added"]), len(delta["changed"]),
            len(delta["deleted"])))
    commit_sha, tree_sha = rehearse(gh, repo, folder, local, delta,
                                    base_tree, head, message)
    recheck_delta(folder, local, delta)
    note("Landing rehearsed commit %s..." % commit_sha[:8])
    gh.update_ref(repo, branch, commit_sha)
    new_head, _t, new_remote = gh.remote_state(repo, branch)
    if new_head != commit_sha:
        raise GateError("read-back failed: branch head %s is not the "
                        "rehearsed commit %s"
                        % (new_head, commit_sha))
    if new_remote != expected:
        raise GateError("read-back failed: remote tree does not match "
                        "the expected tree hash-for-hash")
    entry_hash = journal_add("push", repo, branch, folder, orig_head,
                             commit_sha, tree_sha,
                             len(delta["added"]) + boot_count,
                             len(delta["changed"]), len(delta["deleted"]),
                             0, len(warns(findings)))
    result = {"status": "pushed", "findings": findings,
              "overridden": overridden, "delta": delta,
              "head": commit_sha, "tree": tree_sha,
              "journal": entry_hash, "absorbed": absorbed,
              "version": version, "message": message}
    note("Landed and verified.")
    pull_back(gh, repo, branch, local, delta, info.get("private"),
              note)
    if version:
        result["release_draft"] = release_draft(repo, branch, version,
                                                result, delta)
        note("Release draft prepared (not published): %s"
             % result["release_draft"])
    return result


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
# History sweep, observe-first onboarding, batch sweeps
# --------------------------------------------------------------------------

def history_sweep(repo, branch=None, max_commits=200, gh=None,
                  progress=None):
    """Audit the remote repo's PAST commits for the same shapes. A
    secret deleted today is still public in history; the sweep names
    the blobs and commits so the credential can be rotated."""
    def note(msg):
        if progress:
            progress(msg)
    gh = gh or GH()
    commits = []
    page = 1
    while len(commits) < max_commits:
        path = "/repos/%s/commits?per_page=100&page=%d" % (repo, page)
        if branch:
            path += "&sha=" + urllib.parse.quote(branch, safe="/")
        batch = gh.call("GET", path)
        if not batch:
            break
        commits.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    commits = commits[:max_commits]
    note("Walking %d commits..." % len(commits))
    appearances = {}
    path_findings = []
    for c in commits:
        tree = gh.tree_map(repo, gh.commit_tree_sha(repo, c["sha"]))
        for p, sha in tree.items():
            slot = appearances.setdefault(sha, {"paths": set(),
                                                "commits": set()})
            slot["paths"].add(p)
            slot["commits"].add(c["sha"][:8])
            verdict = filename_verdict(p)
            if verdict == "block":
                path_findings.append({"path": p, "commit": c["sha"][:8],
                                      "kind": "filename-class"})
    note("Scanning %d unique blobs..." % len(appearances))
    blob_findings = []
    fetched = 0
    for sha, slot in appearances.items():
        if fetched >= 1500:
            note("Blob fetch cap reached; sweep is partial.")
            break
        try:
            raw = fetch_blob(gh, repo, sha)
        except GateError:
            continue
        fetched += 1
        if len(raw) > MAX_SCAN_BYTES or b"\0" in raw[:8192]:
            continue
        text = raw.decode("utf-8", errors="replace")
        kinds = set()
        for line in text.splitlines():
            for name, rx in BLOCK_PATTERNS:
                if rx.search(line):
                    kinds.add(name)
        if kinds:
            blob_findings.append({
                "sha": sha[:12], "paths": sorted(slot["paths"]),
                "commits": sorted(slot["commits"])[:5],
                "kinds": sorted(kinds)})
    return {"commits": len(commits), "blobs": len(appearances),
            "blob_findings": blob_findings,
            "path_findings": path_findings}


def observe(folder, repo, gh=None):
    """First contact with an unmanaged repo is observe-only: profile
    it, draft proposed guardrails, change nothing."""
    gh = gh or GH()
    info = gh.repo_info(repo)
    branch = info.get("default_branch") or "main"
    head, _t, remote = gh.remote_state(repo, branch)
    from collections import Counter
    exts = Counter()
    for p in remote:
        base = os.path.basename(p)
        exts[os.path.splitext(base)[1] or "(none)"] += 1
    draft = {"must_stay_private": bool(info.get("private")),
             "watch_strings": [], "protected_branches": [],
             "gate_command": "", "overrides": []}
    draft_path = None
    if folder and os.path.isdir(folder):
        draft_path = os.path.join(folder, ".ghostgate.draft.json")
        with open(draft_path, "w", encoding="utf-8") as fh:
            json.dump(draft, fh, indent=2)
            fh.write("\n")
    return {"repo": repo, "private": info.get("private"),
            "default_branch": branch, "head": head,
            "remote_files": len(remote), "top_extensions":
            exts.most_common(5), "draft_path": draft_path,
            "journaled": journal_last_for(repo, branch) is not None}


def batch_sweep(batch_file, gh=None, progress=None):
    """Each line of the batch file: FOLDER REPO [BRANCH]. Every pair
    goes through the full gate; the board reports one verdict each."""
    def note(msg):
        if progress:
            progress(msg)
    gh = gh or GH()
    results = []
    with open(batch_file, "r", encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh
                 if ln.strip() and not ln.startswith("#")]
    for ln in lines:
        parts = ln.split()
        folder, repo = parts[0], parts[1]
        branch = parts[2] if len(parts) > 2 else "main"
        note("== %s -> %s@%s" % (folder, repo, branch))
        try:
            r = push_flow(folder, repo, branch, gh=gh,
                          progress=progress)
            verdict = ("CLEAN" if r["status"] == "clean"
                       else "PUSHED " + (r["head"] or "")[:8])
            results.append((repo, branch, verdict))
        except GateError as e:
            results.append((repo, branch, "STOPPED: " + str(e)))
            note("STOPPED: " + str(e))
    return results


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
    # Deep scan: a token sealed inside a zip must still be caught.
    import zipfile
    with zipfile.ZipFile(os.path.join(bad, "pack.zip"), "w") as zf:
        zf.writestr("inner.txt", "sealed ghp_" + "C" * 36 + "\n")
    f2 = scan_tree(bad, local_tree(bad), load_rules(bad))
    check("token inside a zip caught",
          any(x["path"] == "pack.zip!inner.txt"
              and x["kind"] == "github-token" for x in f2))
    # Overrides: fingerprint + reason suppresses exactly one finding;
    # a reason-less override suppresses nothing.
    target = [x for x in f2 if x["path"] == "tokens.txt"
              and x["kind"] == "github-token"][0]
    rules_ov = {"watch_strings": ["999 TEST LANE"],
                "overrides": [{"fp": target["fp"][:16],
                               "reason": "documented test fixture"}]}
    active, overridden = partition_overrides(f2, rules_ov)
    check("override with reason suppresses its finding",
          len(overridden) == 1
          and all(x["fp"] != target["fp"] for x in active))
    rules_bare = {"overrides": [{"fp": target["fp"][:16],
                                 "reason": ""}]}
    active2, overridden2 = partition_overrides(f2, rules_bare)
    check("override without a reason suppresses nothing",
          overridden2 == [] and len(active2) == len(f2))
    # Project gate command.
    try:
        run_gate_command(bad, {"gate_command": "false"}, lambda m: None)
        check("failing gate command stops the flow", False)
    except GateError:
        check("failing gate command stops the flow", True)
    run_gate_command(bad, {"gate_command": "true"}, lambda m: None)
    check("passing gate command lets the flow continue", True)
    # Last-second re-check.
    tree_b = local_tree(bad)
    delta = {"added": [], "changed": ["tokens.txt"], "deleted": []}
    recheck_delta(bad, tree_b, delta)
    check("re-check passes on an untouched delta", True)
    with open(os.path.join(bad, "tokens.txt"), "a") as fh:
        fh.write("tampered after the scan\n")
    try:
        recheck_delta(bad, tree_b, delta)
        check("re-check catches a file changed after the scan", False)
    except GateError:
        check("re-check catches a file changed after the scan", True)
    # Version extraction for drafted commit messages.
    check("version extraction (VERSION =)",
          extract_version('VERSION = "1.2.3"') == "1.2.3")
    check("version extraction (package.json)",
          extract_version('{"version": "2.0.1"}') == "2.0.1")
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
        print("  [%s] %s (%s) fp %s"
              % (f["severity"].upper(), loc, f["kind"], f["fp"][:12]))


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
            findings, overridden = partition_overrides(
                scan_tree(folder, tree, load_rules(folder)),
                load_rules(folder))
            print("Scanned %d files in %s" % (len(tree), folder))
            _print_findings(findings)
            for f in overridden:
                print("  [OVERRIDDEN] %s (%s) - %s"
                      % (f["path"], f["kind"], f["reason"]))
            print("%d blocking, %d warning(s), %d overridden"
                  % (len(blocks(findings)), len(warns(findings)),
                     len(overridden)))
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
                print("Pushed %s@%s -> %s (%s)"
                      % (repo, branch, result["head"][:12],
                         result.get("message", "")))
            for f in result.get("overridden", []):
                print("  [OVERRIDDEN] %s (%s) - %s"
                      % (f["path"], f["kind"], f["reason"]))
            wn = warns(result["findings"])
            if wn:
                print("Warnings:")
                _print_findings(wn)
            if result.get("release_draft"):
                print("Release draft prepared (not published): %s"
                      % result["release_draft"])
            return 0
        if argv[0] == "--history" and len(argv) >= 2:
            repo = argv[1]
            branch = argv[2] if len(argv) > 2 else None
            r = history_sweep(repo, branch,
                              progress=lambda m: print("  " + m))
            print("History sweep: %d commits, %d unique blobs"
                  % (r["commits"], r["blobs"]))
            for bf in r["blob_findings"]:
                print("  [BLOCK] blob %s kinds %s in %s (commits %s)"
                      % (bf["sha"], ", ".join(bf["kinds"]),
                         ", ".join(bf["paths"][:3]),
                         ", ".join(bf["commits"])))
            for pf in r["path_findings"]:
                print("  [BLOCK] %s (%s) at commit %s"
                      % (pf["path"], pf["kind"], pf["commit"]))
            bad = bool(r["blob_findings"] or r["path_findings"])
            if bad:
                print("If any of these were real credentials, rotate "
                      "them; deleting the file today does not remove "
                      "them from history.")
            return 1 if bad else 0
        if argv[0] == "--observe" and len(argv) >= 3:
            r = observe(argv[1], argv[2])
            print("Observed %s (nothing changed)" % r["repo"])
            print("  visibility: %s" % ("private" if r["private"]
                                        else "public"))
            print("  default branch: %s, head: %s"
                  % (r["default_branch"], (r["head"] or "none")[:12]))
            print("  remote files: %d, top types: %s"
                  % (r["remote_files"],
                     ", ".join("%s x%d" % e
                               for e in r["top_extensions"])))
            print("  journaled before: %s" % r["journaled"])
            if r["draft_path"]:
                print("  proposed guardrails drafted at %s (rename "
                      "to .ghostgate.json to adopt)"
                      % r["draft_path"])
            return 0
        if argv[0] == "--batch" and len(argv) == 2:
            results = batch_sweep(argv[1],
                                  progress=lambda m: print("  " + m))
            print("Batch board:")
            failed = 0
            for repo, branch, verdict in results:
                print("  %s@%s: %s" % (repo, branch, verdict))
                if verdict.startswith("STOPPED"):
                    failed += 1
            return 1 if failed else 0
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
                              ("History", self.on_history),
                              ("Observe", self.on_observe),
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
                findings, overridden = partition_overrides(
                    scan_tree(folder, tree, load_rules(folder)),
                    load_rules(folder))
                lines = ["Scanned %d files." % len(tree)]
                for f in findings:
                    loc = f["path"] + ((":%d" % f["line"])
                                       if f["line"] else "")
                    lines.append("  [%s] %s (%s) fp %s"
                                 % (f["severity"].upper(), loc,
                                    f["kind"], f["fp"][:12]))
                for f in overridden:
                    lines.append("  [OVERRIDDEN] %s (%s) - %s"
                                 % (f["path"], f["kind"], f["reason"]))
                lines.append("%d blocking, %d warning(s), "
                             "%d overridden."
                             % (len(blocks(findings)),
                                len(warns(findings)), len(overridden)))
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

        def on_history(self):
            try:
                _f, repo, branch = self.inputs()
                if not repo:
                    raise GateError("enter a repo (owner/name)")
            except GateError as e:
                messagebox.showerror("Ghost Gate", str(e))
                return

            def fn():
                r = history_sweep(repo, branch)
                lines = ["History sweep: %d commits, %d unique blobs"
                         % (r["commits"], r["blobs"])]
                for bf in r["blob_findings"]:
                    lines.append(
                        "  [BLOCK] blob %s kinds %s in %s (commits %s)"
                        % (bf["sha"], ", ".join(bf["kinds"]),
                           ", ".join(bf["paths"][:3]),
                           ", ".join(bf["commits"])))
                for pf in r["path_findings"]:
                    lines.append("  [BLOCK] %s (%s) at commit %s"
                                 % (pf["path"], pf["kind"],
                                    pf["commit"]))
                if not (r["blob_findings"] or r["path_findings"]):
                    lines.append("  No blocked shapes found in "
                                 "history.")
                return "\n".join(lines)
            self.run_worker(fn)

        def on_observe(self):
            try:
                folder, repo, _b = self.inputs()
                if not repo:
                    raise GateError("enter a repo (owner/name)")
            except GateError as e:
                messagebox.showerror("Ghost Gate", str(e))
                return

            def fn():
                r = observe(folder, repo)
                lines = ["Observed %s (nothing changed)" % r["repo"],
                         "  visibility: %s"
                         % ("private" if r["private"] else "public"),
                         "  default branch: %s, remote files: %d"
                         % (r["default_branch"], r["remote_files"]),
                         "  journaled before: %s" % r["journaled"]]
                if r["draft_path"]:
                    lines.append("  proposed guardrails drafted at "
                                 "%s" % r["draft_path"])
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
