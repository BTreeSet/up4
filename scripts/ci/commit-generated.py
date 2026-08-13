#!/usr/bin/env python3
"""Commit regenerated P4 artifacts as a GitHub-signed bot commit.

This is the *only* thing in this repository that runs with `contents: write`,
so it is written to do one thing and to refuse everything else.

# The trust boundary

Regeneration builds two P4 compilers from source, off the network, and runs
them. That job holds no write token. It hands its result here as an artifact,
and this script treats that artifact as **untrusted input**: every path is
parsed against a closed allowlist before anything is committed. A compiler that
emitted `.github/workflows/ci.yml` would be rejected here rather than pushed.

What the allowlist does *not* buy is control over the bytes inside a generated
file -- committing compiler output is the entire point. It bounds the blast
radius to the directories that are already understood to be machine-written.

# Why the GitHub API rather than `git push`

`createCommitOnBranch` takes no author or committer field (verified against
GitHub's published GraphQL schema, 2026-08-12), so the identity is whatever the
token is: with GITHUB_TOKEN that is github-actions[bot]. Commits authored
through it are GPG-signed by GitHub and show as Verified, which means a ruleset
requiring signed commits needs no bypass actor for this workflow. A `git push`
would need a committer identity we would have to invent and a signing key we
would have to store.

`expectedHeadOid` is required by the schema, which turns the push into a
compare-and-swap on the ref: the head this run was based on, or nothing. A
regeneration can take two hours, so `main` moving underneath it is a real
event, not a theoretical one. Losing the race is not an error worth failing the
build over -- the next run recomputes from the new head -- so it exits 0 and
says so.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import pathlib
import subprocess
import sys

# The closed set of paths a reconciliation may touch. A prefix ending in `/` is
# a directory; anything else is an exact file. Adding a generated artifact
# somewhere new is a deliberate edit here, reviewed like any other.
ALLOWED_PREFIXES = (
    "crates/up4-x4c/src/generated/",
    "crates/up4-ubpf/src/generated/",
)
ALLOWED_EXACT = ("p4/generated.lock",)


class Rejected(Exception):
    """A path the reconciler is not entitled to write."""


def admit(path: str) -> str:
    """Parse one untrusted path into a committable one, or raise.

    Rejects absolute paths, parent traversal, and backslashes before consulting
    the allowlist, so a path cannot be admitted by a prefix it only appears to
    have.
    """
    if not path or path.startswith("/") or "\\" in path:
        raise Rejected(f"not a repository-relative path: {path!r}")
    parts = pathlib.PurePosixPath(path).parts
    if ".." in parts or "." in parts:
        raise Rejected(f"path traversal: {path!r}")
    if path in ALLOWED_EXACT or any(path.startswith(p) for p in ALLOWED_PREFIXES):
        return path
    raise Rejected(f"outside the generated set: {path!r}")


def read_manifest(pkg: pathlib.Path) -> list[tuple[str, str]]:
    """Parse the regeneration job's manifest into `(status, admitted path)`.

    This is the smart-constructor boundary. Every path crosses it exactly once,
    and a path that does not survive stops the run: partial commits of a change
    set that was partly rejected would be worse than committing nothing.
    """
    text = (pkg / "MANIFEST").read_text()
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        status, _, path = line.partition("\t")
        if status not in ("M", "D"):
            raise Rejected(f"unknown manifest status {status!r}")
        out.append((status, admit(path)))
    return out


def file_changes(pkg: pathlib.Path, entries: list[tuple[str, str]]) -> dict:
    """Split the change set into GraphQL `additions` and `deletions`.

    Contents are base64 of the packaged bytes; `FileAddition.contents` is
    `Base64String!` and covers creation and modification alike, so only removal
    needs the other arm. Bytes come from the package, never from the checkout:
    this job checked out only the validator.
    """
    additions, deletions = [], []
    for status, path in entries:
        if status == "D":
            deletions.append({"path": path})
            continue
        blob = pkg / "files" / path
        if not blob.is_file():
            raise Rejected(f"manifest lists {path!r} but the package has no such file")
        additions.append(
            {"path": path, "contents": base64.b64encode(blob.read_bytes()).decode()}
        )
    return {"additions": additions, "deletions": deletions}


MUTATION = """
mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid url } }
}
"""

# Paths a regeneration reads. If none of them moved between the commit the
# artifacts were built from and the branch's new head, the artifacts are still
# valid for that head and the commit can simply be retargeted.
REGEN_INPUTS = (
    "p4/",
    "xtask/",
    "crates/up4-x4c/src/generated/",
    "crates/up4-ubpf/src/generated/",
)

# A regeneration takes up to two hours, so losing the compare-and-swap once is
# ordinary. Losing it three times running means the branch is busier than this
# workflow can follow, and the schedule is the right thing to fall back on.
MAX_ATTEMPTS = 3


@dataclasses.dataclass(frozen=True)
class Committed:
    url: str


@dataclasses.dataclass(frozen=True)
class Raced:
    """The branch moved: `expectedHeadOid` did not match. `head` is where it is now."""

    head: str


@dataclasses.dataclass(frozen=True)
class Failed:
    message: str


Outcome = Committed | Raced | Failed


def gh_json(*args: str):
    """`gh api ...` decoded, or `None` if the call failed."""
    r = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def branch_head(repo: str, branch: str) -> str | None:
    got = gh_json(f"repos/{repo}/branches/{branch}")
    return (got or {}).get("commit", {}).get("sha")


def inputs_moved(repo: str, base: str, head: str) -> bool:
    """Did anything the regeneration reads change between `base` and `head`?

    Conservative by construction: an answer this cannot determine is reported as
    "moved", because retargeting artifacts onto sources they were not built from
    is the one outcome worth avoiding. GitHub's compare endpoint truncates its
    file list on large diffs, so a full page is treated as unknown.
    """
    got = gh_json(f"repos/{repo}/compare/{base}...{head}")
    if got is None or "files" not in got:
        return True
    files = got["files"]
    if len(files) >= 300:
        return True
    return any(
        f.get("filename", "").startswith(REGEN_INPUTS) for f in files
    )


def post(repo: str, branch: str, expected_head: str, message: dict, changes: dict) -> Outcome:
    """One `createCommitOnBranch` attempt.

    A failure is classified by *asking the server where the branch is*, not by
    matching words in the error text. An earlier version of this script looked
    for "expected head" and "not match" in the message; the API says "Expected
    branch to point to ... but it did not", so every race was reported as a hard
    failure. Error prose is not an interface.
    """
    variables = {
        "input": {
            "branch": {"repositoryNameWithOwner": repo, "branchName": branch},
            "expectedHeadOid": expected_head,
            "message": message,
            "fileChanges": changes,
        }
    }
    r = subprocess.run(
        ["gh", "api", "graphql", "--input", "-",
         "--jq", ".data.createCommitOnBranch.commit.url"],
        input=json.dumps({"query": MUTATION, "variables": variables}),
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        return Committed(r.stdout.strip())
    now = branch_head(repo, branch)
    if now is not None and now != expected_head:
        return Raced(now)
    return Failed(r.stderr.strip())


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: commit-generated.py <package-dir> <owner/repo> <branch> "
              "<expected-head-oid>", file=sys.stderr)
        return 2
    pkg = pathlib.Path(sys.argv[1])
    repo, branch, expected_head = sys.argv[2:5]

    if not (pkg / "MANIFEST").is_file():
        print("no manifest: nothing to commit")
        return 0

    try:
        entries = read_manifest(pkg)
        changes = file_changes(pkg, entries)
    except Rejected as e:
        print(f"::error::refusing to commit: {e}", file=sys.stderr)
        print("The regeneration job produced a path outside the generated set.",
              file=sys.stderr)
        return 1
    if not entries:
        print("nothing to commit: every artifact is already current")
        return 0
    paths = [p for _, p in entries]

    body = (
        "Regenerated by `cargo xtask reconcile` because a `.p4` source or the\n"
        "pinned toolchain moved. Only artifacts that are actually stale are\n"
        "rewritten: x4c's output is not byte-reproducible, so its staleness is\n"
        "judged by the recorded source hash rather than by comparing bytes.\n\n"
        + "\n".join(f"- {p}" for p in paths)
    )
    message = {"headline": "chore(p4): reconcile generated artifacts", "body": body}

    base = expected_head
    for attempt in range(1, MAX_ATTEMPTS + 1):
        match post(repo, branch, expected_head, message, changes):
            case Committed(url):
                print(f"committed {len(paths)} path(s): {url}")
                return 0
            case Failed(message=err):
                print(f"::error::createCommitOnBranch failed: {err}", file=sys.stderr)
                return 1
            case Raced(head=head):
                # The branch moved during the build. Whether these artifacts are
                # still correct for the new head is a question about the inputs,
                # not about the race.
                if inputs_moved(repo, base, head):
                    print(f"::notice::{branch} moved to {head[:12]} and a "
                          "regeneration input changed with it; these artifacts are "
                          "stale. The push that moved it triggers its own run.")
                    return 0
                print(f"::notice::{branch} moved to {head[:12]}, but nothing the "
                      f"regeneration reads changed; retargeting "
                      f"(attempt {attempt}/{MAX_ATTEMPTS}).")
                expected_head = head

    print(f"::notice::{branch} moved faster than this workflow could follow "
          f"({MAX_ATTEMPTS} attempts); leaving it to the schedule.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
