#!/usr/bin/env python3
"""Differential test: every generated redirect spelling, real bash vs the hook.

Redirect classification is derived from bash's tokenisation rather than from a
table of spellings, and this is what checks the derivation. For each spelling it
observes what bash actually did — the argv the command received, the files it
created, the file it reported it could not open — and compares that against the
accesses `src/redirect.rs` derives. A file bash touched with no demand is a
bypass; a demand bash's behaviour does not justify is an over-approximation.

Needs a real bash, so it is not part of `cargo test`. Run it before trusting a
change to redirect classification, and extend its alphabet before trusting it
against a new spelling — an earlier version crossed the right dimensions using
only `"` and `'`, passed every case, and said nothing about the escaped family
bash treats asymmetrically.

    scripts/redirect-differential.py

Exits non-zero if any access was missed or fabricated.
"""
import os, re, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

BASH = shutil.which("bash") or "/bin/bash"
ROOT = os.path.realpath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(
    os.path.dirname(os.path.realpath(__file__)))
OUT = os.path.realpath(sys.argv[2]) if len(sys.argv) > 2 else tempfile.mkdtemp(
    prefix="redirect-differential-")
os.makedirs(OUT, exist_ok=True)

# Operators that can name a file, and how the named word is used.
OPS = {
    ">":   "write",
    ">>":  "write",
    ">|":  "write",
    "<":   "read",
    "<>":  "readwrite",
    ">&":  "write",
    "1>&": "write",
    "&>":  "write",
    "&>>": "write",
    "<&":  "none",
    "2>&": "none",
}

def spellings_of(ch):
    """Every way to write one character that bash reduces to `ch`."""
    return [ch, "\\" + ch, '"%s"' % ch, "'%s'" % ch]

BODIES = ["f", "ff", "2", "22", "x", "d/e"]

def words():
    """Redirect target words, crossing dash position with how it is written."""
    seen = set()
    out = []
    def add(w):
        if w not in seen:
            seen.add(w)
            out.append(w)
    for body in BODIES:
        for b in (body, '"%s"' % body, "'%s'" % body, body[0] + '"%s"' % body[1:] if len(body) > 1 else body):
            add(b)
            for d in spellings_of("-"):
                add(d + b)          # leading dash
                add(b + d)          # trailing dash
                add(d + b + d)      # both
    for d in spellings_of("-"):
        add(d)                      # the bare close form and its disguises
        add(d + d)
    # Whole words that are already complete spellings: crossing these with the
    # quoting loop above would produce a backslash inside quotes, which bash
    # keeps literally and which is a filename question rather than a redirect
    # one.
    for w in ["a\\ b", '"a b"', "'a b'", "-a\\ b", "\\-a\\ b", '-"a b"',
              "d\\/e", "-d\\/e", '2"2"', '\\-2"2"', '"-2"suffix', "\\-2suffix",
              "sub/-f", "-sub/f", "f\\-", '"2"-', '2"-"']:
        add(w)
    add('""')
    add("''")
    add('""' + "-")
    add("-" + '""')
    return out

WORDS = words()

# Each command maps argument *positions* to roles differently, so a spliced
# operand landing in the wrong slot changes the derived accesses rather than
# disappearing into an undifferentiated set of reads.
def roles_cat(argv):
    return [("Read", a) for a in argv]

def roles_cp(argv):
    if len(argv) < 2:
        return [("Write", a) for a in argv]
    return [("Read", a) for a in argv[:-1]] + [("Write", argv[-1])]

def roles_grep(argv):
    return [("Read", a) for a in argv[1:]]

def roles_none(argv):
    # A redirect with no command word: bash performs the redirections and, for
    # a close form, runs whatever operand it recovered. Either way no file
    # access comes from the argument list.
    return []

# The fourth field says whether the command's own arguments can name files.
# Where they cannot, every access the checker derives came from the redirect, so
# the comparison holds even for a line bash refused to run — bash performed no
# accesses at all, and the checker should have derived none.
# Fields: whether the command's own arguments can name files, and whether it is
# guaranteed to run. The second matters because bash reports a redirect it could
# not open and a command it could not execute in the same words, and where the
# recovered operand *becomes* the command — `>&-d/e` runs `d/e` — the message is
# about the command. Only a family whose command always runs can attribute that
# message to the redirect.
COMMANDS = [
    ("cat", roles_cat, "cat in.txt {redir} zzz", True, True),
    ("cp", roles_cp, "cp in.txt {redir} zzz", True, True),
    ("grep", roles_grep, "grep in.txt {redir} zzz", True, True),
    ("true", roles_none, "true {redir}", False, True),
    ("eval", roles_none, "eval x {redir}", False, True),
    ("", roles_none, "{redir}", False, False),
    ("assign", roles_none, "FOO=x {redir}", False, False),
]

def cases():
    for name, roles, template, args_bear_files, command_runs in COMMANDS:
        for op, mode in OPS.items():
            for w in WORDS:
                yield name, roles, template, args_bear_files, command_runs, op, mode, w

def run_probe(d, op, w, template, seed):
    """One bash run in a fresh directory; `seed` names files to create first."""
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    with open(os.path.join(d, "in.txt"), "w") as f:
        f.write("data\n")
    # Words like `d/e` and `sub/f` name a path, and without their parent the
    # redirect fails on every one of them — a whole family quietly testing that
    # bash refuses to run.
    for parent in ("d", "sub"):
        os.makedirs(os.path.join(d, parent), exist_ok=True)
    for name in seed:
        if name and not os.path.isabs(name):
            try:
                with open(os.path.join(d, name), "w") as f:
                    f.write("seed\n")
            except OSError:
                pass
    # The probe function stands in for whichever command the template names, so
    # the argv it reports is the argv that command would have received.
    line = template.replace("{redir}", op + w)
    for name in ("cat", "cp", "grep"):
        if line.startswith(name + " "):
            line = "p" + line[len(name):]
    script = (
        'p(){ for a in "$@"; do printf "%s\\0" "$a" >&9; done; }\n'
        'exec 9>argv.out\n'
        + line + "\n"
    )
    def snapshot():
        # Recursive: `>d/e` creates a file one level down, and a shallow listing
        # would report it as never created — turning a correct write demand into
        # a fabricated one.
        return {
            os.path.relpath(os.path.join(root, f), d)
            for root, _, files in os.walk(d)
            for f in files
        }

    before = snapshot()
    r = subprocess.run([BASH, "-c", script], cwd=d, capture_output=True, text=True)
    created = sorted(c for c in (snapshot() - before) if c != "argv.out")
    argv = []
    ap = os.path.join(d, "argv.out")
    if os.path.exists(ap):
        with open(ap) as f:
            raw = f.read()
        argv = raw.split("\0")[:-1] if raw else []
    missing = [m for m in re.findall(r"line \d+: (.*): No such file or directory", r.stderr) if m]
    return argv, created, missing, r.stderr.strip()

def bash_observe(idx, op, w, template):
    """What bash did, with a second pass so a read target exists to be opened.

    Pass one runs in an empty directory; if bash reports it could not open the
    target, pass two creates exactly the file bash named and runs again, so the
    command actually executes and its argv becomes observable. `ran` is false
    when bash abandoned the command either way (an ambiguous redirect, an empty
    target) — there is no argv to compare against then.
    """
    d = os.path.join(OUT, "c%05d" % idx)
    argv, created, missing, stderr = run_probe(d, op, w, template, [])
    seeded = []
    if missing and not argv:
        seeded = [m for m in missing if m]
        argv2, created2, missing2, stderr2 = run_probe(d, op, w, template, seeded)
        if argv2:
            argv, created2_all, stderr = argv2, created2, stderr2
            # A file bash opened for reading was seeded, so it is not "created";
            # keep pass one's report of what the redirect named.
            created = sorted(set(created) | (set(created2) - set(seeded)))
            missing = missing2 or missing
    shutil.rmtree(d, ignore_errors=True)
    # "Did bash execute this command line?" — not "did it produce an argv",
    # which is always false for a template with no command word and would have
    # excluded every command-less spelling from the over-approximation check.
    # A redirection that fails is the one thing that stops the line running;
    # `command not found` means it ran.
    redir_failed = any(e in stderr for e in (
        "ambiguous redirect", "Bad file descriptor", "cannot duplicate fd",
        "No such file or directory", "Is a directory", "Not a directory",
        "Permission denied", "restricted",
    ))
    ran = not redir_failed
    if argv and not ran:
        raise AssertionError("argv observed on a line bash refused to run: %r" % stderr)
    return argv, created, missing, seeded, ran, stderr

def main():
    all_cases = list(cases())
    print(f"{len(all_cases)} spellings", file=sys.stderr)
    # scriptcheck side, one batch.
    cmds = [t.replace("{redir}", op + w) for _, _, t, _, _, op, _, w in all_cases]
    tmp = os.path.join(OUT, "cmds")
    with open(tmp, "w") as f:
        f.write("\0".join(cmds))
    casedir = os.path.join(OUT, "cwd")
    os.makedirs(casedir, exist_ok=True)
    real_casedir = os.path.realpath(casedir)
    # Build the helper here rather than trusting whatever is in target/: a
    # stale binary reports the bugs it had when it was built, against a tree
    # that no longer has them.
    subprocess.run(["cargo", "build", "--quiet", "--example", "file_demands"],
                   cwd=ROOT, check=True)
    dump = subprocess.run(
        [os.path.join(ROOT, "target/debug/examples/file_demands"), casedir, tmp],
        capture_output=True, text=True, check=True,
    )
    demands = {}
    for line in dump.stdout.splitlines():
        cmd, _, rules = line.partition("\t")
        demands[cmd] = [r for r in rules.split("\x1f") if r]

    def resolve(name):
        return os.path.realpath(os.path.join(real_casedir, name)) if not os.path.isabs(name) else name

    def run_one(i):
        name, roles, template, args_bear_files, command_runs, op, mode, w = all_cases[i]
        cmd = cmds[i]
        argv, created, missing, seeded, ran, stderr = bash_observe(i, op, w, template)
        expected = set()
        for kind, a in roles(argv):
            expected.add((kind, resolve(a)))
        # What the redirect named, however bash reported it. A file it could not
        # open is still a file it tried to open: `true >-d/e` fails only because
        # `-d` does not exist, and the checker is right to demand the write.
        # Reading "created nothing" as "named nothing" would score that as a
        # fabrication.
        targets = set(created)
        if command_runs:
            targets |= set(missing) | set(seeded)
        if mode in ("write", "readwrite"):
            expected |= {("Write", resolve(t)) for t in targets}
        if mode in ("read", "readwrite"):
            expected |= {("Read", resolve(t)) for t in targets}
        actual = set()
        for r in demands.get(cmd, []):
            m = re.match(r"^(Read|Write)\((.*)\)$", r)
            if m:
                actual.add((m.group(1), m.group(2)))
        return dict(cmd=cmd, argv=argv, created=created, missing=missing, seeded=seeded,
                    ran=ran, args_bear_files=args_bear_files, command_runs=command_runs,
                    stderr=stderr, expected=expected, actual=actual)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(run_one, range(len(all_cases))))

    bypasses, extras, unobservable = [], [], 0
    for r in results:
        miss = r["expected"] - r["actual"]
        extra = r["actual"] - r["expected"]
        if miss:
            bypasses.append((r, miss))
        if not r["ran"] and (r["args_bear_files"] or (not r["command_runs"] and r["stderr"])):
            # The evidence does not separate a fabricated access from a real
            # one: either bash never produced the argv the checker derived, or
            # it failed in a way it reports identically for a redirect and for a
            # command. Only over-approximation is excluded — a missed access
            # still counts everywhere, and the `true` family, whose command
            # always runs, keeps both directions across every spelling.
            unobservable += 1
            continue
        if extra:
            extras.append((r, extra))

    print(f"\n=== {len(results)} spellings, {len(bypasses)} missed accesses, {len(extras)} over-approximations, {unobservable} whose argv bash never produced")
    for r, miss in bypasses:
        print(f"MISSED  {r['cmd']!r}\n        bash argv={r['argv']} created={r['created']} missing={r['missing']}"
              f"\n        expected={sorted(miss)}\n        actual={sorted(r['actual'])}")
    for r, extra in extras:
        print(f"EXTRA   {r['cmd']!r}\n        bash argv={r['argv']} created={r['created']} missing={r['missing']}"
              f"\n        extra={sorted(extra)}")
    # Both directions fail the run: a missed access is a bypass, and a
    # fabricated one is a deny the user cannot lift.
    return 1 if bypasses or extras else 0

sys.exit(main())
