#!/usr/bin/env python3 -I
"""Build-time leak scan. NOT shipped in the package: it names the tools it hunts.

Scans every byte of every file under a directory (and the file names) for
anything that identifies the builder, the machine, the toolchain paths, or the
tools used to write the software. Exits 1 if anything is found.
"""
import os, re, subprocess, sys

def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    except Exception:
        return ""

user = os.environ.get("USER") or sh("whoami")
here = os.path.dirname(os.path.abspath(__file__))

# Identity is never written in this file. It comes from the machine, from git,
# and from an optional untracked list (release/private-scan.local, one literal
# per line, # for comments) for anything else that must never ship.
git_email = sh("git", "-C", here, "config", "user.email")
identity = {sh("git", "-C", here, "config", "user.name"), git_email, git_email.split("@")[0]}
try:
    with open(os.path.join(here, "private-scan.local")) as f:
        identity |= {l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")}
except FileNotFoundError:
    pass

literals = identity | {
    # who and where
    user, sh("id", "-F"), sh("hostname"), sh("hostname", "-s"),
    sh("scutil", "--get", "ComputerName"), sh("scutil", "--get", "LocalHostName"),
    os.path.expanduser("~"), os.getcwd(),
    "/Users/", "/private/", "/var/folders", "scratchpad", "EmbalmApp",
    # toolchain and build environment
    ".build", "CommandLineTools", "Xcode", "swiftlang", "MacOSX", "DerivedData",
    sh("sw_vers", "-buildVersion"),
    # tools and models used to write it
    "claude", "anthropic", "openai", "chatgpt", "gemini", "copilot", "fable", "mythos",
    "sonnet", "haiku", "opus", "language model", "generated with", "co-authored",
    "co-author", "assistant", "gpt-", "gpt4", "gpt5",
}
# A factory-default machine name identifies nobody and appears in ordinary text.
GENERIC = {"mac", "macbook", "macbook-pro", "macbook-air", "macbook pro", "macbook air",
           "mac-mini", "mac mini", "mac-studio", "mac studio", "imac", "localhost", "local"}
literals = {l for l in literals if l and len(l) >= 3 and l.lower() not in GENERIC}
words = {"llm", "gpt"}   # whole-word only (too short for substring matching)
word_re = re.compile(rb"(?<![A-Za-z0-9])(" + b"|".join(w.encode() for w in words) + rb")(?![A-Za-z0-9])", re.I)

# The target-side audit script must name generic build-path strings in order to
# search for them. Those generic words are allowed in that one file only;
# every identity pattern (names, user, host, tools, models) still applies to it.
ALLOW = {"setup.sh": {"/users/", "/private/", "/var/folders", ".build", "commandlinetools",
                      "xcode", "derceddata", "deriveddata", "macosx"}}

root = sys.argv[1]
hits = 0
for dirpath, _, files in os.walk(root):
    for name in files + [os.path.basename(dirpath)]:
        lname = name.lower()
        for l in literals:
            if l.lower() in lname and l.lower() not in ALLOW.get(name, ()):
                print(f"NAME  {os.path.join(dirpath, name)}: contains {l!r}"); hits += 1
    for name in files:
        path = os.path.join(dirpath, name)
        if os.path.islink(path): continue
        data = open(path, "rb").read()
        low = data.lower()
        rel = os.path.relpath(path, root)
        for l in sorted(literals):
            if l.lower() in ALLOW.get(os.path.basename(path), ()): continue
            b = l.lower().encode()
            i = low.find(b)
            if i >= 0:
                snippet = data[max(0, i - 20): i + len(b) + 30]
                snippet = re.sub(rb"[^\x20-\x7e]", b".", snippet).decode()
                print(f"FOUND {rel}: {l!r}  ...{snippet}..."); hits += 1
        for m in word_re.finditer(data):
            snippet = re.sub(rb"[^\x20-\x7e]", b".", data[max(0, m.start() - 20): m.end() + 30]).decode()
            print(f"FOUND {rel}: whole word {m.group(1).decode()!r}  ...{snippet}..."); hits += 1
            break
print(f"scan of {root}: {hits} finding(s)")
sys.exit(1 if hits else 0)
