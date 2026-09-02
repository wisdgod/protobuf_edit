#!/usr/bin/env python3
"""Reconcile the compiled crate's public surface against the census mint.

Inputs: a rustdoc JSON document (``cargo rustdoc --all-features --
-Zunstable-options --output-format json``) and a census dump written by
``COORDINATES_DUMP=<path> cargo test --all-features --test coordinates
every_public_type_faces_the_auto_trait_matrix``. rustdoc reads the
compiled crate, so it sees every public item through macro expansion —
the one vantage no in-tree text judge has.

Five directions, each reported as a named leftover list grouped by
module, one line per item:

  A  under-naming: public {struct, enum} the census never minted a
     demand for (keyed by declaring file, the census's own vocabulary).
  B  overreach: census keys no compiled public declaration backs.
  C  alias closure: public paths whose declaration sits in a private
     module must be alias pins or census keys.
  D  trait enrollment: the reachable public trait set must equal the
     census dump's TRAITS roster, both directions.
  E  alias roll: every alias pair's declaration side must be a key
     the census mints — an entry over a never-minted key is a zombie
     whose pins stand ready to discharge a demand nothing raises.

Two red classes, kept distinct: a VERDICT red (any direction's leftover
is nonempty, exit 1) speaks about the crate; a HARNESS red (exit 2)
means this instrument cannot read its input — an unexpected
format_version or a JSON shape outside the assumptions spelled in the
guards below — and says nothing about the crate.

Python stdlib only; no dependency joins the crate's test suite.
"""

import json
import sys
from collections import defaultdict

CRATE = "protobuf_edit"

# The rustdoc JSON format this judge's shape assumptions were verified
# against. Another version is a harness red until the guards below are
# re-verified against its output and this pin is re-blessed.
EXPECTED_FORMAT_VERSION = 61

# Deliberately-public-but-unrostered rulings, keyed by census-vocabulary
# path, each carrying its reason in place. Empty is itself a claim: no
# roster under-names the crate.
ALLOWLIST: dict[str, str] = {}


class HarnessRed(Exception):
    """The instrument cannot read its input; no crate verdict implied."""


def harness(condition: bool, message: str) -> None:
    if not condition:
        raise HarnessRed(message)


def kind_of(item_id: str, item: dict) -> str:
    inner = item.get("inner")
    harness(
        isinstance(inner, dict) and len(inner) == 1,
        f"index item {item_id} has no single-key 'inner' discriminant",
    )
    return next(iter(inner))


def span_key(item_id: str, item: dict, name: str) -> str:
    """The census's vocabulary: the declaring file's module path plus
    the identifier. In-file private strata fold onto the file, exactly
    as the census's text walk keys them."""
    span = item.get("span")
    harness(
        isinstance(span, dict) and isinstance(span.get("filename"), str),
        f"{name} ({item_id}) carries no span filename",
    )
    filename = span["filename"]
    harness(
        filename.startswith("src/") and filename.endswith(".rs"),
        f"{name} ({item_id}) has a span outside src/: {filename}",
    )
    rel = filename[len("src/") : -len(".rs")]
    if rel == "lib":
        return f"{CRATE}::{name}"
    return f"{CRATE}::{rel.replace('/', '::')}::{name}"


def load_rustdoc(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    for key in ("format_version", "root", "index", "paths"):
        harness(key in doc, f"rustdoc JSON lacks the top-level {key!r} key")
    print(f"rustdoc format_version: {doc['format_version']}")
    harness(
        doc["format_version"] == EXPECTED_FORMAT_VERSION,
        f"format_version {doc['format_version']} is not the verified "
        f"{EXPECTED_FORMAT_VERSION}; re-verify the shape guards, then re-bless",
    )
    return doc


def load_dump(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    sections = {"declared": set(), "aliases": [], "traits": set()}
    current = None
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("["):
            harness(
                line in ("[declared]", "[aliases]", "[traits]"),
                f"census dump carries an unknown section {line!r}",
            )
            current = line[1:-1]
            continue
        harness(current is not None, "census dump has a line before any section")
        if current == "aliases":
            harness(" => " in line, f"alias line without ' => ': {line!r}")
            declaration, pin = line.split(" => ", 1)
            sections["aliases"].append((declaration, pin))
        else:
            sections[current].add(line)
    harness(bool(sections["declared"]), "census dump declares no keys")
    harness(bool(sections["traits"]), "census dump carries no trait roster")
    return sections


def grouped_lines(rows: list[tuple[str, str]]) -> list[str]:
    """Rows of (display path, annotation) clustered by parent module."""
    by_module: dict[str, list[str]] = defaultdict(list)
    for display, note in rows:
        module = display.rsplit("::", 1)[0]
        by_module[module].append(f"    {display}{note}")
    out = []
    for module in sorted(by_module):
        out.append(f"  {module}")
        out.extend(sorted(by_module[module]))
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: judge.py <rustdoc.json> <coordinates.dump>", file=sys.stderr)
        return 2

    doc = load_rustdoc(sys.argv[1])
    dump = load_dump(sys.argv[2])
    index: dict = doc["index"]
    local_paths = {
        item_id: entry
        for item_id, entry in doc["paths"].items()
        if entry.get("crate_id") == 0
    }
    for item_id, entry in local_paths.items():
        path = entry.get("path")
        harness(
            isinstance(path, list) and path and path[0] == CRATE,
            f"paths entry {item_id} does not start at the crate root",
        )

    # The public module tree. Every module rustdoc indexes must be
    # public and sit on an all-public chain from the root; a
    # declaration is consumer-addressable iff its parent chain lies
    # in this set.
    public_modules: set[tuple] = set()
    for item_id, item in index.items():
        if kind_of(item_id, item) != "module":
            continue
        harness(
            item.get("visibility") == "public",
            f"module {item_id} is indexed but not public",
        )
        harness(item_id in local_paths, f"module {item_id} has no paths entry")
        harness(
            isinstance(item["inner"]["module"].get("items"), list),
            f"module {item_id} carries no items list",
        )
        public_modules.add(tuple(local_paths[item_id]["path"]))
    for module in public_modules:
        for depth in range(1, len(module)):
            harness(
                module[:depth] in public_modules,
                f"module {'::'.join(module)} has a non-public ancestor",
            )

    def addressable(path: list) -> bool:
        return tuple(path[:-1]) in public_modules

    # Parent module of every indexed item, for locating use items.
    parent_module: dict[str, tuple] = {}
    for item_id, item in index.items():
        if kind_of(item_id, item) == "module":
            module_path = tuple(local_paths[item_id]["path"])
            for child in item["inner"]["module"]["items"]:
                parent_module[str(child)] = module_path

    # Re-export edges: target id -> the public paths spelled for it.
    reexports: dict[str, set] = defaultdict(set)
    external_reexports = 0
    for item_id, item in index.items():
        if kind_of(item_id, item) != "use":
            continue
        use = item["inner"]["use"]
        harness(
            not use.get("is_glob"),
            f"use item {item_id} is a glob re-export; the judge does not model globs",
        )
        target = use.get("id")
        harness(target is not None, f"use item {item_id} carries no target id")
        target = str(target)
        if target not in index:
            external_reexports += 1
            continue
        harness(
            kind_of(target, index[target]) != "module",
            f"use item {item_id} re-exports a module; the judge does not model that",
        )
        module_path = parent_module.get(item_id)
        harness(module_path is not None, f"use item {item_id} sits in no module")
        name = use.get("name")
        harness(bool(name), f"use item {item_id} carries no name")
        reexports[target].add("::".join(module_path) + f"::{name}")

    # The compiled public surface, in both vocabularies.
    types: dict[str, tuple] = {}  # id -> (span key, declaration path)
    traits: dict[str, list] = {}  # id -> declaration path
    for item_id, item in index.items():
        kind = kind_of(item_id, item)
        if kind not in ("struct", "enum", "trait"):
            continue
        harness(
            item.get("visibility") == "public",
            f"{kind} {item.get('name')} ({item_id}) is indexed but not public",
        )
        harness(
            item_id in local_paths,
            f"{kind} {item.get('name')} ({item_id}) has no paths entry",
        )
        name = item.get("name")
        harness(bool(name), f"{kind} {item_id} carries no name")
        declaration = local_paths[item_id]["path"]
        if kind == "trait":
            traits[item_id] = declaration
        else:
            types[item_id] = (span_key(item_id, item, name), declaration)

    census_keys = dump["declared"]
    alias_pins = {pin for _, pin in dump["aliases"]}
    roster_traits = dump["traits"]

    print(
        f"rustdoc public surface: {len(types)} types, {len(traits)} traits, "
        f"{sum(len(p) for p in reexports.values())} local re-export paths, "
        f"{external_reexports} external re-exports"
    )
    print(
        f"census dump: {len(census_keys)} declared keys, "
        f"{len(dump['aliases'])} alias pairs, {len(roster_traits)} roster traits"
    )
    for key, reason in ALLOWLIST.items():
        print(f"allowlisted: {key} — {reason}")

    failures: list[tuple[str, list[str]]] = []

    # A. Under-naming: a compiled public type no roster demands.
    rustdoc_keys = {key for key, _ in types.values()}
    key_declarations = defaultdict(set)
    for key, declaration in types.values():
        key_declarations[key].add("::".join(declaration))
    a_rows = []
    for key in rustdoc_keys - census_keys - set(ALLOWLIST):
        spelled = {d for d in key_declarations[key] if d != key}
        note = f" (declared at {', '.join(sorted(spelled))})" if spelled else ""
        a_rows.append((key, note))
    if a_rows:
        failures.append(("A under-naming: public types the census never demands", grouped_lines(a_rows)))

    # B. Overreach: a census key without a compiled public declaration.
    b_rows = [(key, "") for key in census_keys - rustdoc_keys]
    if b_rows:
        failures.append(("B overreach: census keys no public declaration backs", grouped_lines(b_rows)))

    # C. Alias closure: a public path over a private declaration must
    # be an alias pin or a census key.
    c_rows = []
    for item_id, (_, declaration) in types.items():
        if addressable(declaration):
            continue
        for public_path in reexports.get(item_id, ()):
            if public_path in alias_pins or public_path in census_keys:
                continue
            c_rows.append((public_path, f" (declared at {'::'.join(declaration)})"))
    if c_rows:
        failures.append(("C alias closure: public paths outside ALIASES and the census", grouped_lines(c_rows)))

    # D. Trait enrollment: reachable public traits == the roster.
    reachable_traits = {
        "::".join(declaration)
        for item_id, declaration in traits.items()
        if addressable(declaration) or reexports.get(item_id)
    }
    d_rows = [(path, " (reachable, not enrolled)") for path in reachable_traits - roster_traits]
    d_rows += [(path, " (enrolled, not reachable)") for path in roster_traits - reachable_traits]
    if d_rows:
        failures.append(("D trait enrollment: TRAITS roster out of step", grouped_lines(d_rows)))

    # E. Alias roll: an alias entry whose declaration side the census
    # never mints is a zombie — its pins stand ready to discharge a
    # demand nothing raises.
    e_rows = [
        (declaration, " (aliased, never minted)")
        for declaration in {d for d, _ in dump["aliases"]}
        if declaration not in census_keys
    ]
    if e_rows:
        failures.append(
            ("E alias roll: alias declarations the census never mints", grouped_lines(e_rows))
        )

    if failures:
        for heading, lines in failures:
            print(f"\nVERDICT RED — {heading} ({sum(1 for l in lines if l.startswith('    '))} rows)")
            print("\n".join(lines))
        return 1
    print("\nall five directions clean: the roster and the compiled surface agree")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessRed as red:
        print(f"\nHARNESS RED — {red}", file=sys.stderr)
        print("the judge could not read its input; no crate verdict implied", file=sys.stderr)
        sys.exit(2)
