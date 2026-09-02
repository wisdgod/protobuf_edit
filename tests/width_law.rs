//! The width-vocabulary law over the whole source tree.
//!
//! Textual over `src/`, so every macro arm and cfg branch is judged
//! regardless of the running feature set. Four judges:
//!
//! 1. **The four-class manifest.** Every stored field whose spelling
//!    falls in the width grammar resolves to exactly one manifest
//!    entry, every entry is hit exactly once, and each entry's
//!    declared shape conforms to its class: `Migrating` fields carry
//!    the width vocabulary itself (`WordWidth`, `ValueWidth`, their
//!    `Option`s, or the verdict enums' width parameter `W`),
//!    `ExemptPublic` fields stay raw integers on public fault
//!    surfaces, `ExemptInterior` fields stay raw inside
//!    constructor-disciplined aggregates whose named invariant is
//!    richer than a range, and `NotWidth` hits are extent, state,
//!    count, or depth quantities listed so silence is examined
//!    rather than assumed.
//! 2. **Mint discipline.** The provenance doors are pinned per file:
//!    every `met_unchecked` call site (each carrying a `SAFETY`
//!    comment in its statement), every `minimal_of` call site, every
//!    `WordWidth::MIN` placeholder, and zero qualified
//!    `new_unchecked` mints on the width types outside their root.
//! 3. **Positional stores.** Every tuple struct over a bare
//!    primitive is pinned by name, so a width cannot hide in a
//!    nameless field. (Tuple *variants* over primitives carry domain
//!    values — `Varint(u64)`, `I32(u32)` — and stay outside the
//!    grammar; enum payloads that store widths do so through named
//!    fields, which the manifest covers.)
//! 4. **Instrument controls.** Planted probes per spelling class —
//!    attribute-stacked, multiline, macro-arm, generic-width, and a
//!    tuple probe — prove the detector sees what it claims to see,
//!    and that parameters, locals, literals, comments, and strings
//!    stay invisible.
//!
//! The grammar (field declarations inside `struct`/`enum` bodies,
//! macro template text included, comments and strings stripped):
//! names `width`, `w`, `*_width`, `*_w`, `need`, `needed`, `have`,
//! `remaining` over `u8`/`u16`/`u32`/`u64`, their `Option`s, the
//! width types, or `W`; names `len`/`*_len` over the bare
//! primitives; and any field declared with a width type regardless
//! of name (so a rename cannot walk a typed field out of the
//! census). Fields inside parenthesized macro invocations are
//! outside the walk — none exist today; template declarations live
//! in `macro_rules!` bodies, which the scanner walks.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

// ─── the source walk ───

/// Walks `src/` and returns every Rust file as (path relative to
/// `src/`, contents), sorted by path.
fn src_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("src directory is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path
                    .strip_prefix(&root)
                    .expect("walked file lies under src")
                    .components()
                    .map(|part| part.as_os_str().to_str().expect("source paths are UTF-8"))
                    .collect::<Vec<_>>()
                    .join("/");
                let text = fs::read_to_string(&path).expect("source file is readable");
                files.push((rel, text));
            }
        }
    }
    // The walk must have covered the real tree: an empty or clipped
    // walk would pass every per-file assertion vacuously.
    assert!(files.len() >= 200, "the census walked only {} files under src/", files.len());
    files.sort();
    files
}

// ─── comment and string stripping ───

/// Replaces comments and string/char literals with spaces, keeping
/// newlines, so the scanners see code text alone at unchanged line
/// numbers.
fn strip_rust(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, seg: &str| {
        out.extend(seg.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
    };
    let mut i = 0;
    while i < bytes.len() {
        let rest = &text[i..];
        if rest.starts_with("//") {
            let end = rest.find('\n').map_or(text.len(), |n| i + n);
            blank(&mut out, &text[i..end]);
            i = end;
        } else if rest.starts_with("/*") {
            let mut depth = 1_usize;
            let mut j = i + 2;
            while j < bytes.len() && depth > 0 {
                if text[j..].starts_with("/*") {
                    depth += 1;
                    j += 2;
                } else if text[j..].starts_with("*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, &text[i..j]);
            i = j;
        } else if let Some(open) = raw_string_open(rest) {
            let closer = format!("\"{}", "#".repeat(open.hashes));
            let body = i + open.prefix;
            let end = text[body..].find(&closer).map_or(text.len(), |n| body + n + closer.len());
            blank(&mut out, &text[i..end]);
            i = end;
        } else if rest.starts_with('"') || rest.starts_with("b\"") {
            let mut j = i + if rest.starts_with('b') { 2 } else { 1 };
            while j < bytes.len() {
                match bytes[j] {
                    b'\\' => j += 2,
                    b'"' => {
                        j += 1;
                        break;
                    }
                    _ => j += 1,
                }
            }
            blank(&mut out, &text[i..j.min(text.len())]);
            i = j.min(text.len());
        } else if bytes[i] == b'\'' {
            // A char literal spans tick, one (possibly escaped)
            // char, tick; a lifetime tick has no closing tick and
            // rides through as punctuation.
            let lit = if rest.len() >= 4 && bytes[i + 1] == b'\\' && bytes[i + 3] == b'\'' {
                Some(4)
            } else if rest.len() >= 3 && bytes[i + 1] != b'\\' && bytes[i + 2] == b'\'' {
                Some(3)
            } else {
                None
            };
            if let Some(n) = lit {
                blank(&mut out, &text[i..i + n]);
                i += n;
            } else {
                out.push('\'');
                i += 1;
            }
        } else {
            out.push(text[i..].chars().next().expect("in bounds"));
            i += text[i..].chars().next().expect("in bounds").len_utf8();
        }
    }
    out
}

/// The opening of a raw (or raw-byte) string at the start of `rest`,
/// when one begins there.
struct RawOpen {
    prefix: usize,
    hashes: usize,
}

fn raw_string_open(rest: &str) -> Option<RawOpen> {
    let after_b = rest.strip_prefix('b').unwrap_or(rest);
    let after_r = after_b.strip_prefix('r')?;
    let hashes = after_r.len() - after_r.trim_start_matches('#').len();
    if !after_r[hashes..].starts_with('"') {
        return None;
    }
    let prefix = (rest.len() - after_b.len()) + 1 + hashes + 1;
    Some(RawOpen { prefix, hashes })
}

// ─── tokenizing ───

const fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Splits stripped source into (byte offset, token text): words,
/// `$`-joined metavariables, `=>`, `::`, and single punctuation.
fn tokenize(stripped: &str) -> Vec<(usize, String)> {
    let bytes = stripped.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
        } else if b == b'$' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let word_start = j;
            while j < bytes.len() && is_word_byte(bytes[j]) {
                j += 1;
            }
            if j > word_start {
                toks.push((i, format!("${}", &stripped[word_start..j])));
                i = j;
            } else {
                toks.push((i, "$".to_owned()));
                i += 1;
            }
        } else if is_word_byte(b) {
            let mut j = i;
            while j < bytes.len() && is_word_byte(bytes[j]) {
                j += 1;
            }
            toks.push((i, stripped[i..j].to_owned()));
            i = j;
        } else if stripped[i..].starts_with("=>") {
            toks.push((i, "=>".to_owned()));
            i += 2;
        } else if stripped[i..].starts_with("::") {
            toks.push((i, "::".to_owned()));
            i += 2;
        } else {
            toks.push((i, (b as char).to_string()));
            i += 1;
        }
    }
    toks
}

// ─── the declaration scanner ───

/// One named field declared in a `struct` or `enum` body.
struct FieldDecl {
    line: usize,
    /// `Container` or `Enum::Variant`, prefixed `macro!::@arm::`
    /// for declarations inside macro template text.
    container: String,
    field: String,
    /// The declared type's tokens, joined without spaces.
    ty: String,
    /// Reachable as public surface: an enum variant field under a
    /// `pub` enum, or a struct field spelled `pub` itself.
    public: bool,
}

/// One tuple struct declaration and its first field's type.
struct TupleDecl {
    name: String,
    first_ty: String,
}

#[derive(PartialEq, Eq)]
enum Kind {
    Struct,
    Enum,
    Variant,
    MacroDef,
    Invoke,
    Arm,
    Opaque,
}

struct Scope {
    kind: Kind,
    name: String,
    vis_pub: bool,
    /// The owning enum's name, for variant scopes.
    enum_name: String,
    /// The arm label carried by `Arm` scopes.
    arm: String,
}

/// Walks one file's stripped text and returns its field and tuple
/// declarations, macro template text included.
#[allow(clippy::too_many_lines, reason = "one token walk; splitting it would scatter the state")]
fn scan(stripped: &str) -> (Vec<FieldDecl>, Vec<TupleDecl>) {
    let toks = tokenize(stripped);
    let newlines: Vec<usize> =
        stripped.bytes().enumerate().filter_map(|(pos, b)| (b == b'\n').then_some(pos)).collect();
    let line_of = |pos: usize| newlines.partition_point(|&n| n < pos) + 1;

    let mut fields = Vec::new();
    let mut tuples = Vec::new();
    let mut stack: Vec<Scope> = Vec::new();
    // A `struct`/`enum` header awaiting its body brace: (is_enum,
    // name, declared exactly `pub`).
    let mut pending: Option<(bool, String, bool)> = None;
    // `macro_rules` progress: the name arrives two tokens later.
    let mut macro_stage = 0_u8;
    let mut macro_name = String::new();
    let mut pending_invoke: Option<String> = None;
    let mut arm_label: Option<String> = None;
    let mut paren = 0_i32;
    let mut bracket = 0_i32;
    let mut prev_sig = String::new();

    let is_word = |t: &str| t.bytes().all(|b| is_word_byte(b) || b == b'$') && !t.is_empty();
    let macro_of = |stack: &[Scope]| {
        stack
            .iter()
            .rev()
            .find(|s| matches!(s.kind, Kind::MacroDef | Kind::Invoke))
            .map(|s| s.name.clone())
    };
    let arm_of = |stack: &[Scope]| {
        for s in stack.iter().rev() {
            match s.kind {
                Kind::Arm => return Some(s.arm.clone()),
                Kind::MacroDef | Kind::Invoke => return None,
                _ => {}
            }
        }
        None
    };

    let mut i = 0;
    while i < toks.len() {
        let (pos, t) = (toks[i].0, toks[i].1.as_str());
        match t {
            "(" => {
                if paren == 0
                    && bracket == 0
                    && let Some((false, name, _)) = &pending
                {
                    // A tuple struct: record its first field's type,
                    // skipping a leading field visibility.
                    let mut j = i + 1;
                    while j < toks.len()
                        && matches!(toks[j].1.as_str(), "pub" | "crate" | "(" | ")")
                    {
                        j += 1;
                    }
                    let first_ty = toks.get(j).map_or(String::new(), |(_, ty)| ty.clone());
                    tuples.push(TupleDecl { name: name.clone(), first_ty });
                }
                paren += 1;
                if paren == 1 && stack.last().is_some_and(|s| s.kind == Kind::MacroDef) {
                    arm_label = None;
                }
            }
            ")" => paren -= 1,
            "[" => bracket += 1,
            "]" => bracket -= 1,
            _ if paren == 0 && bracket == 0 => {
                match t {
                    "macro_rules" => macro_stage = 1,
                    "!" if macro_stage == 1 => macro_stage = 2,
                    _ if macro_stage == 2 && is_word(t) => {
                        macro_name = t.to_owned();
                        macro_stage = 3;
                    }
                    "struct" | "enum" => {
                        if let Some((_, name)) = toks.get(i + 1)
                            && is_word(name)
                        {
                            pending = Some((t == "enum", name.clone(), prev_sig == "pub"));
                        }
                    }
                    "!" if toks.get(i + 1).is_some_and(|(_, n)| n == "{") && is_word(&prev_sig) => {
                        pending_invoke = Some(prev_sig.clone());
                    }
                    ";" => {
                        pending = None;
                        pending_invoke = None;
                    }
                    "{" => {
                        if let Some((is_enum, name, vis_pub)) = pending.take_if(|_| prev_sig != "=")
                        {
                            stack.push(Scope {
                                kind: if is_enum { Kind::Enum } else { Kind::Struct },
                                name,
                                vis_pub,
                                enum_name: String::new(),
                                arm: String::new(),
                            });
                        } else if macro_stage == 3 {
                            stack.push(Scope {
                                kind: Kind::MacroDef,
                                name: core::mem::take(&mut macro_name),
                                vis_pub: false,
                                enum_name: String::new(),
                                arm: String::new(),
                            });
                            macro_stage = 0;
                        } else if let Some(name) = pending_invoke.take() {
                            stack.push(Scope {
                                kind: Kind::Invoke,
                                name,
                                vis_pub: false,
                                enum_name: String::new(),
                                arm: String::new(),
                            });
                        } else if prev_sig == "=>" && stack.iter().any(|s| s.kind == Kind::MacroDef)
                        {
                            stack.push(Scope {
                                kind: Kind::Arm,
                                name: String::new(),
                                vis_pub: false,
                                enum_name: String::new(),
                                arm: arm_label.clone().unwrap_or_default(),
                            });
                        } else if stack.last().is_some_and(|s| s.kind == Kind::Enum)
                            && is_word(&prev_sig)
                        {
                            let owner = stack.last().expect("just probed");
                            let (enum_name, vis_pub) = (owner.name.clone(), owner.vis_pub);
                            stack.push(Scope {
                                kind: Kind::Variant,
                                name: prev_sig.clone(),
                                vis_pub,
                                enum_name,
                                arm: String::new(),
                            });
                        } else {
                            stack.push(Scope {
                                kind: Kind::Opaque,
                                name: String::new(),
                                vis_pub: false,
                                enum_name: String::new(),
                                arm: String::new(),
                            });
                        }
                        prev_sig = "{".to_owned();
                        i += 1;
                        continue;
                    }
                    "}" => {
                        stack.pop();
                        prev_sig = "}".to_owned();
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
                // A field declaration inside a struct or variant
                // body at its immediate level.
                if stack.last().is_some_and(|s| matches!(s.kind, Kind::Struct | Kind::Variant))
                    && is_word(t)
                    && !matches!(t, "pub" | "crate" | "in" | "where")
                    && toks.get(i + 1).is_some_and(|(_, n)| n == ":")
                    && matches!(prev_sig.as_str(), "{" | "," | "]" | ")" | "pub")
                {
                    let mut j = i + 2;
                    let (mut ang, mut par, mut brk) = (0_i32, 0_i32, 0_i32);
                    let mut ty = String::new();
                    while let Some((_, tt)) = toks.get(j) {
                        match tt.as_str() {
                            "<" => ang += 1,
                            ">" => ang -= 1,
                            "(" => par += 1,
                            ")" if par == 0 => break,
                            ")" => par -= 1,
                            "[" => brk += 1,
                            "]" => brk -= 1,
                            "," | "}" if ang == 0 && par == 0 && brk == 0 => break,
                            _ => {}
                        }
                        ty.push_str(tt);
                        j += 1;
                    }
                    let owner = stack.last().expect("just probed");
                    let container = match owner.kind {
                        Kind::Struct => owner.name.clone(),
                        _ => format!("{}::{}", owner.enum_name, owner.name),
                    };
                    let prefix = macro_of(&stack).map_or_else(String::new, |m| {
                        arm_of(&stack)
                            .filter(|a| !a.is_empty())
                            .map_or_else(|| format!("{m}!::"), |a| format!("{m}!::@{a}::"))
                    });
                    let public = match owner.kind {
                        Kind::Variant => owner.vis_pub,
                        _ => prev_sig == "pub",
                    };
                    fields.push(FieldDecl {
                        line: line_of(pos),
                        container: format!("{prefix}{container}"),
                        field: t.to_owned(),
                        ty,
                        public,
                    });
                    prev_sig = t.to_owned();
                    i = j;
                    continue;
                }
            }
            _ => {}
        }
        // Arm labels live at the top level of a macro-definition
        // pattern group: `@label` plus one optional bare word.
        if t == "@"
            && paren == 1
            && stack.last().is_some_and(|s| s.kind == Kind::MacroDef)
            && let Some((_, label)) = toks.get(i + 1)
        {
            let mut label = label.clone();
            if let Some((_, second)) = toks.get(i + 2)
                && second.bytes().all(is_word_byte)
                && !second.is_empty()
            {
                label.push(' ');
                label.push_str(second);
            }
            arm_label = Some(label);
        }
        if paren == 0 && bracket == 0 {
            prev_sig = t.to_owned();
        }
        i += 1;
    }
    (fields, tuples)
}

// ─── the width grammar ───

fn width_name(name: &str) -> bool {
    name == "width" || name == "w" || name.ends_with("_width") || name.ends_with("_w")
}

fn aux_name(name: &str) -> bool {
    matches!(name, "need" | "needed" | "have" | "remaining")
}

fn len_name(name: &str) -> bool {
    name == "len" || name.ends_with("_len")
}

fn prim(ty: &str) -> bool {
    matches!(ty, "u8" | "u16" | "u32" | "u64")
}

fn opt_prim(ty: &str) -> bool {
    matches!(ty, "Option<u8>" | "Option<u16>" | "Option<u32>" | "Option<u64>")
}

fn width_ty(ty: &str) -> bool {
    matches!(ty, "WordWidth" | "ValueWidth" | "Option<WordWidth>" | "Option<ValueWidth>")
}

/// Whether a declared field falls under the width grammar.
fn detected(f: &FieldDecl) -> bool {
    ((width_name(&f.field) || aux_name(&f.field))
        && (prim(&f.ty) || opt_prim(&f.ty) || width_ty(&f.ty) || f.ty == "W"))
        || (len_name(&f.field) && prim(&f.ty))
        || width_ty(&f.ty)
}

// ─── the manifest ───

/// A manifested field's adjudicated class.
enum Class {
    /// Migrated to the width vocabulary: the declared type must be
    /// `WordWidth`, `ValueWidth`, one of their `Option`s, or the
    /// verdict enums' width parameter `W` (instantiated at the step
    /// faces' width types).
    Migrating { ty: &'static str },
    /// Public raw-integer width carrier, frozen by the landed
    /// public posture; the domain note names what the integer
    /// means.
    ExemptPublic { ty: &'static str, domain: &'static str },
    /// Raw integer inside a constructor-disciplined aggregate whose
    /// named invariant is richer than a range; not publicly
    /// reachable.
    ExemptInterior { ty: &'static str, invariant: &'static str },
    /// A grammar hit that is not a width claim: extent, state,
    /// count, or depth class.
    NotWidth { ty: &'static str, class: &'static str },
}

struct Entry {
    file: &'static str,
    container: &'static str,
    field: &'static str,
    class: Class,
}

const fn e(
    file: &'static str,
    container: &'static str,
    field: &'static str,
    class: Class,
) -> Entry {
    Entry { file, container, field, class }
}

const fn m(ty: &'static str) -> Class {
    Class::Migrating { ty }
}

const fn xp(ty: &'static str, domain: &'static str) -> Class {
    Class::ExemptPublic { ty, domain }
}

const fn xi(ty: &'static str, invariant: &'static str) -> Class {
    Class::ExemptInterior { ty, invariant }
}

const fn nw(ty: &'static str, class: &'static str) -> Class {
    Class::NotWidth { ty, class }
}

/// Every width-grammar field declaration in the tree, keyed
/// `(file, container-or-macro-arm path, field)`.
const MANIFEST: &[Entry] = &[
    e(
        "collect/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("collect/grouped.rs", "Row", "tag_width", m("WordWidth")),
    e("collect/grouped.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "collect/grouped.rs",
        "WordCarry",
        "width",
        xi(
            "u8",
            "word bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("collect/grouped.rs", "PendingHead", "tag_width", m("WordWidth")),
    e("collect/grouped.rs", "StepWord::Done", "width", m("W")),
    e(
        "collect/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("collect/groupless.rs", "Row", "tag_width", m("WordWidth")),
    e("collect/groupless.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "collect/groupless.rs",
        "WordCarry",
        "width",
        xi(
            "u8",
            "word bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("collect/groupless.rs", "PendingHead", "tag_width", m("WordWidth")),
    e("collect/groupless.rs", "StepWord::Done", "width", m("W")),
    e(
        "commission/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e(
        "commission/grouped.rs",
        "FetchFault::Oversize",
        "len",
        nw("u64", "staged extent byte length"),
    ),
    e(
        "commission/grouped.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "commission/grouped.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "commission/grouped.rs",
        "SizeFrame::Len",
        "tag_w",
        xi("u64", "minimal head-window byte count, the admission theorem's derivation"),
    ),
    e(
        "commission/grouped.rs",
        "PayloadAnswer::Resident",
        "len",
        nw("u32", "resident payload byte extent"),
    ),
    e(
        "commission/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e(
        "commission/groupless.rs",
        "FetchFault::Oversize",
        "len",
        nw("u64", "staged extent byte length"),
    ),
    e(
        "commission/groupless.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "commission/groupless.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "commission/groupless.rs",
        "SizeFrame",
        "tag_w",
        xi("u64", "minimal head-window byte count, the admission theorem's derivation"),
    ),
    e(
        "commission/groupless.rs",
        "PayloadAnswer::Resident",
        "len",
        nw("u32", "resident payload byte extent"),
    ),
    e(
        "construct.rs",
        "OverCap",
        "len",
        nw("u64", "the byte length that crossed the construction cap"),
    ),
    e("construct.rs", "Event::Len", "width", m("WordWidth")),
    e("construct.rs", "CopyEvent::Len", "width", m("WordWidth")),
    e("convert/grouped.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("convert/grouped.rs", "FaultKind::Output", "len", nw("u64", "output byte extent")),
    e(
        "convert/grouped.rs",
        "SlotValue::Dirty",
        "new_len",
        nw("u32", "staged replacement byte extent"),
    ),
    e("convert/grouped.rs", "Layer", "remaining", nw("u16", "LEN-crossing depth budget countdown")),
    e("convert/groupless.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("convert/groupless.rs", "FaultKind::Output", "len", nw("u64", "output byte extent")),
    e(
        "editor.rs",
        "one_shot_store!::@store::PayloadSlot::Copied",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@vocabulary::FaultKind::PayloadCut",
        "need",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@vocabulary::FaultKind::PayloadCut",
        "have",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@vocabulary::Close::Len",
        "prefix_w",
        m("WordWidth"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@vocabulary::Close::Len",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e("editor/grouped.rs", "one_shot_machine!::@vocabulary::Close::Len", "tag_w", m("WordWidth")),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@vocabulary::Close::ReGroup",
        "tag_w",
        m("WordWidth"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@vocabulary::Close::ReGroup",
        "end_w",
        m("WordWidth"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_edit_fault::EditFault::DepthExceeded",
        "need",
        nw("u32", "depth count"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum plain::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum plain::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ImportSpine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ReSrcBody",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ReSrcBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::NewSrcBody",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@canonical_vocab plain::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@canonical_vocab::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@refusal canonical::Refusal::NonMinimalTag",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@refusal canonical::Refusal::NonMinimalLen",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@refusal canonical::Refusal::NonMinimalValue",
        "width",
        xp("u8", "met padded value width, 2..=10"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@row_struct tolerant::Row",
        "tag_width",
        m("Option<WordWidth>"),
    ),
    e(
        "editor/grouped.rs",
        "one_shot_machine!::@row_struct tolerant::Row",
        "delim_width",
        m("Option<WordWidth>"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@vocabulary::FaultKind::PayloadCut",
        "need",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@vocabulary::FaultKind::PayloadCut",
        "have",
        nw("u32", "payload byte claim pair"),
    ),
    e("editor/groupless.rs", "one_shot_machine!::@vocabulary::Close", "prefix_w", m("WordWidth")),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@vocabulary::Close",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e("editor/groupless.rs", "one_shot_machine!::@vocabulary::Close", "tag_w", m("WordWidth")),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum plain::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum plain::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ImportSpine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ReSrcBody",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::ReSrcBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@1s_arm_enum transfer::Arm::NewSrcBody",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@canonical_vocab plain::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@canonical_vocab::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@refusal canonical::Refusal::NonMinimalTag",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@refusal canonical::Refusal::NonMinimalLen",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@refusal canonical::Refusal::NonMinimalValue",
        "width",
        xp("u8", "met padded value width, 2..=10"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@row_struct tolerant::Row",
        "tag_width",
        m("Option<WordWidth>"),
    ),
    e(
        "editor/groupless.rs",
        "one_shot_machine!::@row_struct tolerant::Row",
        "delim_width",
        m("Option<WordWidth>"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::WriteListFull",
        "need",
        nw("u32", "write-slot count pair"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::WriteListFull",
        "have",
        nw("u32", "write-slot count pair"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::ValueWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e("fixed_inplace/grouped.rs", "FaultKind::ValueWidth", "have", xp("u32", "the met slot width")),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::TagWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e("fixed_inplace/grouped.rs", "FaultKind::TagWidth", "have", xp("u32", "the met slot width")),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::PayloadLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::PayloadLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::FillerUnfit",
        "need",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::FillerUnfit",
        "have",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::ReplacementLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "FaultKind::ReplacementLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "StepCursor",
        "tag_w",
        xi(
            "u8",
            "walk progress: 0 = no record delivered yet, else the delivered head's met tag width",
        ),
    ),
    e(
        "fixed_inplace/grouped.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e("fixed_inplace/grouped.rs", "PendingPair", "start_width", m("WordWidth")),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::WriteListFull",
        "need",
        nw("u32", "write-slot count pair"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::WriteListFull",
        "have",
        nw("u32", "write-slot count pair"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::ValueWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::ValueWidth",
        "have",
        xp("u32", "the met slot width"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::TagWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e("fixed_inplace/groupless.rs", "FaultKind::TagWidth", "have", xp("u32", "the met slot width")),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::PayloadLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::PayloadLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::FillerUnfit",
        "need",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::FillerUnfit",
        "have",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::ReplacementLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "FaultKind::ReplacementLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "fixed_inplace/groupless.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e("fixed_inspect.rs", "OpenFault::SlabShort", "need", nw("u64", "slab byte claim pair")),
    e("fixed_inspect.rs", "OpenFault::SlabShort", "have", nw("u64", "slab byte claim pair")),
    e("fixed_inspect.rs", "StoreLane", "len", nw("u32", "store lane element count")),
    e(
        "fixed_inspect/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("fixed_inspect/grouped.rs", "Row", "tag_width", m("WordWidth")),
    e("fixed_inspect/grouped.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "fixed_inspect/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("fixed_inspect/groupless.rs", "Row", "tag_width", m("WordWidth")),
    e("fixed_inspect/groupless.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e("fixed_patch.rs", "Lane", "len", nw("u32", "store lane byte length")),
    e("fixed_patch.rs", "ByteLane", "len", nw("u32", "store lane byte length")),
    e("fixed_patch.rs", "PayloadSlot::Copied", "len", nw("u32", "copied payload byte extent")),
    e(
        "fixed_patch/grouped.rs",
        "FaultKind::PayloadCut",
        "need",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "fixed_patch/grouped.rs",
        "FaultKind::PayloadCut",
        "have",
        nw("u32", "payload byte claim pair"),
    ),
    e("fixed_patch/grouped.rs", "OpenFault::SlabShort", "need", nw("u64", "slab byte claim pair")),
    e("fixed_patch/grouped.rs", "OpenFault::SlabShort", "have", nw("u64", "slab byte claim pair")),
    e(
        "fixed_patch/grouped.rs",
        "SaveFault::OutputShort",
        "need",
        nw("u32", "output byte shortfall"),
    ),
    e("fixed_patch/grouped.rs", "Row", "tag_width", m("Option<WordWidth>")),
    e("fixed_patch/grouped.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "fixed_patch/grouped.rs",
        "Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "fixed_patch/grouped.rs",
        "Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "fixed_patch/grouped.rs",
        "CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "fixed_patch/groupless.rs",
        "FaultKind::PayloadCut",
        "need",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "fixed_patch/groupless.rs",
        "FaultKind::PayloadCut",
        "have",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "fixed_patch/groupless.rs",
        "OpenFault::SlabShort",
        "need",
        nw("u64", "slab byte claim pair"),
    ),
    e(
        "fixed_patch/groupless.rs",
        "OpenFault::SlabShort",
        "have",
        nw("u64", "slab byte claim pair"),
    ),
    e(
        "fixed_patch/groupless.rs",
        "SaveFault::OutputShort",
        "need",
        nw("u32", "output byte shortfall"),
    ),
    e("fixed_patch/groupless.rs", "Row", "tag_width", m("Option<WordWidth>")),
    e("fixed_patch/groupless.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "fixed_patch/groupless.rs",
        "Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "fixed_patch/groupless.rs",
        "Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "fixed_patch/groupless.rs",
        "CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e("inplace.rs", "Write::Varint", "width", m("ValueWidth")),
    e("inplace.rs", "Write::Tag", "width", m("WordWidth")),
    e(
        "inplace.rs",
        "Write::Filler",
        "width",
        nw("u32", "whole-record byte extent; width >= filler_need(field) was judged"),
    ),
    e(
        "inplace/grouped.rs",
        "FaultKind::ValueWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e("inplace/grouped.rs", "FaultKind::ValueWidth", "have", xp("u32", "the met slot width")),
    e(
        "inplace/grouped.rs",
        "FaultKind::TagWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e("inplace/grouped.rs", "FaultKind::TagWidth", "have", xp("u32", "the met slot width")),
    e(
        "inplace/grouped.rs",
        "FaultKind::PayloadLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "inplace/grouped.rs",
        "FaultKind::PayloadLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "inplace/grouped.rs",
        "FaultKind::FillerUnfit",
        "need",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "inplace/grouped.rs",
        "FaultKind::FillerUnfit",
        "have",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "inplace/grouped.rs",
        "FaultKind::ReplacementLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "inplace/grouped.rs",
        "FaultKind::ReplacementLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e("inplace/grouped.rs", "Layer", "remaining", nw("u16", "LEN-crossing depth budget countdown")),
    e("inplace/grouped.rs", "PendingPair", "start_width", m("WordWidth")),
    e(
        "inplace/groupless.rs",
        "FaultKind::ValueWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e("inplace/groupless.rs", "FaultKind::ValueWidth", "have", xp("u32", "the met slot width")),
    e(
        "inplace/groupless.rs",
        "FaultKind::TagWidth",
        "need",
        xp("u32", "the authored value's minimal width"),
    ),
    e("inplace/groupless.rs", "FaultKind::TagWidth", "have", xp("u32", "the met slot width")),
    e(
        "inplace/groupless.rs",
        "FaultKind::PayloadLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "inplace/groupless.rs",
        "FaultKind::PayloadLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "inplace/groupless.rs",
        "FaultKind::FillerUnfit",
        "need",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "inplace/groupless.rs",
        "FaultKind::FillerUnfit",
        "have",
        nw("u32", "filler byte extent claim pair (derived from a width, stored as extent)"),
    ),
    e(
        "inplace/groupless.rs",
        "FaultKind::ReplacementLength",
        "need",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "inplace/groupless.rs",
        "FaultKind::ReplacementLength",
        "have",
        nw("u32", "byte extent claim pair"),
    ),
    e(
        "inplace/groupless.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e(
        "inspect/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("inspect/grouped.rs", "Row", "tag_width", m("WordWidth")),
    e("inspect/grouped.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "inspect/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("inspect/groupless.rs", "Row", "tag_width", m("WordWidth")),
    e("inspect/groupless.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "maintain/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("maintain/grouped.rs", "FetchFault::Oversize", "len", nw("u64", "staged extent byte length")),
    e(
        "maintain/grouped.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "maintain/grouped.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e("maintain/grouped.rs", "SizeFrame::Len", "prefix_w", m("WordWidth")),
    e(
        "maintain/grouped.rs",
        "SizeFrame::Len",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e("maintain/grouped.rs", "SizeFrame::Len", "tag_w", m("WordWidth")),
    e(
        "maintain/grouped.rs",
        "CanonicalPayload::Doc",
        "len",
        nw("u64", "opaque payload byte extent"),
    ),
    e(
        "maintain/grouped.rs",
        "PayloadAnswer::Resident",
        "len",
        nw("u32", "resident payload byte extent"),
    ),
    e(
        "maintain/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e(
        "maintain/groupless.rs",
        "FetchFault::Oversize",
        "len",
        nw("u64", "staged extent byte length"),
    ),
    e(
        "maintain/groupless.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "maintain/groupless.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e("maintain/groupless.rs", "SizeFrame", "prefix_w", m("WordWidth")),
    e(
        "maintain/groupless.rs",
        "SizeFrame",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e("maintain/groupless.rs", "SizeFrame", "tag_w", m("WordWidth")),
    e(
        "maintain/groupless.rs",
        "CanonicalPayload::Doc",
        "len",
        nw("u64", "opaque payload byte extent"),
    ),
    e(
        "maintain/groupless.rs",
        "PayloadAnswer::Resident",
        "len",
        nw("u32", "resident payload byte extent"),
    ),
    e(
        "overhaul/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("overhaul/grouped.rs", "FetchFault::Oversize", "len", nw("u64", "staged extent byte length")),
    e(
        "overhaul/grouped.rs",
        "Row",
        "payload_len",
        nw(
            "u64",
            "payload extent; content is kind-dependent (LEN declared length, varint met width, fixed 4 or 8)",
        ),
    ),
    e("overhaul/grouped.rs", "Row", "tag_width", m("WordWidth")),
    e("overhaul/grouped.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "overhaul/grouped.rs",
        "overhaul_machine!::@save_view::Seal::Prefix",
        "prefix_src_w",
        m("WordWidth"),
    ),
    e(
        "overhaul/grouped.rs",
        "overhaul_machine!::@save_view::Seal::Prefix",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e("overhaul/grouped.rs", "overhaul_machine!::@save_view::Seal::End", "end_w", m("WordWidth")),
    e("overhaul/grouped.rs", "overhaul_machine!::@save_view::Frame", "head_w", m("WordWidth")),
    e(
        "overhaul/grouped.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "overhaul/grouped.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "overhaul/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e(
        "overhaul/groupless.rs",
        "FetchFault::Oversize",
        "len",
        nw("u64", "staged extent byte length"),
    ),
    e(
        "overhaul/groupless.rs",
        "Row",
        "payload_len",
        nw(
            "u64",
            "payload extent; content is kind-dependent (LEN declared length, varint met width, fixed 4 or 8)",
        ),
    ),
    e("overhaul/groupless.rs", "Row", "tag_width", m("WordWidth")),
    e("overhaul/groupless.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e("overhaul/groupless.rs", "overhaul_machine!::@save_view::Frame", "tag_w", m("WordWidth")),
    e(
        "overhaul/groupless.rs",
        "overhaul_machine!::@save_view::Frame",
        "prefix_src_w",
        m("WordWidth"),
    ),
    e(
        "overhaul/groupless.rs",
        "overhaul_machine!::@save_view::Frame",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "overhaul/groupless.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "overhaul/groupless.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e("pump.rs", "StagedHead", "len", xi("u8", "buf[..len] initialized and len <= 5; 0 = empty")),
    e(
        "refit/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("refit/grouped.rs", "FetchFault::Oversize", "len", nw("u64", "staged extent byte length")),
    e(
        "refit/grouped.rs",
        "Row",
        "payload_len",
        nw(
            "u64",
            "payload extent; content is kind-dependent (LEN declared length, varint minimal \
             width, fixed 4 or 8)",
        ),
    ),
    e(
        "refit/grouped.rs",
        "PayloadSlot::Parts",
        "len",
        nw("u32", "concatenated scatter byte extent, judged into the length class"),
    ),
    e(
        "refit/grouped.rs",
        "BorrowSlot::Parts",
        "len",
        nw("u32", "concatenated scatter byte extent, judged into the length class"),
    ),
    e(
        "refit/grouped.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "refit/grouped.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "refit/grouped.rs",
        "refit_machine!::@save_view::Seal::End",
        "end_w",
        xi("u64", "minimal end-tag byte count, the admission theorem's derivation"),
    ),
    e(
        "refit/grouped.rs",
        "refit_machine!::@save_view::Frame",
        "head_w",
        xi("u64", "minimal head-window byte count, the admission theorem's derivation"),
    ),
    e(
        "refit/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("refit/groupless.rs", "FetchFault::Oversize", "len", nw("u64", "staged extent byte length")),
    e(
        "refit/groupless.rs",
        "Row",
        "payload_len",
        nw(
            "u64",
            "payload extent; content is kind-dependent (LEN declared length, varint minimal \
             width, fixed 4 or 8)",
        ),
    ),
    e(
        "refit/groupless.rs",
        "PayloadSlot::Parts",
        "len",
        nw("u32", "concatenated scatter byte extent, judged into the length class"),
    ),
    e(
        "refit/groupless.rs",
        "BorrowSlot::Parts",
        "len",
        nw("u32", "concatenated scatter byte extent, judged into the length class"),
    ),
    e(
        "refit/groupless.rs",
        "Arm::ReBody",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "refit/groupless.rs",
        "Arm::Spine",
        "src_len",
        nw("u64", "source-body byte extent (verbatim criterion)"),
    ),
    e(
        "refit/groupless.rs",
        "refit_machine!::@save_view::Frame",
        "tag_w",
        xi("u64", "minimal head-window byte count, the admission theorem's derivation"),
    ),
    e("replay_convert/grouped.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("replay_convert/groupless.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("replay_pump.rs", "StepRead::Done", "width", m("W")),
    e("replay_pump.rs", "StepRead::NonMinimal", "width", m("W")),
    e(
        "replay_revise.rs",
        "revising_replay_store!::@len_role_base::PayloadLenOrValueWidth",
        "len_or_width",
        xi(
            "u32",
            "kind-coupled role word: a LEN's length-class payload length, a tolerant \
             varint's met value width in 1..=10, or zero when vacant — every \
             constructor takes the row kind it serves and refuses a foreign pairing",
        ),
    ),
    e(
        "replay_revise.rs",
        "revising_replay_store!::@store mixed::MixSlot::Copied",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "replay_revise.rs",
        "revising_replay_store!::@row tolerant::Row",
        "tag_width",
        m("Option<WordWidth>"),
    ),
    e(
        "replay_revise.rs",
        "revising_replay_store!::@row tolerant::Row",
        "delim_width",
        m("Option<WordWidth>"),
    ),
    e("replay_rewrite/grouped.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("replay_rewrite/groupless.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e(
        "replay_script.rs",
        "PrefixSlot",
        "width",
        xi(
            "u8",
            "settle states over (verbatim, width): open and verbatim hold 0, re-authored holds encoded_len32(word) in 1..=5",
        ),
    ),
    e("replay_script.rs", "Script", "out_len", nw("u64", "emitted output byte length")),
    e("replay_splice/grouped.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("replay_splice/groupless.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e(
        "retain/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("retain/grouped.rs", "Row", "tag_width", m("WordWidth")),
    e("retain/grouped.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "retain/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e("retain/groupless.rs", "Row", "tag_width", m("WordWidth")),
    e("retain/groupless.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "revise.rs",
        "revising_store!::@store_mixed noun::MixSlot::Copied",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@canonical_vocab plain::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@canonical_vocab::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@faults Machine::FaultKind::PayloadCut",
        "need",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@faults Machine::FaultKind::PayloadCut",
        "have",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@refusal canonical::Refusal::NonMinimalTag",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@refusal canonical::Refusal::NonMinimalLen",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@refusal canonical::Refusal::NonMinimalValue",
        "width",
        xp("u8", "met padded value width, 2..=10"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@row tolerant::Row",
        "tag_width",
        m("Option<WordWidth>"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@row tolerant::Row",
        "delim_width",
        m("Option<WordWidth>"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@size_frame tolerant::Close::Len",
        "prefix_w",
        m("Option<WordWidth>"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@size_frame tolerant::Close::Len",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@size_frame tolerant::Close::Len",
        "tag_w",
        m("WordWidth"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@size_frame tolerant::Close::ReGroup",
        "end_w",
        m("WordWidth"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@size_frame tolerant::Close::ReGroup",
        "tag_w",
        m("WordWidth"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum plain::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum plain::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum transfer::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum transfer::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum transfer::Arm::ReBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum transfer::Arm::ReBodyAlias",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum transfer::Arm::NewBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum transfer::Arm::ImportSpine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum::Arm::ReBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum::Arm::ReBodyAlias",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum::Arm::NewBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/grouped.rs",
        "revising_machine!::@arm_enum::Arm::BodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@canonical_vocab plain::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@canonical_vocab transfer::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@canonical_vocab::CanonicalPayload::Doc",
        "len",
        nw("u32", "copied payload byte extent"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@faults Machine::FaultKind::PayloadCut",
        "need",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@faults Machine::FaultKind::PayloadCut",
        "have",
        nw("u32", "payload byte claim pair"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@refusal canonical::Refusal::NonMinimalTag",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@refusal canonical::Refusal::NonMinimalLen",
        "width",
        xp("u8", "met padded framing width, 2..=5"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@refusal canonical::Refusal::NonMinimalValue",
        "width",
        xp("u8", "met padded value width, 2..=10"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@row tolerant::Row",
        "tag_width",
        m("Option<WordWidth>"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@row tolerant::Row",
        "delim_width",
        m("Option<WordWidth>"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@size_frame tolerant::SizeFrame",
        "prefix_w",
        m("Option<WordWidth>"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@size_frame tolerant::SizeFrame",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@size_frame tolerant::SizeFrame",
        "tag_w",
        m("WordWidth"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum plain::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum plain::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum transfer::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum transfer::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum transfer::Arm::ReBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum transfer::Arm::ReBodyAlias",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum transfer::Arm::NewBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum transfer::Arm::ImportSpine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum::Arm::ReBody",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum::Arm::Spine",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum::Arm::ReBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum::Arm::ReBodyAlias",
        "src_len",
        nw("u32", "source-body byte extent (verbatim criterion); u32::MAX = authored sentinel"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum::Arm::NewBodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum transfer::Arm::BodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "revise/groupless.rs",
        "revising_machine!::@arm_enum::Arm::BodyAlias",
        "len",
        nw("u32", "settle-arm byte extent (coordinates, not widths)"),
    ),
    e(
        "rewire/grouped.rs",
        "RuleFaultKind::RewriteOverflow",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "rewire/grouped.rs",
        "RuleFaultKind::RewriteOverflow",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e(
        "rewire/grouped.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "rewire/grouped.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e(
        "rewire/groupless.rs",
        "RuleFaultKind::RewriteOverflow",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "rewire/groupless.rs",
        "RuleFaultKind::RewriteOverflow",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e(
        "rewire/groupless.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "rewire/groupless.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e("rewrite.rs", "SlotValue::Dirty", "new_len", nw("u32", "staged replacement byte extent")),
    e("rewrite/grouped.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("rewrite/grouped.rs", "FaultKind::Output", "len", nw("u64", "output byte extent")),
    e("rewrite/grouped.rs", "Layer", "remaining", nw("u16", "LEN-crossing depth budget countdown")),
    e(
        "rewrite/grouped/transfer.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e("rewrite/groupless.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("rewrite/groupless.rs", "FaultKind::Output", "len", nw("u64", "output byte extent")),
    e(
        "rewrite/groupless.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e(
        "rewrite/groupless/transfer.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e("route/grouped/tests.rs", "Ev::Len", "len", nw("u32", "test event byte extent")),
    e("route/groupless/tests.rs", "Ev::Len", "len", nw("u32", "test event byte extent")),
    e("select/grouped.rs", "Layer", "remaining", nw("u16", "LEN-crossing depth budget countdown")),
    e(
        "select/groupless.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e("session.rs", "DocBytes", "len", nw("u32", "document byte length")),
    e("session.rs", "RawDoc", "len", nw("u32", "document byte length")),
    e("source/grouped.rs", "Geometry", "tag_w", m("WordWidth")),
    e("source/grouped.rs", "Geometry", "delim_w", m("Option<WordWidth>")),
    e(
        "source/grouped.rs",
        "Geometry",
        "payload_len",
        nw(
            "u32",
            "payload extent; content is kind-dependent (LEN declared length, varint met width, fixed 4 or 8)",
        ),
    ),
    e("source/groupless.rs", "Geometry", "tag_w", m("WordWidth")),
    e("source/groupless.rs", "Geometry", "delim_w", m("Option<WordWidth>")),
    e(
        "source/groupless.rs",
        "Geometry",
        "payload_len",
        nw(
            "u32",
            "payload extent; content is kind-dependent (LEN declared length, varint met width, fixed 4 or 8)",
        ),
    ),
    e("splice/back.rs", "Hole", "tail_len", nw("u32", "back-plan byte extent")),
    e("splice/back.rs", "Op::Staged", "len", nw("u32", "back-plan byte extent")),
    e("splice/back.rs", "Frame", "tail_len", nw("u32", "back-plan byte extent")),
    e("splice/grouped.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("splice/grouped.rs", "FaultKind::Output", "len", nw("u64", "output byte extent")),
    e("splice/grouped.rs", "Layer", "remaining", nw("u16", "LEN-crossing depth budget countdown")),
    e(
        "splice/grouped/transfer.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e("splice/groupless.rs", "FaultKind::Growth", "len", nw("u64", "output byte extent")),
    e("splice/groupless.rs", "FaultKind::Output", "len", nw("u64", "output byte extent")),
    e(
        "splice/groupless.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e(
        "splice/groupless/transfer.rs",
        "Layer",
        "remaining",
        nw("u16", "LEN-crossing depth budget countdown"),
    ),
    e("splice/transfer.rs", "Op::Staged", "len", nw("u32", "back-plan byte extent")),
    e("splice/transfer.rs", "Frame", "tail_len", nw("u32", "back-plan byte extent")),
    e(
        "stream_adopt/grouped.rs",
        "VarintCarry",
        "width",
        xi(
            "u8",
            "value bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("stream_adopt/grouped.rs", "Step::Done", "width", m("W")),
    e("stream_adopt/grouped.rs", "PendingHead", "tag_width", m("WordWidth")),
    e(
        "stream_adopt/grouped.rs",
        "Phase::Fixed",
        "remaining",
        xi(
            "u8",
            "fixed payload bytes still owed, counted down from the kind's 4 or 8; 0 = complete",
        ),
    ),
    e(
        "stream_adopt/groupless.rs",
        "VarintCarry",
        "width",
        xi(
            "u8",
            "value bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("stream_adopt/groupless.rs", "Step::Done", "width", m("W")),
    e("stream_adopt/groupless.rs", "PendingHead", "tag_width", m("WordWidth")),
    e(
        "stream_adopt/groupless.rs",
        "Phase::Fixed",
        "remaining",
        xi(
            "u8",
            "fixed payload bytes still owed, counted down from the kind's 4 or 8; 0 = complete",
        ),
    ),
    e(
        "stream_corpus.rs",
        "Body::Varint",
        "width",
        xp("u32", "authored spelling, clamped to >= minimal by widen()"),
    ),
    e(
        "stream_corpus.rs",
        "Body::Len",
        "prefix_width",
        xp("u32", "authored spelling, clamped to >= minimal by widen()"),
    ),
    e(
        "stream_corpus.rs",
        "Record",
        "tag_width",
        xp("u32", "authored spelling, clamped to >= minimal by widen()"),
    ),
    e(
        "stream_corpus.rs",
        "Expected",
        "tag_width",
        xp("u32", "authored spelling, clamped to >= minimal by widen()"),
    ),
    e(
        "stream_corpus.rs",
        "Expected",
        "delim_width",
        xp("u32", "authored spelling, clamped to >= minimal by widen()"),
    ),
    e(
        "stream_corpus.rs",
        "Expected",
        "payload_len",
        nw("u32", "corpus payload extent (a varint row's value width rides here)"),
    ),
    e(
        "stream_corpus.rs",
        "Node::Group",
        "tag_width",
        xp("u32", "authored spelling, clamped to >= minimal by widen()"),
    ),
    e(
        "stream_corpus.rs",
        "Node::Group",
        "end_width",
        xp("u32", "authored spelling, clamped to >= minimal by widen()"),
    ),
    e("stream_corpus.rs", "CutStage::Payload", "have", nw("u32", "corpus cut byte extents")),
    e("stream_corpus.rs", "CutStage::Payload", "need", nw("u32", "corpus cut byte extents")),
    e(
        "stream_draft/grouped.rs",
        "VarintCarry",
        "width",
        xi(
            "u8",
            "value bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("stream_draft/grouped.rs", "Step::Done", "width", m("W")),
    e("stream_draft/grouped.rs", "PendingHead", "tag_width", m("WordWidth")),
    e(
        "stream_draft/grouped.rs",
        "Phase::Fixed",
        "remaining",
        xi(
            "u8",
            "fixed payload bytes still owed, counted down from the kind's 4 or 8; 0 = complete",
        ),
    ),
    e(
        "stream_draft/groupless.rs",
        "VarintCarry",
        "width",
        xi(
            "u8",
            "value bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("stream_draft/groupless.rs", "Step::Done", "width", m("W")),
    e("stream_draft/groupless.rs", "PendingHead", "tag_width", m("WordWidth")),
    e(
        "stream_draft/groupless.rs",
        "Phase::Fixed",
        "remaining",
        xi(
            "u8",
            "fixed payload bytes still owed, counted down from the kind's 4 or 8; 0 = complete",
        ),
    ),
    e(
        "stream_intake/grouped.rs",
        "VarintCarry",
        "width",
        xi(
            "u8",
            "value bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("stream_intake/grouped.rs", "Step::Done", "width", m("W")),
    e("stream_intake/grouped.rs", "PendingHead", "tag_width", m("WordWidth")),
    e(
        "stream_intake/grouped.rs",
        "Phase::Fixed",
        "remaining",
        xi(
            "u8",
            "fixed payload bytes still owed, counted down from the kind's 4 or 8; 0 = complete",
        ),
    ),
    e(
        "stream_intake/groupless.rs",
        "VarintCarry",
        "width",
        xi(
            "u8",
            "value bytes consumed, acc in lockstep; backing suffix starts at accumulated - width; 0 = fresh",
        ),
    ),
    e("stream_intake/groupless.rs", "Step::Done", "width", m("W")),
    e("stream_intake/groupless.rs", "PendingHead", "tag_width", m("WordWidth")),
    e(
        "stream_intake/groupless.rs",
        "Phase::Fixed",
        "remaining",
        xi(
            "u8",
            "fixed payload bytes still owed, counted down from the kind's 4 or 8; 0 = complete",
        ),
    ),
    e("survey.rs", "FetchFault::Oversize", "len", nw("u64", "staged extent byte length")),
    e(
        "survey/grouped.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e(
        "survey/grouped.rs",
        "Row",
        "payload_len",
        nw(
            "u64",
            "payload extent; content is kind-dependent (LEN declared length, varint met width, fixed 4 or 8)",
        ),
    ),
    e("survey/grouped.rs", "Row", "tag_width", m("WordWidth")),
    e("survey/grouped.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "survey/groupless.rs",
        "FaultKind::FixedTruncated",
        "needed",
        xp("u8", "kind-required byte count, 4 or 8"),
    ),
    e(
        "survey/groupless.rs",
        "Row",
        "payload_len",
        nw(
            "u64",
            "payload extent; content is kind-dependent (LEN declared length, varint met width, fixed 4 or 8)",
        ),
    ),
    e("survey/groupless.rs", "Row", "tag_width", m("WordWidth")),
    e("survey/groupless.rs", "Row", "delim_width", m("Option<WordWidth>")),
    e(
        "transcode/grouped.rs",
        "RuleFaultKind::RewriteOverflow",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "transcode/grouped.rs",
        "RuleFaultKind::RewriteOverflow",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e(
        "transcode/grouped.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "transcode/grouped.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e(
        "transcode/groupless.rs",
        "RuleFaultKind::RewriteOverflow",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "transcode/groupless.rs",
        "RuleFaultKind::RewriteOverflow",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e(
        "transcode/groupless.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "width",
        xp("u8", "the completed construct's met width, 1..=10"),
    ),
    e(
        "transcode/groupless.rs",
        "RuleFaultKind::RewriteWidthMismatch",
        "need",
        xp("u8", "the rewrite value's standalone minimal width, 1..=10"),
    ),
    e(
        "varint.rs",
        "Minimal64",
        "width",
        xi(
            "u32",
            "pair invariant width == encoded_len64(value), established by the sole mint of(), spent by append_to",
        ),
    ),
    e(
        "varint/carry.rs",
        "Carry",
        "len",
        xi("u8", "buf[..len] initialized and len <= 10 with acc in lockstep; 0 = empty"),
    ),
];

/// Non-vacuity floors per class: a sweep finding fewer hits than
/// these is instrument failure, not success.
const MIGRATING_FLOOR: usize = 30;
const NOT_WIDTH_FLOOR: usize = 20;

// ─── judge 1: the manifest ───

#[test]
fn width_grammar_fields_match_the_manifest_exactly() {
    let mut counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut by_key: BTreeMap<(String, String, String), &Entry> = BTreeMap::new();
    for entry in MANIFEST {
        let key = (entry.file.to_owned(), entry.container.to_owned(), entry.field.to_owned());
        assert!(by_key.insert(key.clone(), entry).is_none(), "manifest repeats {key:?}");
        counts.insert(key, 0);
    }

    let mut errors = Vec::new();
    let mut class_hits = [0_usize; 4];
    for (rel, text) in src_files() {
        let stripped = strip_rust(&text);
        let (fields, _tuples) = scan(&stripped);
        for f in fields.iter().filter(|f| detected(f)) {
            let key = (rel.clone(), f.container.clone(), f.field.clone());
            let Some(entry) = by_key.get(&key) else {
                errors.push(format!(
                    "unmanifested hit: {rel}:{} {}::{} of type {}",
                    f.line, f.container, f.field, f.ty
                ));
                continue;
            };
            *counts.get_mut(&key).expect("keyed together") += 1;
            let (expected_ty, idx) = match entry.class {
                Class::Migrating { ty } => (ty, 0),
                Class::ExemptPublic { ty, .. } => (ty, 1),
                Class::ExemptInterior { ty, .. } => (ty, 2),
                Class::NotWidth { ty, .. } => (ty, 3),
            };
            class_hits[idx] += 1;
            if f.ty != expected_ty {
                errors.push(format!(
                    "{rel}:{} {}::{} declares {} where the manifest records {expected_ty}",
                    f.line, f.container, f.field, f.ty
                ));
            }
            match entry.class {
                Class::Migrating { ty } => {
                    assert!(
                        width_ty(ty) || ty == "W",
                        "manifest bug: Migrating {key:?} records raw {ty}"
                    );
                }
                Class::ExemptPublic { ty, domain } => {
                    assert!(prim(ty) && !domain.is_empty(), "manifest bug at {key:?}");
                    if !f.public {
                        errors.push(format!(
                            "{rel}:{} {}::{} is manifested ExemptPublic but not publicly \
                             reachable",
                            f.line, f.container, f.field
                        ));
                    }
                }
                Class::ExemptInterior { ty, invariant } => {
                    assert!(prim(ty) && !invariant.is_empty(), "manifest bug at {key:?}");
                    if f.public {
                        errors.push(format!(
                            "{rel}:{} {}::{} is manifested ExemptInterior but publicly \
                             reachable",
                            f.line, f.container, f.field
                        ));
                    }
                }
                Class::NotWidth { ty, class } => {
                    assert!(
                        (prim(ty) || opt_prim(ty)) && !class.is_empty(),
                        "manifest bug at {key:?}"
                    );
                }
            }
        }
    }

    for (key, count) in &counts {
        if *count != 1 {
            errors.push(format!(
                "manifest entry {key:?} hit {count} times (renamed, moved, or retired \
                 without a manifest update)"
            ));
        }
    }
    assert!(errors.is_empty(), "width law violations:\n{}", errors.join("\n"));

    let [migrating, exempt_public, exempt_interior, not_width] = class_hits;
    assert!(
        migrating >= MIGRATING_FLOOR && not_width >= NOT_WIDTH_FLOOR,
        "vacuous sweep: {migrating} migrating and {not_width} not-width hits"
    );
    assert!(
        exempt_public > 0 && exempt_interior > 0,
        "vacuous sweep: {exempt_public} public and {exempt_interior} interior hits"
    );
}

// ─── judge 2: mint discipline ───

/// `met_unchecked` call sites per file; each carries a `SAFETY`
/// comment within [`SAFETY_WINDOW`] lines above it.
const MET_PINS: &[(&str, usize)] = &[
    ("collect/grouped.rs", 2),
    ("collect/groupless.rs", 2),
    ("editor/grouped.rs", 10),
    ("editor/groupless.rs", 6),
    ("fixed_inplace/grouped.rs", 5),
    ("fixed_inplace/groupless.rs", 3),
    ("fixed_inspect/grouped.rs", 2),
    ("fixed_inspect/groupless.rs", 2),
    ("fixed_patch/grouped.rs", 2),
    ("fixed_patch/groupless.rs", 2),
    ("inplace/grouped.rs", 5),
    ("inplace/groupless.rs", 3),
    ("inspect/grouped.rs", 2),
    ("inspect/groupless.rs", 2),
    ("replay_pump.rs", 1),
    ("replay_revise.rs", 3),
    ("retain/grouped.rs", 2),
    ("retain/groupless.rs", 2),
    ("revise/grouped.rs", 6),
    ("revise/groupless.rs", 4),
    ("stream_adopt/grouped.rs", 1),
    ("stream_adopt/groupless.rs", 1),
    ("stream_draft/grouped.rs", 1),
    ("stream_draft/groupless.rs", 1),
    ("stream_intake/grouped.rs", 1),
    ("stream_intake/groupless.rs", 1),
    ("varint.rs", 3),
];

/// `minimal_of` call sites per file: the min-provenance edges.
const MINIMAL_PINS: &[(&str, usize)] = &[
    ("construct.rs", 1),
    ("editor/grouped.rs", 3),
    ("editor/groupless.rs", 2),
    ("overhaul/grouped.rs", 2),
    ("replay_revise.rs", 2),
    ("revise/grouped.rs", 5),
    ("revise/groupless.rs", 6),
];

/// `WordWidth::MIN` sites: the placeholder plants and the root's
/// own tests.
const MIN_PINS: &[(&str, usize)] = &[
    ("construct.rs", 1),
    ("overhaul/grouped.rs", 1),
    ("overhaul/groupless.rs", 1),
    ("varint.rs", 2),
];

/// A `SAFETY` comment must sit within this many lines above a
/// `met_unchecked` call (the widest current statement spans 14).
const SAFETY_WINDOW: usize = 16;

/// Occurrences of `needle` per line of `stripped`, 1-based.
fn call_sites(stripped: &str, needle: &str) -> Vec<usize> {
    let mut sites = Vec::new();
    for (idx, line) in stripped.lines().enumerate() {
        for _ in line.match_indices(needle) {
            sites.push(idx + 1);
        }
    }
    sites
}

#[test]
fn mint_doors_are_pinned_and_safety_commented() {
    let files = src_files();
    let met: BTreeMap<&str, usize> = MET_PINS.iter().copied().collect();
    let minimal: BTreeMap<&str, usize> = MINIMAL_PINS.iter().copied().collect();
    let min_pins: BTreeMap<&str, usize> = MIN_PINS.iter().copied().collect();
    let mut errors = Vec::new();
    let (mut met_total, mut minimal_total, mut min_total) = (0_usize, 0_usize, 0_usize);

    for (rel, text) in &files {
        let stripped = strip_rust(text);
        let original_lines: Vec<&str> = text.lines().collect();

        let met_sites = call_sites(&stripped, "::met_unchecked(");
        met_total += met_sites.len();
        let pinned = met.get(rel.as_str()).copied().unwrap_or(0);
        if met_sites.len() != pinned {
            errors.push(format!(
                "{rel}: {} met_unchecked call sites, {pinned} pinned (at lines {met_sites:?})",
                met_sites.len()
            ));
        }
        for line in met_sites {
            let window = &original_lines[line.saturating_sub(SAFETY_WINDOW + 1)..line - 1];
            if !window.iter().any(|l| l.contains("SAFETY")) {
                errors.push(format!("{rel}:{line}: met_unchecked without SAFETY above it"));
            }
        }

        let minimal_sites = call_sites(&stripped, "::minimal_of(");
        minimal_total += minimal_sites.len();
        let pinned = minimal.get(rel.as_str()).copied().unwrap_or(0);
        if minimal_sites.len() != pinned {
            errors.push(format!(
                "{rel}: {} minimal_of call sites, {pinned} pinned (at lines {minimal_sites:?})",
                minimal_sites.len()
            ));
        }

        // `WordWidth::MIN` with a word boundary after it.
        let mut min_sites = Vec::new();
        for (idx, line) in stripped.lines().enumerate() {
            for (at, _) in line.match_indices("WordWidth::MIN") {
                let after = line[at + "WordWidth::MIN".len()..].bytes().next();
                if !after.is_some_and(is_word_byte) {
                    min_sites.push(idx + 1);
                }
            }
        }
        min_total += min_sites.len();
        let pinned = min_pins.get(rel.as_str()).copied().unwrap_or(0);
        if min_sites.len() != pinned {
            errors.push(format!(
                "{rel}: {} WordWidth::MIN sites, {pinned} pinned (at lines {min_sites:?})",
                min_sites.len()
            ));
        }
        if stripped.contains("ValueWidth::MIN") {
            errors.push(format!("{rel}: ValueWidth::MIN exists but the type has no min face"));
        }

        // The unchecked door never opens outside the root.
        if rel != "varint.rs"
            && (stripped.contains("WordWidth::new_unchecked")
                || stripped.contains("ValueWidth::new_unchecked"))
        {
            errors.push(format!("{rel}: qualified new_unchecked mint outside src/varint.rs"));
        }
    }
    assert!(errors.is_empty(), "mint-door violations:\n{}", errors.join("\n"));

    assert_eq!(
        (met_total, minimal_total, min_total),
        (75, 21, 5),
        "door totals moved: update the pin tables from the tree"
    );

    // Instrument controls: the root's own text proves the needles
    // are visible to the stripped scan.
    let varint = &files.iter().find(|(rel, _)| rel == "varint.rs").expect("root exists").1;
    let stripped = strip_rust(varint);
    assert!(
        stripped.contains("Self::new_unchecked("),
        "control failed: the doors' own delegates are invisible"
    );
    let decls = |needle: &str| {
        files.iter().map(|(_, text)| strip_rust(text).matches(needle).count()).sum::<usize>()
    };
    assert_eq!(
        (decls("struct WordWidth("), decls("struct ValueWidth(")),
        (1, 1),
        "the width types must have exactly one declaration each"
    );
}

// ─── judge 3: positional stores ───

/// Every tuple struct over a bare primitive, by (file, name, first
/// field type): contract types minted by `define_valid_range_type!`,
/// full-domain coordinates, PRNGs, and test probes. A new entry
/// here is a conscious adjudication that the positional store is
/// not a width.
const TUPLE_PINS: &[(&str, &str, &str)] = &[
    ("admission.rs", "Coord", "u32"),
    ("admission.rs", "Extent", "u32"),
    ("collect.rs", "NodeId", "u32"),
    ("commission.rs", "LayerId", "u32"),
    ("commission.rs", "SourceRunId", "u32"),
    ("construct.rs", "BorrowAt", "u32"),
    ("cursor.rs", "GroupDepth", "u16"),
    ("editor.rs", "RowId", "u32"),
    ("editor.rs", "WordAt", "u32"),
    ("editor.rs", "PayloadAt", "u32"),
    ("fixed_inspect.rs", "FrameAt", "u16"),
    ("fixed_patch.rs", "RowId", "u32"),
    ("fixed_patch.rs", "WordAt", "u32"),
    ("fixed_patch.rs", "PayloadAt", "u32"),
    ("inspect.rs", "NodeId", "u32"),
    ("inspect.rs", "RowCount", "u32"),
    ("lib.rs", "DepthLimit", "u16"),
    ("maintain.rs", "LayerId", "u32"),
    ("maintain.rs", "SourceRunId", "u32"),
    ("overhaul.rs", "RowId", "u32"),
    ("path.rs", "PathId", "u16"),
    ("path.rs", "GapMask", "u8"),
    ("path.rs", "Rng", "u64"),
    ("refit.rs", "RowId", "u32"),
    ("replay_revise.rs", "RowId", "u32"),
    ("replay_revise.rs", "At64", "u64"),
    ("replay_revise.rs", "ValueAt", "u32"),
    ("replay_source.rs", "AuthoredAt", "u32"),
    ("replay_source.rs", "SlotAt", "u32"),
    ("replay_source.rs", "SourceAt", "u64"),
    ("replay_splice/grouped/tests.rs", "Spy", "u32"),
    ("replay_splice/groupless/tests.rs", "OneDeep", "u32"),
    ("replay_splice/groupless/tests.rs", "Counter", "u32"),
    ("retain.rs", "NodeId", "u32"),
    ("revise.rs", "RowId", "u32"),
    ("revise.rs", "At32", "u32"),
    ("revise.rs", "ValueAt", "u32"),
    ("revise.rs", "RowId", "u32"),
    ("revise.rs", "At32", "u32"),
    ("revise.rs", "ValueAt", "u32"),
    ("revise.rs", "RowId", "u32"),
    ("revise.rs", "At32", "u32"),
    ("revise.rs", "ValueAt", "u32"),
    ("revise.rs", "RowId", "u32"),
    ("revise.rs", "At32", "u32"),
    ("revise.rs", "ValueAt", "u32"),
    ("revise/grouped.rs", "LayerId", "u32"),
    ("revise/grouped.rs", "SourceRunId", "u32"),
    ("revise/groupless.rs", "LayerId", "u32"),
    ("revise/groupless.rs", "SourceRunId", "u32"),
    ("route/groupless/tests.rs", "Count", "u32"),
    ("session/grouped/tests.rs", "XorShift", "u32"),
    ("session/groupless/tests.rs", "XorShift", "u32"),
    ("survey.rs", "NodeId", "u32"),
    ("transcode/grouped/tests.rs", "DropField", "u32"),
    ("transcode/grouped/tests.rs", "RewriteVarint", "u32"),
    ("transcode/grouped/tests.rs", "LockedRewrite", "u64"),
    ("transcode/grouped/tests.rs", "ReplaceLen", "u32"),
    ("varint.rs", "WordWidth", "u8"),
    ("varint.rs", "ValueWidth", "u8"),
    ("wire.rs", "FieldNumber", "u32"),
    ("wire.rs", "PayloadLen", "u32"),
    ("wire.rs", "Low3", "u8"),
];

#[test]
fn tuple_structs_over_primitives_are_pinned() {
    let mut found = Vec::new();
    for (rel, text) in src_files() {
        let stripped = strip_rust(&text);
        let (_fields, tuples) = scan(&stripped);
        for t in tuples {
            if prim(&t.first_ty) {
                found.push((rel.clone(), t.name, t.first_ty));
            }
        }
    }
    found.sort();
    let mut pinned: Vec<(String, String, String)> =
        TUPLE_PINS.iter().map(|&(f, n, t)| (f.to_owned(), n.to_owned(), t.to_owned())).collect();
    pinned.sort();
    assert_eq!(
        found, pinned,
        "tuple structs over primitives moved: re-derive the pin list from the tree"
    );
}

// ─── judge 4: instrument controls ───

/// Planted declarations, one per spelling class the detector must
/// see — and the shapes it must stay blind to.
const PROBE: &str = r#"
pub struct Plain {
    /// width: u8 in a doc comment is not a declaration.
    pub width: u8,
    #[cfg(feature = "x")]
    #[doc(alias = "stacked")]
    tag_width: Option<WordWidth>,
    delim_width:
        Option<WordWidth>,
    other: u32,
}
enum Verdict<W> {
    Done {
        width: W,
    },
}
macro_rules! probe {
    (@row tolerant) => {
        struct Row {
            src_len: u32,
        }
    };
}
struct Sneak(u8);
fn not_a_field(width: u8) -> u8 {
    let len: u8 = width;
    let s = "width: u8";
    let _ = s;
    Plain { width: len }.width
}
"#;

#[test]
fn planted_probes_calibrate_the_detector() {
    let stripped = strip_rust(PROBE);
    let (fields, tuples) = scan(&stripped);
    let hits: Vec<(String, String, String, bool)> = fields
        .iter()
        .filter(|f| detected(f))
        .map(|f| (f.container.clone(), f.field.clone(), f.ty.clone(), f.public))
        .collect();
    let expected: Vec<(String, String, String, bool)> = [
        ("Plain", "width", "u8", true),
        ("Plain", "tag_width", "Option<WordWidth>", false),
        ("Plain", "delim_width", "Option<WordWidth>", false),
        ("Verdict::Done", "width", "W", false),
        ("probe!::@row tolerant::Row", "src_len", "u32", false),
    ]
    .iter()
    .map(|&(c, f, t, p)| (c.to_owned(), f.to_owned(), t.to_owned(), p))
    .collect();
    assert_eq!(hits, expected, "the detector drifted off the planted spelling classes");

    // The tuple probe: nameless stores are invisible to the field
    // grammar and must therefore be caught by the tuple scan.
    let tuple_hits: Vec<(String, String)> =
        tuples.into_iter().filter(|t| prim(&t.first_ty)).map(|t| (t.name, t.first_ty)).collect();
    assert_eq!(tuple_hits, vec![("Sneak".to_owned(), "u8".to_owned())], "the tuple probe drifted");
}
