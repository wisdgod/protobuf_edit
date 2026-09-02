//! Hand-built tolerant-domain documents: each pairs a padded
//! encoding with its canonical twin — the same record sequence with
//! every varint site minimal. Padding widens a tag, a length
//! prefix, or a varint value without moving any value reading;
//! where a widened interior changes a payload's byte count, every
//! enclosing length prefix re-derives (the cascade geometry).
//!
//! LEN payloads stay clear of the message-speculation ambiguity
//! band: each is either a message every reader descends into or a
//! blob every reader refuses (the first speculated tag faults), so
//! the value reading never hinges on a guess.

/// One LEN payload's adjudicated reading — the membership witness
/// that keeps the batch out of the speculation ambiguity band. The
/// consuming pin judges it with the machine: a `Message` payload
/// parses completely (every descending reader agrees), a `Bytes`
/// payload faults speculation (every reader refuses).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LenReading {
    /// A message every reader descends into.
    Message,
    /// A blob every reader refuses to parse.
    Bytes,
}

/// One document pair. `groupless` marks the padded bytes free of
/// group codes at every parsed tag position — lawful for the
/// groupless dialect; both flags' faces are asserted by the
/// consuming tests, so a mislabel cannot pass silently. `lens`
/// declares every LEN payload's reading in parse order (pre-order,
/// outermost first) — the same order on the padded bytes and the
/// twin, judged on both.
pub struct PaddedDoc {
    /// Case name, quoted by every assertion.
    pub name: &'static str,
    /// Hex of the padded document (whitespace ignored).
    pub padded: &'static str,
    /// Hex of the canonical twin (whitespace ignored).
    pub twin: &'static str,
    /// Lawful in the groupless dialect.
    pub groupless: bool,
    /// Every LEN payload's reading, in parse order.
    #[allow(
        dead_code,
        reason = "the support file is included per test target, and each target \
                  reads its own subset of the document faces"
    )]
    pub lens: &'static [LenReading],
}

/// The batch: 12 documents, 10 of them groupless-lawful. Consumers
/// pin both counts so a shrunken loop cannot pass vacuously.
pub const DOCS: &[PaddedDoc] = &[
    // ─── root tags ───
    // Padding site: the middle record's root tag, 0x10 widened to
    // 90 00. The twin restores the one-byte tag; the flanking
    // records pin that the reader resynchronizes on both sides.
    PaddedDoc {
        name: "root_tag_widened_mid_document",
        padded: "0801 9000 02 1803",
        twin: "0801 1002 1803",
        groupless: true,
        lens: &[],
    },
    // Padding site: the root tag at the five-byte window cap, 0x08
    // widened to 88 80 80 80 00. The twin is the spec worked
    // example, field 1 varint 150.
    PaddedDoc {
        name: "root_tag_widened_to_cap",
        padded: "8880808000 9601",
        twin: "08 9601",
        groupless: true,
        lens: &[],
    },
    // ─── varint values ───
    // Padding site: the varint value 150, 96 01 widened to
    // 96 81 00; a second record follows the widened value. The twin
    // minimizes the value and keeps the neighbor.
    PaddedDoc {
        name: "varint_value_widened",
        padded: "08 968100 1001",
        twin: "08 9601 1001",
        groupless: true,
        lens: &[],
    },
    // Padding site: the varint value 150 at the ten-byte value
    // window cap (nonzero, unlike the corpus zero pin). The twin is
    // the two-byte minimal value.
    PaddedDoc {
        name: "varint_value_widened_to_cap",
        padded: "08 96818080808080808000",
        twin: "08 9601",
        groupless: true,
        lens: &[],
    },
    // ─── length prefixes and cascades ───
    // Padding site: the root LEN prefix, 03 widened to 83 00, over
    // a payload that is a clean message. No cascade — the root has
    // no enclosing length. The twin is the spec nested example.
    PaddedDoc {
        name: "outer_len_prefix_widened",
        padded: "1A 8300 089601",
        twin: "1A 03 089601",
        groupless: true,
        lens: &[LenReading::Message],
    },
    // Padding site: the nested LEN prefix, 01 widened to 81 00,
    // one level down. One cascade: the root prefix re-derives its
    // value (04) against the twin's (03) to seat the wider inner
    // prefix.
    PaddedDoc {
        name: "nested_len_prefix_widened",
        padded: "1A04 128100 61",
        twin: "1A03 1201 61",
        groupless: true,
        lens: &[LenReading::Message, LenReading::Bytes],
    },
    // Padding site: the innermost LEN prefix at depth two, 01
    // widened to 81 00. Two cascades: both enclosing prefixes
    // re-derive (root 06 over the twin's 05, middle 04 over 03).
    PaddedDoc {
        name: "cascade_len_prefix_two_levels",
        padded: "1A06 1A04 128100 61",
        twin: "1A05 1A03 1201 61",
        groupless: true,
        lens: &[LenReading::Message, LenReading::Message, LenReading::Bytes],
    },
    // Padding site: the nested LEN prefix, 05 widened to 85 00,
    // over a blob payload ("hello" fails message speculation at its
    // third byte in every reader). One cascade: the root prefix
    // re-derives (08 over the twin's 07).
    PaddedDoc {
        name: "nested_blob_prefix_widened",
        padded: "1A08 128500 68656C6C6F",
        twin: "1A07 1205 68656C6C6F",
        groupless: true,
        lens: &[LenReading::Message, LenReading::Bytes],
    },
    // ─── fixed-width neighbors ───
    // Padding sites: both varint tags (88 00, 90 00) and the second
    // varint's value (96 81 00), bracketing an I32 whose payload
    // bytes EF BE AD DE all carry the varint continuation bit — a
    // desynchronized reader cannot cross it. The twin minimizes all
    // three varint sites around the identical fixed record.
    PaddedDoc {
        name: "fixed32_between_padded_varints",
        padded: "8800 01 0D EFBEADDE 9000 968100",
        twin: "0801 0DEFBEADDE 10 9601",
        groupless: true,
        lens: &[],
    },
    // Padding site: a varint value zero at the ten-byte cap wedged
    // between an all-ones I64 and an I32. The fixed payloads are
    // read by width alone; the twin shrinks only the varint value.
    PaddedDoc {
        name: "fixed64_before_value_cap_padding",
        padded: "09 FFFFFFFFFFFFFFFF 08 80808080808080808000 0D 01000000",
        twin: "09 FFFFFFFFFFFFFFFF 0800 0D 01000000",
        groupless: true,
        lens: &[],
    },
    // ─── group interiors (grouped dialect only) ───
    // Padding sites: inside a minimally-framed group, the interior
    // record's tag (88 00) and value (96 81 00). The twin is the
    // corpus group_match document.
    PaddedDoc {
        name: "group_interior_padded",
        padded: "0B 8800 968100 0C",
        twin: "0B 089601 0C",
        groupless: false,
        lens: &[],
    },
    // Padding sites: both group framing tags (SGROUP 8B 00,
    // EGROUP 8C 80 00 — asymmetric widths) and the interior LEN
    // prefix (81 00). Group framing is not length-prefixed, so no
    // cascade. The twin minimizes all three sites.
    PaddedDoc {
        name: "group_framing_and_interior_padded",
        padded: "8B00 128100 61 8C8000",
        twin: "0B 120161 0C",
        groupless: false,
        lens: &[LenReading::Bytes],
    },
];
