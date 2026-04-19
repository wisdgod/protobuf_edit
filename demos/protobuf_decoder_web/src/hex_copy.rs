use std::fmt::Write;

use base64::Engine;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyFormat {
    HexSpaced,
    HexCompact,
    HexDump,
    CArray,
    CEscape,
    RustArray,
    Base64,
}

impl CopyFormat {
    pub const ALL: &[Self] = &[
        Self::HexSpaced,
        Self::HexCompact,
        Self::HexDump,
        Self::CArray,
        Self::CEscape,
        Self::RustArray,
        Self::Base64,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::HexSpaced => "Hex (spaced)",
            Self::HexCompact => "Hex (compact)",
            Self::HexDump => "Hex dump",
            Self::CArray => "C array",
            Self::CEscape => "C escape",
            Self::RustArray => "Rust array",
            Self::Base64 => "Base64",
        }
    }

    pub fn format(self, bytes: &[u8]) -> String {
        match self {
            Self::HexSpaced => format_hex_spaced(bytes),
            Self::HexCompact => format_hex_compact(bytes),
            Self::HexDump => format_hex_dump(bytes),
            Self::CArray => format_c_array(bytes),
            Self::CEscape => format_c_escape(bytes),
            Self::RustArray => format_rust_array(bytes),
            Self::Base64 => format_base64(bytes),
        }
    }
}

fn format_hex_spaced(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02X}");
    }
    out
}

fn format_hex_compact(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

fn format_hex_dump(bytes: &[u8]) -> String {
    let rows = bytes.len().div_ceil(16);
    let mut out = String::with_capacity(rows * 78);
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let offset = row * 16;
        let _ = write!(out, "{offset:08X}  ");

        for (i, &b) in chunk.iter().enumerate() {
            if i == 8 {
                out.push(' ');
            }
            let _ = write!(out, "{b:02X} ");
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        if chunk.len() <= 8 {
            out.push(' ');
        }

        out.push(' ');
        out.push('|');
        for &b in chunk {
            let ch = if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' };
            out.push(ch);
        }
        out.push('|');
        out.push('\n');
    }
    out
}

fn format_c_array(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 6 + 4);
    out.push_str("{ ");
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "0x{b:02X}");
    }
    out.push_str(" }");
    out
}

fn format_c_escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for &b in bytes {
        let _ = write!(out, "\\x{b:02X}");
    }
    out
}

fn format_rust_array(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 6 + 2);
    out.push('[');
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "0x{b:02X}");
    }
    out.push(']');
    out
}

fn format_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_spaced() {
        assert_eq!(CopyFormat::HexSpaced.format(b"AB"), "41 42");
    }

    #[test]
    fn hex_compact() {
        assert_eq!(CopyFormat::HexCompact.format(b"AB"), "4142");
    }

    #[test]
    fn c_array() {
        assert_eq!(CopyFormat::CArray.format(b"\x00\xFF"), "{ 0x00, 0xFF }");
    }

    #[test]
    fn c_escape() {
        assert_eq!(CopyFormat::CEscape.format(b"\x4A\x6F"), "\\x4A\\x6F");
    }

    #[test]
    fn rust_array() {
        assert_eq!(CopyFormat::RustArray.format(b"\x4A\x6F"), "[0x4A, 0x6F]");
    }

    #[test]
    fn base64() {
        assert_eq!(CopyFormat::Base64.format(b"John"), "Sm9obg==");
    }

    #[test]
    fn hex_dump_single_row() {
        let bytes = b"Hello, World!";
        let dump = CopyFormat::HexDump.format(bytes);
        assert!(dump.starts_with("00000000  48 65 6C 6C 6F 2C 20 57  6F 72 6C 64 21"));
        assert!(dump.contains("|Hello, World!|"));
    }
}
