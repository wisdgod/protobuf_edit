use base64::Engine as _;

use crate::error::UiResult;

pub(crate) fn decode_user_input(input: &str) -> UiResult<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Input is empty.".into());
    }

    let no_ws: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let no_ws = no_ws.as_str();
    if no_ws.is_empty() {
        return Err("Input is empty.".into());
    }

    let hex_candidate = no_ws.strip_prefix("0x").unwrap_or(no_ws);
    let looks_like_hex = hex_candidate.len().is_multiple_of(2)
        && !hex_candidate.is_empty()
        && hex_candidate.chars().all(|c| c.is_ascii_hexdigit());

    if looks_like_hex && let Ok(bytes) = hex::decode(hex_candidate) {
        return Ok(bytes);
    }

    let b64_candidate = no_ws;
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64_candidate) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(b64_candidate) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64_candidate) {
        return Ok(bytes);
    }

    Err("Failed to decode input as hex or base64.".into())
}

pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn encode_base64_url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn decode_base64_url(input: &str) -> UiResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| format!("Failed to decode URL-safe base64: {e}").into())
}
