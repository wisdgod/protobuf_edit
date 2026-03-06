use crate::error::{UiError, UiResult};

use super::model::{MessageId, DEFAULT_FRAME_NAME_TEMPLATE};

const KEY_CURRENT: &str = "protobuf_decoder_web.v1.current_message";
const KEY_NEXT_ID: &str = "protobuf_decoder_web.v1.next_message_id";
const KEY_FRAME_NAME_TEMPLATE: &str = "protobuf_decoder_web.v1.frame_name_template";
const KEY_THEME_PREF: &str = "protobuf_decoder_web.v1.theme";

pub(crate) fn store_theme_pref(pref: &str) -> UiResult<()> {
    let pref = match pref.trim() {
        "light" => "light",
        "dark" => "dark",
        "system" => "system",
        other => {
            return Err(format!(
                "Invalid theme pref {other:?}. Expected \"light\", \"dark\", or \"system\"."
            )
            .into());
        }
    };
    storage_set(KEY_THEME_PREF, pref)
}

pub(crate) fn load_frame_name_template() -> UiResult<String> {
    Ok(storage_get(KEY_FRAME_NAME_TEMPLATE)?.unwrap_or_else(|| DEFAULT_FRAME_NAME_TEMPLATE.into()))
}

pub(crate) fn store_frame_name_template(template: &str) -> UiResult<()> {
    let template = template.trim();
    if template.is_empty() || template == DEFAULT_FRAME_NAME_TEMPLATE {
        return storage_remove(KEY_FRAME_NAME_TEMPLATE);
    }
    storage_set(KEY_FRAME_NAME_TEMPLATE, template)
}

pub(crate) fn current_message() -> UiResult<Option<MessageId>> {
    let Some(raw) = storage_get(KEY_CURRENT)? else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    raw.trim().parse::<MessageId>().map(Some).map_err(|_| "Invalid current message id.".into())
}

pub(crate) fn set_current_message(id: Option<MessageId>) -> UiResult<()> {
    match id {
        Some(id) => storage_set(KEY_CURRENT, &id.to_string())?,
        None => storage_remove(KEY_CURRENT)?,
    }
    Ok(())
}

pub(crate) fn download_filename(name: &str, id: MessageId) -> String {
    let mut base = sanitize_filename(name);
    if base.is_empty() {
        base = format!("message-{id}");
    }
    format!("{base}.bin")
}

pub(super) fn alloc_message_id() -> UiResult<MessageId> {
    let raw = storage_get(KEY_NEXT_ID)?.unwrap_or_else(|| "1".to_string());
    let next = raw.trim().parse::<u64>().unwrap_or(1);
    let bumped = next.saturating_add(1);
    storage_set(KEY_NEXT_ID, &bumped.to_string())?;
    Ok(MessageId::new(next))
}

fn sanitize_filename(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        let mapped = match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => Some(ch),
            '-' | '_' => Some(ch),
            ' ' => Some('-'),
            _ => None,
        };
        if let Some(ch) = mapped {
            out.push(ch);
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').to_string()
}

fn storage() -> UiResult<web_sys::Storage> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    let storage = window
        .local_storage()
        .map_err(|err| UiError::from(format!("Failed to access localStorage: {err:?}")))?
        .ok_or("localStorage is not available.")?;
    Ok(storage)
}

fn storage_get(key: &str) -> UiResult<Option<String>> {
    storage()?
        .get_item(key)
        .map_err(|err| UiError::from(format!("localStorage.get_item failed: {err:?}")))
}

fn storage_set(key: &str, value: &str) -> UiResult<()> {
    storage()?
        .set_item(key, value)
        .map_err(|err| UiError::from(format!("localStorage.set_item failed: {err:?}")))
}

fn storage_remove(key: &str) -> UiResult<()> {
    storage()?
        .remove_item(key)
        .map_err(|err| UiError::from(format!("localStorage.remove_item failed: {err:?}")))
}
