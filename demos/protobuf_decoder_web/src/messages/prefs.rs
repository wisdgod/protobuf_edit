use crate::error::{UiError, UiResult};

use super::model::{MessageId, DEFAULT_FRAME_NAME_TEMPLATE};

const KEY_OPEN_TABS: &str = "protobuf_decoder_web.v1.open_tabs";
const KEY_ACTIVE_TAB: &str = "protobuf_decoder_web.v1.active_tab";
const KEY_NEXT_ID: &str = "protobuf_decoder_web.v1.next_message_id";
const KEY_FRAME_NAME_TEMPLATE: &str = "protobuf_decoder_web.v1.frame_name_template";
const KEY_THEME_PREF: &str = "protobuf_decoder_web.v1.theme";
const KEY_LOCALE: &str = "protobuf_decoder_web.v1.locale";
const KEY_READ_ONLY: &str = "protobuf_decoder_web.v1.read_only";

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

pub(crate) fn load_locale() -> Option<String> {
    storage_get(KEY_LOCALE).ok().flatten()
}

pub(crate) fn store_locale(locale: &str) -> UiResult<()> {
    storage_set(KEY_LOCALE, locale)
}

pub(crate) fn load_read_only() -> bool {
    storage_get(KEY_READ_ONLY).ok().flatten().is_some_and(|v| v == "1")
}

pub(crate) fn store_read_only(read_only: bool) -> UiResult<()> {
    if read_only { storage_set(KEY_READ_ONLY, "1") } else { storage_remove(KEY_READ_ONLY) }
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

/// Persisted identity of one open tab: a message document or an envelope
/// frame browser for a source message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistedTab {
    Message(MessageId),
    Envelope(MessageId),
}

impl PersistedTab {
    pub(crate) const fn message_id(self) -> MessageId {
        match self {
            Self::Message(id) | Self::Envelope(id) => id,
        }
    }

    fn encode(self) -> String {
        match self {
            Self::Message(id) => format!("m:{id}"),
            Self::Envelope(id) => format!("e:{id}"),
        }
    }

    fn decode(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if let Some(rest) = raw.strip_prefix("m:") {
            return rest.parse::<MessageId>().ok().map(Self::Message);
        }
        if let Some(rest) = raw.strip_prefix("e:") {
            return rest.parse::<MessageId>().ok().map(Self::Envelope);
        }
        // Legacy bare message id.
        raw.parse::<MessageId>().ok().map(Self::Message)
    }
}

/// Persisted working set: open tabs, in tab order.
pub(crate) fn open_tabs() -> UiResult<Vec<PersistedTab>> {
    let Some(raw) = storage_get(KEY_OPEN_TABS)? else {
        return Ok(Vec::new());
    };
    Ok(raw.split(',').filter_map(PersistedTab::decode).collect())
}

pub(crate) fn set_open_tabs(tabs: &[PersistedTab]) -> UiResult<()> {
    if tabs.is_empty() {
        return storage_remove(KEY_OPEN_TABS);
    }
    let joined = tabs.iter().map(|t| t.encode()).collect::<Vec<_>>().join(",");
    storage_set(KEY_OPEN_TABS, &joined)
}

/// Persisted active tab; `None` means the start view.
pub(crate) fn active_tab() -> UiResult<Option<PersistedTab>> {
    let Some(raw) = storage_get(KEY_ACTIVE_TAB)? else {
        return Ok(None);
    };
    Ok(PersistedTab::decode(&raw))
}

pub(crate) fn set_active_tab(tab: Option<PersistedTab>) -> UiResult<()> {
    match tab {
        Some(tab) => storage_set(KEY_ACTIVE_TAB, &tab.encode()),
        None => storage_remove(KEY_ACTIVE_TAB),
    }
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
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => Some(ch),
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
