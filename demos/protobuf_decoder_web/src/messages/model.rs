use crate::bytes::ByteView;
use crate::error::{UiError, UiResult};
use crate::fx::FxHashMap;
use js_sys::{Object, Reflect};
use std::sync::Arc;
use wasm_bindgen::{JsCast as _, JsValue};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MessageId(u64);

impl MessageId {
    #[inline]
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl core::fmt::Display for MessageId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl core::str::FromStr for MessageId {
    type Err = core::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = s.parse::<u64>()?;
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MessageMeta {
    pub id: MessageId,
    pub class_id: MessageId,
    pub class_name: Arc<str>,
    pub name: Arc<str>,
    pub modified_ms: u64,
    pub bytes_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoadedBytesMode {
    Protobuf,
    Raw,
}

pub(crate) struct LoadedBytes {
    pub bytes: ByteView,
    pub mode: LoadedBytesMode,
    pub note: Option<UiError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EnvelopeFrameRef {
    pub(super) source_id: MessageId,
    pub(super) source_modified_ms: u64,
    pub(super) payload_offset: usize,
    pub(super) payload_len: usize,
    pub(super) flags: u8,
    pub(super) decompress: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MessageRecord {
    pub(super) id: MessageId,
    pub(super) class_id: MessageId,
    pub(super) name: Arc<str>,
    pub(super) modified_ms: u64,
    pub(super) bytes_len: usize,
    pub(super) envelope_ref: Option<EnvelopeFrameRef>,
}

const META_ID: &str = "id";
const META_CLASS_ID: &str = "class_id";
const META_NAME: &str = "name";
const META_MODIFIED_MS: &str = "modified_ms";
const META_BYTES_LEN: &str = "bytes_len";
const META_REF_KIND: &str = "ref_kind";
const META_REF_SOURCE_ID: &str = "ref_source_id";
const META_REF_SOURCE_MODIFIED_MS: &str = "ref_source_modified_ms";
const META_REF_PAYLOAD_OFFSET: &str = "ref_payload_offset";
const META_REF_PAYLOAD_LEN: &str = "ref_payload_len";
const META_REF_FLAGS: &str = "ref_flags";
const META_REF_DECOMPRESS: &str = "ref_decompress";

const CLASS_META_ID: &str = "id";
const CLASS_META_NAME: &str = "name";

pub(crate) const DEFAULT_FRAME_NAME_TEMPLATE: &str = "{source} frame {idx} ({len}B)";

pub(super) fn message_record_to_js(record: &MessageRecord) -> UiResult<JsValue> {
    let obj = Object::new();
    js_set(&obj, META_ID, JsValue::from_str(&record.id.to_string()))?;
    js_set(&obj, META_CLASS_ID, JsValue::from_str(&record.class_id.to_string()))?;
    js_set(&obj, META_NAME, JsValue::from_str(record.name.as_ref()))?;
    js_set(&obj, META_MODIFIED_MS, JsValue::from_f64(record.modified_ms as f64))?;
    js_set(&obj, META_BYTES_LEN, JsValue::from_f64(record.bytes_len as f64))?;

    if let Some(meta) = record.envelope_ref {
        js_set(&obj, META_REF_KIND, JsValue::from_str("envelope_frame"))?;
        js_set(&obj, META_REF_SOURCE_ID, JsValue::from_str(&meta.source_id.to_string()))?;
        js_set(
            &obj,
            META_REF_SOURCE_MODIFIED_MS,
            JsValue::from_f64(meta.source_modified_ms as f64),
        )?;
        js_set(&obj, META_REF_PAYLOAD_OFFSET, JsValue::from_f64(meta.payload_offset as f64))?;
        js_set(&obj, META_REF_PAYLOAD_LEN, JsValue::from_f64(meta.payload_len as f64))?;
        js_set(&obj, META_REF_FLAGS, JsValue::from_f64(meta.flags as f64))?;
        js_set(&obj, META_REF_DECOMPRESS, JsValue::from_bool(meta.decompress))?;
    }

    Ok(obj.into())
}

pub(super) fn load_class_name_map(raw: Vec<JsValue>) -> UiResult<FxHashMap<MessageId, Arc<str>>> {
    let mut out: FxHashMap<MessageId, Arc<str>> = FxHashMap::default();
    for value in raw {
        let (id, name) = class_record_from_js(value)?;
        out.insert(id, name);
    }
    Ok(out)
}

pub(super) fn class_record_to_js(id: MessageId, name: &str) -> UiResult<JsValue> {
    let obj = Object::new();
    js_set(&obj, CLASS_META_ID, JsValue::from_str(&id.to_string()))?;
    js_set(&obj, CLASS_META_NAME, JsValue::from_str(name))?;
    Ok(obj.into())
}

fn class_record_from_js(value: JsValue) -> UiResult<(MessageId, Arc<str>)> {
    let obj: Object =
        value.dyn_into().map_err(|_| UiError::from("Class metadata is not an object."))?;
    let id = js_get_required_id(&obj, CLASS_META_ID)?;
    let raw = js_get_optional_string(&obj, CLASS_META_NAME)?.unwrap_or_default();
    let raw = raw.trim();
    let name = if raw.is_empty() { format!("Class {id}") } else { raw.to_string() };
    Ok((id, Arc::<str>::from(name)))
}

pub(super) fn message_record_from_js(value: JsValue) -> UiResult<MessageRecord> {
    let obj: Object =
        value.dyn_into().map_err(|_| UiError::from("Message metadata is not an object."))?;

    let id = js_get_required_id(&obj, META_ID)?;
    let class_id = js_get_optional_id(&obj, META_CLASS_ID)?.unwrap_or(id);
    let name = js_get_optional_string(&obj, META_NAME)?.unwrap_or_else(|| format!("Message {id}"));
    let modified_ms = js_get_optional_u64(&obj, META_MODIFIED_MS)?.unwrap_or(0);
    let bytes_len = js_get_optional_usize(&obj, META_BYTES_LEN)?.unwrap_or(0);

    let envelope_ref = match js_get_optional_string(&obj, META_REF_KIND)?.as_deref() {
        None => None,
        Some("envelope_frame") => {
            let source_id = js_get_required_id(&obj, META_REF_SOURCE_ID)?;
            let source_modified_ms =
                js_get_optional_u64(&obj, META_REF_SOURCE_MODIFIED_MS)?.unwrap_or(0);
            let payload_offset = js_get_optional_usize(&obj, META_REF_PAYLOAD_OFFSET)?.unwrap_or(0);
            let payload_len =
                js_get_optional_usize(&obj, META_REF_PAYLOAD_LEN)?.unwrap_or(bytes_len);
            let flags = js_get_optional_u64(&obj, META_REF_FLAGS)?.unwrap_or(0) as u8;
            let decompress = js_get_optional_bool(&obj, META_REF_DECOMPRESS)?.unwrap_or(false);
            Some(EnvelopeFrameRef {
                source_id,
                source_modified_ms,
                payload_offset,
                payload_len,
                flags,
                decompress,
            })
        }
        Some(other) => return Err(format!("Message {id} has unknown ref_kind: {other:?}").into()),
    };

    Ok(MessageRecord {
        id,
        class_id,
        name: Arc::<str>::from(name),
        modified_ms,
        bytes_len,
        envelope_ref,
    })
}

fn js_set(obj: &Object, key: &str, value: JsValue) -> UiResult<()> {
    Reflect::set(obj, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|err| UiError::from(format!("Failed to write metadata.{key}: {err:?}")))
}

fn js_get_optional(obj: &Object, key: &str) -> UiResult<Option<JsValue>> {
    let value = Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|err| UiError::from(format!("Failed to read metadata.{key}: {err:?}")))?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    Ok(Some(value))
}

fn js_get_optional_string(obj: &Object, key: &str) -> UiResult<Option<String>> {
    let Some(value) = js_get_optional(obj, key)? else {
        return Ok(None);
    };
    value
        .as_string()
        .ok_or_else(|| UiError::from(format!("metadata.{key} must be a string.")))
        .map(Some)
}

fn js_get_optional_bool(obj: &Object, key: &str) -> UiResult<Option<bool>> {
    let Some(value) = js_get_optional(obj, key)? else {
        return Ok(None);
    };
    value
        .as_bool()
        .ok_or_else(|| UiError::from(format!("metadata.{key} must be a boolean.")))
        .map(Some)
}

fn js_get_optional_u64(obj: &Object, key: &str) -> UiResult<Option<u64>> {
    let Some(value) = js_get_optional(obj, key)? else {
        return Ok(None);
    };
    if let Some(s) = value.as_string() {
        return s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| UiError::from(format!("metadata.{key} must be a u64 string.")));
    }
    let Some(n) = value.as_f64() else {
        return Err(format!("metadata.{key} must be a number.").into());
    };
    if !n.is_finite() || n < 0.0 {
        return Err(format!("metadata.{key} must be a non-negative number.").into());
    }
    Ok(Some(n as u64))
}

fn js_get_optional_usize(obj: &Object, key: &str) -> UiResult<Option<usize>> {
    let Some(v) = js_get_optional_u64(obj, key)? else {
        return Ok(None);
    };
    usize::try_from(v)
        .map(Some)
        .map_err(|_| UiError::from(format!("metadata.{key} is out of range.")))
}

fn js_get_required_id(obj: &Object, key: &str) -> UiResult<MessageId> {
    let Some(value) = js_get_optional(obj, key)? else {
        return Err(format!("metadata.{key} is missing.").into());
    };
    if let Some(s) = value.as_string() {
        return s
            .trim()
            .parse::<MessageId>()
            .map_err(|_| format!("metadata.{key} is invalid.").into());
    }
    let Some(n) = value.as_f64() else {
        return Err(format!("metadata.{key} must be a string or number.").into());
    };
    if !n.is_finite() || n < 0.0 {
        return Err(format!("metadata.{key} must be a non-negative number.").into());
    }
    Ok(MessageId::new(n as u64))
}

fn js_get_optional_id(obj: &Object, key: &str) -> UiResult<Option<MessageId>> {
    let Some(value) = js_get_optional(obj, key)? else {
        return Ok(None);
    };
    if let Some(s) = value.as_string() {
        return s
            .trim()
            .parse::<MessageId>()
            .map(Some)
            .map_err(|_| format!("metadata.{key} is invalid.").into());
    }
    let Some(n) = value.as_f64() else {
        return Err(format!("metadata.{key} must be a string or number.").into());
    };
    if !n.is_finite() || n < 0.0 {
        return Err(format!("metadata.{key} must be a non-negative number.").into());
    }
    Ok(Some(MessageId::new(n as u64)))
}
