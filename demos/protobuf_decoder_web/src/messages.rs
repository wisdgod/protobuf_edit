use crate::idb;
use crate::fx::FxHashMap;
use crate::bytes::ByteView;
use crate::error::{UiError, UiResult};
use crate::page_cache;
use crate::web::decompress_bytes_promise;
use js_sys::{Object, Reflect, Uint8Array};
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;

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
struct EnvelopeFrameRef {
    source_id: MessageId,
    source_modified_ms: u64,
    payload_offset: usize,
    payload_len: usize,
    flags: u8,
    decompress: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MessageRecord {
    id: MessageId,
    class_id: MessageId,
    name: Arc<str>,
    modified_ms: u64,
    bytes_len: usize,
    envelope_ref: Option<EnvelopeFrameRef>,
}

const KEY_CURRENT: &str = "protobuf_decoder_web.v1.current_message";
const KEY_NEXT_ID: &str = "protobuf_decoder_web.v1.next_message_id";
const KEY_FRAME_NAME_TEMPLATE: &str = "protobuf_decoder_web.v1.frame_name_template";
const KEY_THEME_PREF: &str = "protobuf_decoder_web.v1.theme";

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

pub(crate) async fn list_messages() -> UiResult<Vec<MessageMeta>> {
    let raw = idb::list_message_meta().await?;
    let raw_classes = idb::list_class_meta().await?;
    let mut class_names = load_class_name_map(raw_classes)?;
    let mut out: Vec<MessageMeta> = Vec::with_capacity(raw.len());
    for value in raw {
        let record = message_record_from_js(value)?;
        if record.id == record.class_id {
            class_names.entry(record.class_id).or_insert_with(|| record.name.clone());
        }
        let class_name = class_names
            .get(&record.class_id)
            .cloned()
            .unwrap_or_else(|| Arc::<str>::from(format!("Class {}", record.class_id)));
        out.push(MessageMeta {
            id: record.id,
            class_id: record.class_id,
            class_name,
            name: record.name.clone(),
            modified_ms: record.modified_ms,
            bytes_len: record.bytes_len,
        });
    }

    out.sort_by(|a, b| b.modified_ms.cmp(&a.modified_ms).then_with(|| b.id.cmp(&a.id)));
    Ok(out)
}

fn message_record_to_js(record: &MessageRecord) -> UiResult<JsValue> {
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

fn load_class_name_map(raw: Vec<JsValue>) -> UiResult<FxHashMap<MessageId, Arc<str>>> {
    let mut out: FxHashMap<MessageId, Arc<str>> = FxHashMap::default();
    for value in raw {
        let (id, name) = class_record_from_js(value)?;
        out.insert(id, name);
    }
    Ok(out)
}

fn class_record_to_js(id: MessageId, name: &str) -> UiResult<JsValue> {
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

fn message_record_from_js(value: JsValue) -> UiResult<MessageRecord> {
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

pub(crate) async fn load_message_bytes(id: MessageId) -> UiResult<LoadedBytes> {
    let record = load_message_record(id).await?;
    if let Some(meta) = record.envelope_ref {
        return load_envelope_frame_ref(id, record.class_id, meta).await;
    }

    let revision = record.modified_ms;
    if let Some(bytes) = page_cache::cached_message_bytes(id, revision) {
        return Ok(LoadedBytes {
            bytes: ByteView::from_rc(bytes),
            mode: LoadedBytesMode::Protobuf,
            note: None,
        });
    }

    let bytes = match idb::get_message_bytes(id).await? {
        Some(bytes) => bytes,
        None => return Err(format!("Message {id} is missing bytes.").into()),
    };

    let bytes = Rc::new(bytes);
    page_cache::store_message_bytes(id, revision, bytes.clone());
    Ok(LoadedBytes { bytes: ByteView::from_rc(bytes), mode: LoadedBytesMode::Protobuf, note: None })
}

async fn load_message_record(id: MessageId) -> UiResult<MessageRecord> {
    let Some(value) = idb::get_message_meta(id).await? else {
        return Err(format!("Message {id} is missing metadata.").into());
    };
    message_record_from_js(value)
}

pub(crate) async fn create_message(
    name: &str,
    bytes_len: usize,
    bytes: Uint8Array,
) -> UiResult<MessageId> {
    create_message_impl(name, bytes_len, bytes, None).await
}

pub(crate) async fn create_envelope_frame_ref_in_same_class(
    source: MessageId,
    name: &str,
    payload_offset: usize,
    payload_len: usize,
    flags: u8,
    decompress: bool,
) -> UiResult<MessageId> {
    let id = alloc_message_id()?;
    let source_record = load_message_record(source).await?;
    let class_id = source_record.class_id;
    let now = now_ms();
    let source_modified_ms = source_record.modified_ms;

    let record = MessageRecord {
        id,
        class_id,
        name: Arc::<str>::from(name),
        modified_ms: now,
        bytes_len: payload_len,
        envelope_ref: Some(EnvelopeFrameRef {
            source_id: source,
            source_modified_ms,
            payload_offset,
            payload_len,
            flags,
            decompress,
        }),
    };

    idb::put_message_meta(id, message_record_to_js(&record)?).await?;
    let class_name = source_record.name.as_ref().trim();
    if !class_name.is_empty() {
        idb::put_class_meta(class_id, class_record_to_js(class_id, class_name)?).await?;
    }
    set_current_message(Some(id))?;
    Ok(id)
}

async fn create_message_impl(
    name: &str,
    bytes_len: usize,
    bytes: Uint8Array,
    class_id: Option<MessageId>,
) -> UiResult<MessageId> {
    let id = alloc_message_id()?;
    let class_id = class_id.unwrap_or(id);
    let now = now_ms();

    let record = MessageRecord {
        id,
        class_id,
        name: Arc::<str>::from(name),
        modified_ms: now,
        bytes_len,
        envelope_ref: None,
    };

    idb::put_message_bytes_and_meta(id, bytes, message_record_to_js(&record)?).await?;
    let class_name = name.trim();
    if !class_name.is_empty() {
        idb::put_class_meta(class_id, class_record_to_js(class_id, class_name)?).await?;
    }
    set_current_message(Some(id))?;
    Ok(id)
}

pub(crate) async fn delete_message(id: MessageId) -> UiResult<()> {
    let record = load_message_record(id).await?;
    idb::delete_message_bytes_and_meta(id).await?;

    let list = list_messages().await?;
    let class_referenced = list.iter().any(|m| m.class_id == record.class_id);
    if !class_referenced {
        let _ = idb::delete_class_auto_expand(record.class_id).await;
        let _ = idb::delete_class_meta(record.class_id).await;
    }

    let current = current_message()?;
    if current == Some(id) {
        set_current_message(list.first().map(|m| m.id))?;
    }
    Ok(())
}

pub(crate) async fn rename_message(id: MessageId, name: &str) -> UiResult<()> {
    let mut record = load_message_record(id).await?;
    record.name = Arc::<str>::from(name);
    idb::put_message_meta(id, message_record_to_js(&record)?).await?;
    if record.id == record.class_id {
        let class_name = name.trim();
        if !class_name.is_empty() {
            idb::put_class_meta(record.class_id, class_record_to_js(record.class_id, class_name)?)
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn rename_class(class_id: MessageId, name: &str) -> UiResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Class name is empty.".into());
    }

    idb::put_class_meta(class_id, class_record_to_js(class_id, name)?).await?;

    let Some(root_value) = idb::get_message_meta(class_id).await? else {
        return Ok(());
    };
    let mut record = message_record_from_js(root_value)?;
    record.name = Arc::<str>::from(name);
    idb::put_message_meta(class_id, message_record_to_js(&record)?).await?;
    Ok(())
}

pub(crate) async fn update_message_bytes(
    id: MessageId,
    bytes_len: usize,
    bytes: Uint8Array,
) -> UiResult<()> {
    let mut record = load_message_record(id).await?;
    record.bytes_len = bytes_len;
    record.modified_ms = now_ms();
    record.envelope_ref = None;
    idb::put_message_bytes_and_meta(id, bytes, message_record_to_js(&record)?).await?;
    Ok(())
}

pub(crate) async fn load_auto_expand_paths(class_id: MessageId) -> UiResult<Vec<String>> {
    let Some(raw) = idb::get_class_auto_expand(class_id).await? else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(line.to_string());
    }
    Ok(out)
}

pub(crate) async fn store_auto_expand_paths(class_id: MessageId, paths: &[String]) -> UiResult<()> {
    let mut cleaned: Vec<&str> = paths.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    cleaned.sort_unstable();
    cleaned.dedup();

    if cleaned.is_empty() {
        let _ = idb::delete_class_auto_expand(class_id).await;
        return Ok(());
    }

    let value = cleaned.join("\n");
    idb::put_class_auto_expand(class_id, &value).await?;
    Ok(())
}

pub(crate) async fn bump_message_modified(id: MessageId) -> UiResult<()> {
    let mut record = load_message_record(id).await?;
    record.modified_ms = now_ms();
    idb::put_message_meta(id, message_record_to_js(&record)?).await?;
    Ok(())
}

pub(crate) async fn message_modified_ms(id: MessageId) -> UiResult<u64> {
    Ok(load_message_record(id).await?.modified_ms)
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

fn alloc_message_id() -> UiResult<MessageId> {
    let raw = storage_get(KEY_NEXT_ID)?.unwrap_or_else(|| "1".to_string());
    let next = raw.trim().parse::<u64>().unwrap_or(1);
    let bumped = next.saturating_add(1);
    storage_set(KEY_NEXT_ID, &bumped.to_string())?;
    Ok(MessageId::new(next))
}

async fn load_envelope_frame_ref(
    id: MessageId,
    class_id: MessageId,
    meta: EnvelopeFrameRef,
) -> UiResult<LoadedBytes> {
    let source_record = load_message_record(meta.source_id).await?;
    let current_source_rev = source_record.modified_ms;
    if meta.source_modified_ms != 0 && current_source_rev != meta.source_modified_ms {
        return Err(format!(
            "Message {id} references {source} at modified_ms={expected}, but source is now modified_ms={current}.",
            source = meta.source_id,
            expected = meta.source_modified_ms,
            current = current_source_rev,
        )
        .into());
    }

    let bytes = if let Some(bytes) =
        page_cache::cached_message_bytes(meta.source_id, current_source_rev)
    {
        bytes
    } else {
        let bytes = match idb::get_message_bytes(meta.source_id).await? {
            Some(bytes) => bytes,
            None => {
                return Err(format!("Source message {} is missing bytes.", meta.source_id).into());
            }
        };
        let bytes = Rc::new(bytes);
        page_cache::store_message_bytes(meta.source_id, current_source_rev, bytes.clone());
        bytes
    };

    let payload_end = meta.payload_offset.saturating_add(meta.payload_len);
    let Some(payload) = ByteView::slice(bytes.clone(), meta.payload_offset, payload_end) else {
        return Err(format!("Message {id} payload slice is out of bounds.").into());
    };

    let is_json = (meta.flags & 0x02) != 0;

    if !meta.decompress {
        if is_json {
            return Ok(LoadedBytes {
                bytes: payload,
                mode: LoadedBytesMode::Raw,
                note: Some("Frame is marked as JSON; showing raw bytes.".into()),
            });
        }
        return Ok(LoadedBytes { bytes: payload, mode: LoadedBytesMode::Protobuf, note: None });
    }

    if let Some(out) = page_cache::cached_decompressed_bytes(id) {
        return Ok(LoadedBytes {
            bytes: ByteView::from_rc(out),
            mode: if is_json { LoadedBytesMode::Raw } else { LoadedBytesMode::Protobuf },
            note: if is_json {
                Some("Frame is marked as JSON; showing decompressed bytes.".into())
            } else {
                None
            },
        });
    }

    if let Some(error) = page_cache::cached_decompressed_error(id) {
        return Ok(LoadedBytes {
            bytes: payload,
            mode: LoadedBytesMode::Raw,
            note: Some(error.into()),
        });
    }

    let mut formats: Vec<&'static str> = Vec::new();
    if let Some(pref) = page_cache::class_decompress_preference(class_id) {
        formats.push(pref);
    }
    for fmt in ["gzip", "deflate", "deflate-raw", "br"] {
        if !formats.contains(&fmt) {
            formats.push(fmt);
        }
    }

    let payload_bytes = payload.as_slice();
    let mut last_err: Option<UiError> = None;
    for &fmt in &formats {
        let promise = match decompress_bytes_promise(fmt, payload_bytes) {
            Ok(p) => p,
            Err(msg) => {
                last_err = Some(msg);
                continue;
            }
        };
        let buf = match JsFuture::from(promise).await {
            Ok(v) => v,
            Err(err) => {
                last_err = Some(
                    err.as_string().unwrap_or_else(|| format!("{fmt} failed: {err:?}")).into(),
                );
                continue;
            }
        };
        let out_bytes = js_sys::Uint8Array::new(&buf).to_vec();
        let out = Rc::new(out_bytes);
        page_cache::store_decompressed_bytes(id, out.clone());
        page_cache::set_class_decompress_preference(class_id, fmt);
        return Ok(LoadedBytes {
            bytes: ByteView::from_rc(out),
            mode: if is_json { LoadedBytesMode::Raw } else { LoadedBytesMode::Protobuf },
            note: if is_json {
                Some("Frame is marked as JSON; showing decompressed bytes.".into())
            } else {
                None
            },
        });
    }

    let msg = last_err.unwrap_or_else(|| "Decompression failed.".into());
    let msg = msg.into_owned();
    page_cache::store_decompressed_error(id, msg.clone());
    Ok(LoadedBytes { bytes: payload, mode: LoadedBytesMode::Raw, note: Some(msg.into()) })
}

fn now_ms() -> u64 {
    let ms = js_sys::Date::now();
    if ms.is_finite() && ms > 0.0 { ms as u64 } else { 0 }
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
