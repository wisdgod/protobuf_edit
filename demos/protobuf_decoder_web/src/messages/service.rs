use crate::bytes::ByteView;
use crate::error::{UiError, UiResult};
use crate::idb;
use crate::page_cache;
use crate::web::decompress_bytes_promise;
use js_sys::Uint8Array;
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen_futures::JsFuture;

use super::model::{
    class_record_to_js, load_class_name_map, message_record_from_js, message_record_to_js,
    EnvelopeFrameRef, LoadedBytes, LoadedBytesMode, MessageId, MessageMeta, MessageRecord,
};
use super::prefs::{alloc_message_id, current_message, set_current_message};

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
