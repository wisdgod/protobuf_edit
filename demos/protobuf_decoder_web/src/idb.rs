use crate::error::{UiError, UiResult};
use crate::messages::MessageId;
use std::cell::RefCell;
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{IdbDatabase, IdbObjectStore, IdbRequest, IdbTransactionMode};

const DB_NAME: &str = "protobuf_decoder_web.v1";
const DB_VERSION: u32 = 1;
const STORE_MESSAGE_BYTES: &str = "message_bytes";
const STORE_METADATA: &str = "metadata";
const STORE_CLASS_AUTO_EXPAND: &str = "class_auto_expand";
const STORE_CLASS_META: &str = "class_meta";

thread_local! {
    static CACHED_DB: RefCell<Option<IdbDatabase>> = const { RefCell::new(None) };
}

pub(crate) async fn get_message_bytes(id: MessageId) -> UiResult<Option<Vec<u8>>> {
    let Some(value) = idb_get(STORE_MESSAGE_BYTES, &id.to_string()).await? else {
        return Ok(None);
    };
    js_value_to_bytes(value).map(Some).map_err(UiError::from)
}

pub(crate) async fn get_message_meta(id: MessageId) -> UiResult<Option<JsValue>> {
    idb_get(STORE_METADATA, &id.to_string()).await
}

pub(crate) async fn list_message_meta() -> UiResult<Vec<JsValue>> {
    idb_get_all(STORE_METADATA).await
}

pub(crate) async fn put_message_meta(id: MessageId, value: JsValue) -> UiResult<()> {
    idb_put(STORE_METADATA, &id.to_string(), value).await
}

pub(crate) async fn list_class_meta() -> UiResult<Vec<JsValue>> {
    idb_get_all(STORE_CLASS_META).await
}

pub(crate) async fn put_class_meta(class_id: MessageId, value: JsValue) -> UiResult<()> {
    idb_put(STORE_CLASS_META, &class_id.to_string(), value).await
}

pub(crate) async fn get_class_auto_expand(class_id: MessageId) -> UiResult<Option<String>> {
    let Some(value) = idb_get(STORE_CLASS_AUTO_EXPAND, &class_id.to_string()).await? else {
        return Ok(None);
    };
    value
        .as_string()
        .ok_or_else(|| UiError::from("indexedDB class_auto_expand must be a string."))
        .map(Some)
}

pub(crate) async fn put_class_auto_expand(class_id: MessageId, value: &str) -> UiResult<()> {
    idb_put(STORE_CLASS_AUTO_EXPAND, &class_id.to_string(), JsValue::from_str(value)).await
}

pub(crate) async fn delete_class_auto_expand(class_id: MessageId) -> UiResult<()> {
    idb_delete(STORE_CLASS_AUTO_EXPAND, &class_id.to_string()).await
}

pub(crate) async fn delete_class_meta(class_id: MessageId) -> UiResult<()> {
    idb_delete(STORE_CLASS_META, &class_id.to_string()).await
}

pub(crate) async fn put_message_bytes_and_meta(
    id: MessageId,
    bytes: js_sys::Uint8Array,
    meta: JsValue,
) -> UiResult<()> {
    let db = open_db().await?;
    let store_names = js_sys::Array::new();
    store_names.push(&JsValue::from_str(STORE_MESSAGE_BYTES));
    store_names.push(&JsValue::from_str(STORE_METADATA));

    let tx = db
        .transaction_with_str_sequence_and_mode(store_names.as_ref(), IdbTransactionMode::Readwrite)
        .map_err(|err| UiError::from(format!("indexedDB transaction failed: {err:?}")))?;

    let bytes_store = tx
        .object_store(STORE_MESSAGE_BYTES)
        .map_err(|err| UiError::from(format!("indexedDB object_store failed: {err:?}")))?;
    let meta_store = tx
        .object_store(STORE_METADATA)
        .map_err(|err| UiError::from(format!("indexedDB object_store failed: {err:?}")))?;

    let id = id.to_string();
    let key = JsValue::from_str(&id);

    let req = bytes_store
        .put_with_key(&bytes.into(), &key)
        .map_err(|err| UiError::from(format!("indexedDB put failed: {err:?}")))?;
    let _ = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB put failed: {err:?}")))?;

    let req = meta_store
        .put_with_key(&meta, &key)
        .map_err(|err| UiError::from(format!("indexedDB put failed: {err:?}")))?;
    let _ = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB put failed: {err:?}")))?;

    Ok(())
}

pub(crate) async fn delete_message_bytes_and_meta(id: MessageId) -> UiResult<()> {
    let db = open_db().await?;
    let store_names = js_sys::Array::new();
    store_names.push(&JsValue::from_str(STORE_MESSAGE_BYTES));
    store_names.push(&JsValue::from_str(STORE_METADATA));

    let tx = db
        .transaction_with_str_sequence_and_mode(store_names.as_ref(), IdbTransactionMode::Readwrite)
        .map_err(|err| UiError::from(format!("indexedDB transaction failed: {err:?}")))?;

    let bytes_store = tx
        .object_store(STORE_MESSAGE_BYTES)
        .map_err(|err| UiError::from(format!("indexedDB object_store failed: {err:?}")))?;
    let meta_store = tx
        .object_store(STORE_METADATA)
        .map_err(|err| UiError::from(format!("indexedDB object_store failed: {err:?}")))?;

    let key = JsValue::from_str(&id.to_string());

    let req = meta_store
        .delete(&key)
        .map_err(|err| UiError::from(format!("indexedDB delete failed: {err:?}")))?;
    let _ = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB delete failed: {err:?}")))?;

    let req = bytes_store
        .delete(&key)
        .map_err(|err| UiError::from(format!("indexedDB delete failed: {err:?}")))?;
    let _ = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB delete failed: {err:?}")))?;

    Ok(())
}

async fn open_db() -> UiResult<IdbDatabase> {
    let cached = CACHED_DB.with(|cell| cell.borrow().clone());
    if let Some(db) = cached {
        return Ok(db);
    }

    let window = web_sys::window().ok_or("Window is not available.")?;
    let factory = window
        .indexed_db()
        .map_err(|err| UiError::from(format!("Failed to access indexedDB: {err:?}")))?
        .ok_or("indexedDB is not available.")?;

    let request = factory
        .open_with_u32(DB_NAME, DB_VERSION)
        .map_err(|err| UiError::from(format!("indexedDB open failed: {err:?}")))?;

    let request_upgrade = request.clone();
    let upgrade = Closure::wrap(Box::new(move |_event: web_sys::Event| {
        let Ok(db_value) = request_upgrade.result() else {
            return;
        };
        let Ok(db) = db_value.dyn_into::<IdbDatabase>() else {
            return;
        };
        let _ = db.create_object_store(STORE_MESSAGE_BYTES);
        let _ = db.create_object_store(STORE_METADATA);
        let _ = db.create_object_store(STORE_CLASS_AUTO_EXPAND);
        let _ = db.create_object_store(STORE_CLASS_META);
    }) as Box<dyn FnMut(web_sys::Event)>);
    request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));

    let request: IdbRequest = request.unchecked_into();
    let db_value = await_request(request)
        .await
        .map_err(|err| UiError::from(format!("indexedDB open failed: {err:?}")))?;
    let db = db_value
        .dyn_into::<IdbDatabase>()
        .map_err(|_| UiError::from("indexedDB open returned non-database."))?;

    CACHED_DB.with(|cell| cell.replace(Some(db.clone())));
    drop(upgrade);
    Ok(db)
}

async fn await_request(request: IdbRequest) -> Result<JsValue, JsValue> {
    let request_success = request.clone();
    let request_error = request.clone();
    let promise = js_sys::Promise::new(&mut move |resolve, reject| {
        let resolve = resolve.clone();
        let reject = reject.clone();

        let request_success = request_success.clone();
        let success = Closure::once(move |_event: web_sys::Event| {
            let value = request_success.result().unwrap_or_else(|err| err);
            let _ = resolve.call1(&JsValue::UNDEFINED, &value);
        });
        request.set_onsuccess(Some(success.as_ref().unchecked_ref()));
        success.forget();

        let request_error = request_error.clone();
        let error = Closure::once(move |_event: web_sys::Event| {
            let err = match request_error.error() {
                Ok(Some(err)) => JsValue::from(err),
                Ok(None) => JsValue::from_str("indexedDB request failed without an error value."),
                Err(err) => err,
            };
            let _ = reject.call1(&JsValue::UNDEFINED, &err);
        });
        request.set_onerror(Some(error.as_ref().unchecked_ref()));
        error.forget();
    });

    JsFuture::from(promise).await
}

fn js_value_to_bytes(value: JsValue) -> Result<Vec<u8>, &'static str> {
    if let Ok(u8) = value.clone().dyn_into::<js_sys::Uint8Array>() {
        return Ok(u8.to_vec());
    }
    if let Ok(buf) = value.dyn_into::<js_sys::ArrayBuffer>() {
        return Ok(js_sys::Uint8Array::new(&buf).to_vec());
    }

    Err("indexedDB value is not a Uint8Array/ArrayBuffer.")
}

async fn open_store(store_name: &str, mode: IdbTransactionMode) -> UiResult<IdbObjectStore> {
    let db = open_db().await?;
    let tx = db
        .transaction_with_str_and_mode(store_name, mode)
        .map_err(|err| UiError::from(format!("indexedDB transaction failed: {err:?}")))?;
    tx.object_store(store_name)
        .map_err(|err| UiError::from(format!("indexedDB object_store failed: {err:?}")))
}

async fn idb_get(store_name: &str, key: &str) -> UiResult<Option<JsValue>> {
    let store = open_store(store_name, IdbTransactionMode::Readonly).await?;
    let req = store
        .get(&JsValue::from_str(key))
        .map_err(|err| UiError::from(format!("indexedDB get failed: {err:?}")))?;
    let value = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB get failed: {err:?}")))?;
    if value.is_undefined() {
        return Ok(None);
    }
    Ok(Some(value))
}

async fn idb_put(store_name: &str, key: &str, value: JsValue) -> UiResult<()> {
    let store = open_store(store_name, IdbTransactionMode::Readwrite).await?;
    let req = store
        .put_with_key(&value, &JsValue::from_str(key))
        .map_err(|err| UiError::from(format!("indexedDB put failed: {err:?}")))?;
    let _ = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB put failed: {err:?}")))?;
    Ok(())
}

async fn idb_delete(store_name: &str, key: &str) -> UiResult<()> {
    let store = open_store(store_name, IdbTransactionMode::Readwrite).await?;
    let req = store
        .delete(&JsValue::from_str(key))
        .map_err(|err| UiError::from(format!("indexedDB delete failed: {err:?}")))?;
    let _ = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB delete failed: {err:?}")))?;
    Ok(())
}

async fn idb_get_all(store_name: &str) -> UiResult<Vec<JsValue>> {
    let store = open_store(store_name, IdbTransactionMode::Readonly).await?;
    let req = store
        .get_all()
        .map_err(|err| UiError::from(format!("indexedDB getAll failed: {err:?}")))?;
    let value = await_request(req)
        .await
        .map_err(|err| UiError::from(format!("indexedDB getAll failed: {err:?}")))?;
    let arr: js_sys::Array =
        value.dyn_into().map_err(|_| UiError::from("indexedDB getAll did not return an array."))?;
    Ok(arr.iter().collect())
}
