use crate::error::{shared_error, UiError};
use crate::fx::FxHashMap;
use crate::messages::MessageId;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
struct MessageBytesCacheEntry {
    revision: u64,
    bytes: Rc<Vec<u8>>,
}

thread_local! {
    static CLASS_DECOMPRESS_PREF: RefCell<FxHashMap<MessageId, &'static str>> = RefCell::new(FxHashMap::default());
    static MESSAGE_BYTES: RefCell<FxHashMap<MessageId, MessageBytesCacheEntry>> = RefCell::new(FxHashMap::default());
    static DECOMPRESSED_BYTES: RefCell<FxHashMap<MessageId, Rc<Vec<u8>>>> = RefCell::new(FxHashMap::default());
    static DECOMPRESSED_ERRORS: RefCell<FxHashMap<MessageId, UiError>> = RefCell::new(FxHashMap::default());
}

pub(crate) fn class_decompress_preference(class_id: MessageId) -> Option<&'static str> {
    CLASS_DECOMPRESS_PREF.with(|cell| cell.borrow().get(&class_id).copied())
}

pub(crate) fn set_class_decompress_preference(class_id: MessageId, format: &'static str) {
    CLASS_DECOMPRESS_PREF.with(|cell| {
        cell.borrow_mut().insert(class_id, format);
    });
}

pub(crate) fn cached_message_bytes(source_id: MessageId, revision: u64) -> Option<Rc<Vec<u8>>> {
    MESSAGE_BYTES.with(|cell| {
        let map = cell.borrow();
        let entry = map.get(&source_id)?;
        if entry.revision != revision {
            return None;
        }
        Some(entry.bytes.clone())
    })
}

pub(crate) fn store_message_bytes(source_id: MessageId, revision: u64, bytes: Rc<Vec<u8>>) {
    MESSAGE_BYTES.with(|cell| {
        cell.borrow_mut().insert(source_id, MessageBytesCacheEntry { revision, bytes });
    });
}

pub(crate) fn cached_decompressed_bytes(id: MessageId) -> Option<Rc<Vec<u8>>> {
    DECOMPRESSED_BYTES.with(|cell| cell.borrow().get(&id).cloned())
}

pub(crate) fn store_decompressed_bytes(id: MessageId, bytes: Rc<Vec<u8>>) {
    DECOMPRESSED_ERRORS.with(|cell| {
        cell.borrow_mut().remove(&id);
    });
    DECOMPRESSED_BYTES.with(|cell| {
        cell.borrow_mut().insert(id, bytes);
    });
}

pub(crate) fn cached_decompressed_error(id: MessageId) -> Option<UiError> {
    DECOMPRESSED_ERRORS.with(|cell| cell.borrow().get(&id).cloned())
}

pub(crate) fn store_decompressed_error(id: MessageId, error: impl Into<UiError>) {
    DECOMPRESSED_BYTES.with(|cell| {
        cell.borrow_mut().remove(&id);
    });
    let error = shared_error(error);
    DECOMPRESSED_ERRORS.with(|cell| {
        cell.borrow_mut().insert(id, error);
    });
}
