use crate::error::{UiError, UiResult};
use wasm_bindgen::{closure::Closure, JsCast as _, JsValue};

pub(crate) fn set_document_theme(theme: &str) -> UiResult<()> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    let document = window.document().ok_or("Document is not available.")?;
    let el = document.document_element().ok_or("Document element is not available.")?;
    el.set_attribute("data-theme", theme)
        .map_err(|err| UiError::from(format!("Failed to update document theme: {err:?}")))
}

pub(crate) fn get_document_theme() -> UiResult<Option<String>> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    let document = window.document().ok_or("Document is not available.")?;
    let el = document.document_element().ok_or("Document element is not available.")?;
    Ok(el.get_attribute("data-theme"))
}

pub(crate) fn start_theme_transition(duration_ms: i32) -> UiResult<()> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    let document = window.document().ok_or("Document is not available.")?;
    let el = document.document_element().ok_or("Document element is not available.")?;

    let _ = el.class_list().add_1("theme-transition");

    let el = el.clone();
    let cb = Closure::once(move || {
        let _ = el.class_list().remove_1("theme-transition");
    });

    window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            cb.as_ref().unchecked_ref(),
            duration_ms,
        )
        .map_err(|err| UiError::from(format!("setTimeout failed: {err:?}")))?;
    cb.forget();
    Ok(())
}

pub(crate) fn get_url_hash() -> UiResult<String> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    window
        .location()
        .hash()
        .map_err(|err| UiError::from(format!("Failed to read URL hash: {err:?}")))
}

pub(crate) fn build_share_url(hash: &str) -> UiResult<String> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    let mut href = window
        .location()
        .href()
        .map_err(|err| UiError::from(format!("Failed to read current URL: {err:?}")))?;

    if let Some(idx) = href.find('#') {
        href.truncate(idx);
    }

    if hash.is_empty() {
        return Ok(href);
    }
    if hash.starts_with('#') {
        return Ok(format!("{href}{hash}"));
    }
    Ok(format!("{href}#{hash}"))
}

pub(crate) fn clipboard_write_text(text: &str) -> UiResult<js_sys::Promise> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    let navigator = window.navigator();
    let clipboard = navigator.clipboard();
    Ok(clipboard.write_text(text))
}

pub(crate) fn download_bytes(filename: &str, bytes: &[u8]) -> UiResult<()> {
    let window = web_sys::window().ok_or("Window is not available.")?;
    let document = window.document().ok_or("Document is not available.")?;

    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));

    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)
        .map_err(|err| UiError::from(format!("Failed to create Blob: {err:?}")))?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|err| UiError::from(format!("Failed to create object URL: {err:?}")))?;

    let el = document
        .create_element("a")
        .map_err(|err| UiError::from(format!("Failed to create anchor element: {err:?}")))?;
    let a: web_sys::HtmlAnchorElement =
        el.dyn_into().map_err(|_| UiError::from("Failed to cast element to HtmlAnchorElement."))?;

    a.set_href(&url);
    a.set_download(filename);
    a.click();

    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(())
}

pub(crate) fn decompress_bytes_promise(format: &str, bytes: &[u8]) -> UiResult<js_sys::Promise> {
    let global = js_sys::global();
    let ctor = js_sys::Reflect::get(&global, &JsValue::from_str("DecompressionStream"))
        .map_err(|err| UiError::from(format!("Failed to read DecompressionStream: {err:?}")))?;
    if ctor.is_undefined() {
        return Err("DecompressionStream is not supported in this browser.".into());
    }

    let ctor: js_sys::Function =
        ctor.dyn_into().map_err(|_| UiError::from("DecompressionStream is not a constructor."))?;
    let args = js_sys::Array::new();
    args.push(&JsValue::from_str(format));
    let stream = js_sys::Reflect::construct(&ctor, &args).map_err(|err| {
        UiError::from(format!("Failed to construct DecompressionStream({format:?}): {err:?}"))
    })?;
    let stream: web_sys::ReadableWritablePair = stream.unchecked_into();

    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)
        .map_err(|err| UiError::from(format!("Failed to create Blob: {err:?}")))?;

    let decompressed = blob.stream().pipe_through(&stream);
    let response = web_sys::Response::new_with_opt_readable_stream(Some(&decompressed))
        .map_err(|err| UiError::from(format!("Failed to create Response: {err:?}")))?;
    response
        .array_buffer()
        .map_err(|err| UiError::from(format!("Response.array_buffer failed: {err:?}")))
}
