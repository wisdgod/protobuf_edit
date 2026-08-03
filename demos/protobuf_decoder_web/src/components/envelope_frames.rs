use crate::services::EnvelopeService;
use crate::state::{EnvelopeTabState, UiState};
use leptos::prelude::*;
use std::sync::Arc;

#[component]
pub(crate) fn EnvelopeFramesPanel(env: EnvelopeTabState) -> impl IntoView {
    let env_svc = expect_context::<EnvelopeService>();
    let locale = expect_context::<UiState>().locale;
    let envelope_view = env.view;
    let selected = env.selected;

    let list_collapsed = RwSignal::new(false);

    let frames_len =
        move || envelope_view.with(|s| s.as_ref().map(|v| v.frames.len())).unwrap_or(0);

    let show_decompress_controls = move || {
        let idx = selected.get();
        envelope_view.with(|s| {
            let Some(view) = s.as_ref() else {
                return false;
            };
            view.frames.get(idx).is_some_and(|f| f.is_compressed())
        })
    };

    let on_close = {
        let svc = env_svc.clone();
        UnsyncCallback::new(move |()| svc.close_frames())
    };
    let on_extract_all = {
        let svc = env_svc.clone();
        UnsyncCallback::new(move |()| svc.extract_all_frames())
    };
    let on_decompress = {
        let svc = env_svc.clone();
        UnsyncCallback::new(move |()| svc.decompress_selected_frame())
    };
    let on_open = {
        let svc = env_svc.clone();
        UnsyncCallback::new(move |idx: usize| svc.open_frame(idx))
    };
    let on_extract = {
        let svc = env_svc;
        UnsyncCallback::new(move |idx: usize| svc.extract_frame(idx))
    };

    view! {
        <div class="envelope-frames">
            <div class="envelope-frames-header">
                <div class="envelope-frames-title">
                    {move || format!("{}: {}", locale.get().t().envelope_frames, frames_len())}
                </div>
                <div class="envelope-frames-controls">
                    <button
                        class="btn btn--secondary btn--small"
                        on:click=move |_| list_collapsed.update(|v| *v = !*v)
                    >
                        {move || {
                            let t = locale.get().t();
                            if list_collapsed.get() { t.show_list } else { t.hide_list }
                        }}
                    </button>
                    <Show when=move || !list_collapsed.get() fallback=|| ()>
                        <button
                            class="btn btn--secondary btn--small"
                            on:click=move |_| on_extract_all.run(())
                        >
                            {move || locale.get().t().extract_all}
                        </button>
                        <Show when=show_decompress_controls fallback=|| ()>
                            <button
                                class="btn btn--secondary btn--small"
                                on:click=move |_| on_decompress.run(())
                            >
                                {move || locale.get().t().auto_decompress}
                            </button>
                        </Show>
                    </Show>
                    <button class="btn btn--secondary btn--small" on:click=move |_| on_close.run(())>
                        {move || locale.get().t().close}
                    </button>
                </div>
            </div>

            <Show when=move || !list_collapsed.get() fallback=|| ()>
                <div class="envelope-frames-list">
                    <For
                        each=move || 0..frames_len()
                        key=|idx| *idx
                        children=move |idx| {
                            frame_row_view(idx, envelope_view, selected, on_open, on_extract)
                        }
                    />
                </div>
            </Show>
        </div>
    }
}

fn frame_row_view(
    idx: usize,
    envelope_view: RwSignal<Option<crate::envelope::EnvelopeView>, LocalStorage>,
    selected: RwSignal<usize>,
    on_open: UnsyncCallback<usize>,
    on_extract: UnsyncCallback<usize>,
) -> AnyView {
    let locale = expect_context::<UiState>().locale;
    let frame = envelope_view.with(|s| s.as_ref().and_then(|view| view.frames.get(idx).copied()));
    let Some(frame) = frame else {
        return view! { <div></div> }.into_any();
    };

    let row_class = move || {
        if selected.get() == idx { "frame-row frame-row--selected" } else { "frame-row" }
    };

    let meta_line: Arc<str> = Arc::<str>::from(format!(
        "frame {idx}  flags=0x{:02X}  payload={}B  header@{}  payload@{}",
        frame.flags, frame.payload_len, frame.header_offset, frame.payload_offset
    ));

    // Suffix and tooltip derive from the same frame metadata; one memo keeps
    // them in sync and avoids rebuilding both strings on unrelated updates.
    let annotations = Memo::new({
        let meta_line = meta_line.clone();
        move |_| {
            let mut suffix = String::new();
            let mut title = String::from(meta_line.as_ref());
            if frame.is_compressed() {
                suffix.push_str(" (compressed)");
                title.push_str(" [compressed]");
            }
            if frame.is_json() {
                suffix.push_str(" (json)");
                title.push_str(" [json]");
            }

            envelope_view.with(|state| {
                let Some(meta) = state.as_ref().and_then(|view| view.meta.get(idx)) else {
                    return;
                };

                if let Some(info) = meta.decompression {
                    suffix.push_str(" (decompressed)");
                    title.push_str(" [decompressed format=");
                    title.push_str(info.format);
                    title.push_str(" output=");
                    title.push_str(&info.output_len.to_string());
                    title.push_str("B]");
                }
                if let Some(err) = meta.decompression_error.as_ref() {
                    suffix.push_str(" (decompression error)");
                    title.push_str(" [decompression_error=");
                    title.push_str(err.as_ref());
                    title.push(']');
                }
                if let Some(err) = meta.protobuf_error.as_ref() {
                    suffix.push_str(" (protobuf error)");
                    title.push_str(" [protobuf_error=");
                    title.push_str(err.as_ref());
                    title.push(']');
                }
            });

            (Arc::<str>::from(suffix), Arc::<str>::from(title))
        }
    });

    view! {
        <div
            class=row_class
            prop:title=move || annotations.with(|(_, title)| String::from(title.as_ref()))
            on:click=move |_| on_open.run(idx)
        >
            <div class="frame-meta">
                <span>{Oco::from(meta_line)}</span>
                <span class="frame-suffix">
                    {move || annotations.with(|(suffix, _)| Oco::from(suffix.clone()))}
                </span>
            </div>
            <div class="frame-actions">
                <button
                    class="btn btn--secondary btn--small"
                    on:click=move |ev: leptos::ev::MouseEvent| {
                        ev.stop_propagation();
                        on_extract.run(idx);
                    }
                >
                    {move || locale.get().t().extract}
                </button>
            </div>
        </div>
    }
    .into_any()
}
