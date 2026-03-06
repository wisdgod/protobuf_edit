use crate::state::{EnvelopeActions, WorkspaceState};
use leptos::prelude::*;

#[component]
pub(crate) fn EnvelopeFramesPanel() -> impl IntoView {
    let workspace = expect_context::<WorkspaceState>();
    let actions = expect_context::<EnvelopeActions>();
    let envelope_view = workspace.envelope_view;
    let selected = workspace.envelope_selected;
    let EnvelopeActions { on_close, on_decompress, on_open, on_extract, on_extract_all } = actions;

    let list_collapsed = RwSignal::new(true);

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

    view! {
        <div class="envelope-frames">
            <div class="envelope-frames-header">
                <div class="envelope-frames-title">
                    {move || format!("Envelope frames: {}", frames_len())}
                </div>
                <div class="envelope-frames-controls">
                    <button
                        class="btn btn--secondary"
                        on:click=move |_| list_collapsed.update(|v| *v = !*v)
                    >
                        {move || if list_collapsed.get() { "Show list" } else { "Hide list" }}
                    </button>
                    <Show when=move || !list_collapsed.get() fallback=|| ()>
                        <button
                            class="btn btn--secondary"
                            on:click=move |_| on_extract_all.run(())
                        >
                            "Extract all"
                        </button>
                        <Show when=show_decompress_controls fallback=|| ()>
                            <button
                                class="btn btn--secondary"
                                on:click=move |_| on_decompress.run(())
                            >
                                "Auto-decompress → Message"
                            </button>
                        </Show>
                    </Show>
                    <button class="btn btn--secondary" on:click=move |_| on_close.run(())>
                        "Close"
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
    let frame = envelope_view.with(|s| s.as_ref().and_then(|view| view.frames.get(idx).copied()));
    let Some(frame) = frame else {
        return view! { <div></div> }.into_any();
    };

    let row_class = move || {
        if selected.get() == idx { "frame-row frame-row--selected" } else { "frame-row" }
    };

    let meta_line = format!(
        "frame {idx}  flags=0x{:02X}  payload={}B  header@{}  payload@{}",
        frame.flags, frame.payload_len, frame.header_offset, frame.payload_offset
    );

    let suffix = move || {
        let mut out = String::new();
        if frame.is_compressed() {
            out.push_str(" (compressed)");
        }
        if frame.is_json() {
            out.push_str(" (json)");
        }

        envelope_view.with(|state| {
            let Some(view) = state.as_ref() else {
                return;
            };
            let Some(meta) = view.meta.get(idx) else {
                return;
            };

            if meta.decompression.is_some() {
                out.push_str(" (decompressed)");
            }
            if meta.decompression_error.is_some() {
                out.push_str(" (decompression error)");
            }
            if meta.protobuf_error.is_some() {
                out.push_str(" (protobuf error)");
            }
        });

        out
    };

    let title = {
        let meta_line = meta_line.clone();
        move || {
            let mut out = meta_line.clone();
            if frame.is_compressed() {
                out.push_str(" [compressed]");
            }
            if frame.is_json() {
                out.push_str(" [json]");
            }

            envelope_view.with(|state| {
                let Some(view) = state.as_ref() else {
                    return;
                };
                let Some(meta) = view.meta.get(idx) else {
                    return;
                };

                if let Some(info) = meta.decompression {
                    out.push_str(" [decompressed format=");
                    out.push_str(info.format);
                    out.push_str(" output=");
                    out.push_str(&info.output_len.to_string());
                    out.push_str("B]");
                }
                if let Some(err) = meta.decompression_error.as_ref() {
                    out.push_str(" [decompression_error=");
                    out.push_str(err.as_ref());
                    out.push(']');
                }
                if let Some(err) = meta.protobuf_error.as_ref() {
                    out.push_str(" [protobuf_error=");
                    out.push_str(err.as_ref());
                    out.push(']');
                }
            });

            out
        }
    };

    view! {
        <div class=row_class prop:title=title on:click=move |_| on_open.run(idx)>
            <div class="frame-meta">
                <span>{meta_line}</span>
                <span class="frame-suffix">{suffix}</span>
            </div>
            <div class="frame-actions">
                <button
                    class="btn btn--secondary"
                    on:click=move |ev: leptos::ev::MouseEvent| {
                        ev.stop_propagation();
                        on_extract.run(idx);
                    }
                >
                    "Extract"
                </button>
            </div>
        </div>
    }
    .into_any()
}
