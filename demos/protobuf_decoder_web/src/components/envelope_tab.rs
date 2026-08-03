use crate::components::{EnvelopeFramesPanel, FieldTree};
use crate::hex_view::HexGrid;
use crate::services::EnvelopeService;
use crate::state::EnvelopeTabState;
use leptos::html;
use leptos::prelude::*;
use leptos_use::use_event_listener;

/// One open envelope: the frame list on top plus a read-only hex/tree
/// preview of the selected frame below.
///
/// Provides the preview `WorkspaceState` as context so the hex grid and
/// field tree operate on the previewed frame.
#[component]
pub(crate) fn EnvelopeTabView(env: EnvelopeTabState, split_px: RwSignal<f64>) -> impl IntoView {
    provide_context(env.preview.clone());

    // Covers every activation path (open action, tab click, session
    // restore): an unloaded envelope tab loads itself once mounted.
    {
        let env_svc = expect_context::<EnvelopeService>();
        Effect::new(move |_| env_svc.ensure_active_loaded());
    }

    let preview = env.preview.clone();
    let patch_state = preview.patch_state;
    let raw_bytes = preview.raw_bytes;
    let hex_text_mode = preview.hex_text_mode;

    let split_ref = NodeRef::<html::Div>::new();
    let hex_container_ref = NodeRef::<html::Div>::new();
    let split_dragging: RwSignal<bool> = RwSignal::new(false);

    let _stop_split_move = use_event_listener(
        web_sys::window().expect("window is available"),
        leptos::ev::mousemove,
        move |ev: web_sys::MouseEvent| {
            if !split_dragging.get_untracked() {
                return;
            }
            let Some(el) = split_ref.get() else {
                return;
            };
            let rect = el.get_bounding_client_rect();
            let w = rect.width();
            if w <= 0.0 {
                return;
            }
            let max = (w - 220.0).max(0.0);
            let x = (f64::from(ev.client_x()) - rect.left()).clamp(0.0, max);
            split_px.set(x);
        },
    );

    let _stop_split_up = use_event_listener(
        web_sys::window().expect("window is available"),
        leptos::ev::mouseup,
        move |_| {
            if split_dragging.get_untracked() {
                split_dragging.set(false);
            }
        },
    );

    let preview_fallback = move || {
        if raw_bytes.with(std::option::Option::is_some) {
            view! { <div class="panel-header">"No protobuf structure."</div> }.into_any()
        } else {
            view! { <div class="panel-header">"No frame selected."</div> }.into_any()
        }
    };

    let field_tree_view = move || {
        patch_state
            .with(|p| p.as_ref().map(protobuf_edit::Patch::root))
            .map(|root| view! { <FieldTree msg=root depth=0 /> })
    };

    view! {
        <div class="document">
            <EnvelopeFramesPanel env=env.clone() />

            <div class="workspace">
                <div node_ref=split_ref class="split-pane">
                    <div
                        class="split-left"
                        style:flex=move || format!("0 1 {:.0}px", split_px.get())
                    >
                        <div class="panel">
                            <div class="panel-header">
                                <span>"Frame Preview (read-only)"</span>
                                <button
                                    class="btn btn--secondary btn--small"
                                    on:click=move |_| hex_text_mode.update(|m| *m = m.toggle())
                                >
                                    {move || hex_text_mode.get().label()}
                                </button>
                            </div>
                            <HexGrid container_ref=hex_container_ref />
                        </div>
                    </div>
                    <div
                        class="split-handle"
                        on:mousedown=move |ev: leptos::ev::MouseEvent| {
                            ev.prevent_default();
                            split_dragging.set(true);
                        }
                    ></div>
                    <div class="split-right" style:flex="1 1 0">
                        <div class="panel panel--right">
                            <div class="structure">
                                <div class="field-list" tabindex="0">
                                    <Show
                                        when=move || patch_state.with(std::option::Option::is_some)
                                        fallback=preview_fallback
                                    >
                                        {field_tree_view}
                                    </Show>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}
