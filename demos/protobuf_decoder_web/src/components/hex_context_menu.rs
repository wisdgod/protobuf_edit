use crate::hex_copy::CopyFormat;
use crate::hex_view::HexTextMode;
use crate::state::UiState;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// Hex pane context menu: text-column mode switch plus, when a byte range is
/// selected, the copy formats.
#[component]
pub(crate) fn HexContextMenu(
    visible: RwSignal<bool>,
    position: RwSignal<(i32, i32)>,
    text_mode: RwSignal<HexTextMode>,
    has_selection: Memo<bool>,
    on_select: Callback<CopyFormat>,
) -> impl IntoView {
    let locale = expect_context::<UiState>().locale;
    let menu_ref = NodeRef::<html::Div>::new();

    let _dismiss_click = leptos_use::use_event_listener(
        web_sys::window().expect("window"),
        leptos::ev::mousedown,
        move |ev: web_sys::MouseEvent| {
            if !visible.get_untracked() {
                return;
            }
            let Some(el) = menu_ref.get() else { return };
            let Some(target) = ev.target() else { return };
            let target: web_sys::Node = target.unchecked_into();
            let container: &web_sys::Node = el.as_ref();
            if !container.contains(Some(&target)) {
                visible.set(false);
            }
        },
    );

    let _dismiss_esc = leptos_use::use_event_listener(
        web_sys::window().expect("window"),
        leptos::ev::keydown,
        move |ev: web_sys::KeyboardEvent| {
            if visible.get_untracked() && ev.key() == "Escape" {
                ev.stop_propagation();
                visible.set(false);
            }
        },
    );

    let mode_label = move |mode: HexTextMode| -> &'static str {
        match mode {
            HexTextMode::Off => locale.get().t().text_off,
            other => other.label(),
        }
    };

    move || {
        if !visible.get() {
            return None;
        }
        let (x, y) = position.get();
        Some(view! {
            <div
                node_ref=menu_ref
                class="hex-context-menu"
                style:left=format!("{x}px")
                style:top=format!("{y}px")
                // The menu lives inside the hex container, whose mousedown
                // handler closes the menu; without this the item would be
                // unmounted before its click event can fire.
                on:mousedown=move |ev: web_sys::MouseEvent| ev.stop_propagation()
            >
                <div class="hex-context-menu__label">
                    {move || locale.get().t().text_column}
                </div>
                {HexTextMode::ALL.iter().map(|&mode| {
                    view! {
                        <button
                            class="hex-context-menu__item"
                            class:hex-context-menu__item--active=move || {
                                text_mode.get() == mode
                            }
                            on:click=move |_| {
                                text_mode.set(mode);
                                visible.set(false);
                            }
                        >
                            {move || mode_label(mode)}
                        </button>
                    }
                }).collect::<Vec<_>>()}

                <Show when=move || has_selection.get() fallback=|| ()>
                    <div class="hex-context-menu__separator"></div>
                    <div class="hex-context-menu__label">
                        {move || locale.get().t().copy_as}
                    </div>
                    {CopyFormat::ALL.iter().map(|&fmt| {
                        view! {
                            <button
                                class="hex-context-menu__item"
                                on:click=move |_| {
                                    on_select.run(fmt);
                                    visible.set(false);
                                }
                            >
                                {fmt.label()}
                            </button>
                        }
                    }).collect::<Vec<_>>()}
                </Show>
            </div>
        })
    }
}
