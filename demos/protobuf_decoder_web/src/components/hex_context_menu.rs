use crate::hex_copy::CopyFormat;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

#[component]
pub(crate) fn HexContextMenu(
    visible: RwSignal<bool>,
    position: RwSignal<(i32, i32)>,
    on_select: Callback<CopyFormat>,
) -> impl IntoView {
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
            >
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
            </div>
        })
    }
}
