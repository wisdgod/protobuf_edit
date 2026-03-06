use crate::error::{shared_error, UiError};
use leptos::leptos_dom::helpers::set_timeout;
use leptos::prelude::*;
use std::time::Duration;

#[derive(Clone)]
pub struct Toast {
    pub id: u64,
    pub message: UiError,
    pub kind: ToastKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
}

pub fn show_toast(
    toasts: RwSignal<Vec<Toast>>,
    next_toast_id: RwSignal<u64>,
    kind: ToastKind,
    message: impl Into<UiError>,
) {
    let id = next_toast_id.get_untracked();
    next_toast_id.set(id.saturating_add(1));
    let message = shared_error(message);
    toasts.update(|t| t.push(Toast { id, message, kind }));

    set_timeout(
        move || {
            toasts.update(|t| t.retain(|x| x.id != id));
        },
        Duration::from_secs(4),
    );
}

#[component]
pub fn ToastContainer(toasts: RwSignal<Vec<Toast>>) -> impl IntoView {
    view! {
        <div class="toast-container">
            <For
                each=move || toasts.get()
                key=|t| t.id
                children=move |toast| {
                    let cls = match toast.kind {
                        ToastKind::Success => "toast toast--success",
                        ToastKind::Error => "toast toast--error",
                    };
                    view! {
                        <div class=cls>
                            <div>{toast.message.clone()}</div>
                            <button
                                class="toast-close"
                                on:click=move |_| toasts.update(|t| t.retain(|x| x.id != toast.id))
                            >
                                "×"
                            </button>
                        </div>
                    }
                }
            />
        </div>
    }
}
