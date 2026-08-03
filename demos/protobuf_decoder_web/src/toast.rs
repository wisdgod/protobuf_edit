use crate::error::{shared_error, UiError};
use leptos::leptos_dom::helpers::{set_timeout_with_handle, TimeoutHandle};
use leptos::prelude::*;
use rustc_hash::FxHashMap;
use std::time::Duration;

/// Keep the stack readable: when full, the oldest non-alert is evicted.
const MAX_TOASTS: usize = 5;

/// Grace period when a paused timer resumes with (almost) nothing left, so
/// the toast does not vanish the instant the cursor leaves the stack.
const RESUME_GRACE_MS: f64 = 500.0;

#[derive(Clone)]
pub struct Toast {
    pub id: usize,
    pub message: UiError,
    pub kind: ToastKind,
    /// How many times this exact message was shown while already visible.
    pub count: usize,
}

/// Attention level: how the user should treat the message, not whether the
/// operation succeeded. Presentation (duration, persistence, styling, ARIA
/// role) derives from it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    /// Receipt for a user action that has no other visible feedback
    /// (clipboard, download). Short-lived.
    Confirmation,
    /// System event or informative outcome worth a glance.
    Notice,
    /// Completed, but with a caveat the user should notice.
    Warning,
    /// Failure that needs the user's attention. Sticky by default.
    Alert,
}

impl ToastKind {
    /// Auto-dismiss delay scaled by reading effort; `None` means the toast
    /// stays until the user closes it.
    fn default_timeout(self, chars: usize) -> Option<Duration> {
        let chars = chars as u64;
        let ms = match self {
            Self::Confirmation => (2000 + 30 * chars).min(5000),
            Self::Notice => (2500 + 35 * chars).min(8000),
            Self::Warning => (4000 + 35 * chars).min(10_000),
            Self::Alert => return None,
        };
        Some(Duration::from_millis(ms))
    }

    const fn class(self) -> &'static str {
        match self {
            Self::Confirmation => "toast toast--confirmation",
            Self::Notice => "toast toast--notice",
            Self::Warning => "toast toast--warning",
            Self::Alert => "toast toast--alert",
        }
    }

    const fn role(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            _ => "status",
        }
    }
}

/// Per-call override of the kind-derived auto-dismiss policy.
#[derive(Clone, Copy)]
pub enum ToastTimeout {
    /// Kind-derived reading-time delay.
    Default,
    // Deliberate API surface: call sites may override the kind policy even
    // though none currently does.
    #[expect(dead_code, reason = "override capability for call sites")]
    After(Duration),
    /// Never auto-dismiss.
    #[expect(dead_code, reason = "override capability for call sites")]
    Sticky,
}

#[derive(Clone, Copy)]
enum TimerState {
    /// Armed; `deadline_ms` is a `Date::now()` epoch timestamp.
    Running {
        handle: TimeoutHandle,
        deadline_ms: f64,
    },
    /// Suspended while the cursor hovers the stack.
    Paused {
        remaining_ms: f64,
    },
    Sticky,
}

#[derive(Clone, Copy)]
pub(crate) struct ToastManager {
    toasts: RwSignal<Vec<Toast>>,
    next_id: RwSignal<usize>,
    // Timer bookkeeping is not rendered, so it stays out of the signal
    // graph; `TimeoutHandle` is a JS value, hence local storage.
    timers: StoredValue<FxHashMap<usize, TimerState>, LocalStorage>,
    paused: StoredValue<bool>,
}

impl ToastManager {
    pub fn new() -> Self {
        Self {
            toasts: RwSignal::new(Vec::new()),
            next_id: RwSignal::new(1),
            timers: StoredValue::new_local(FxHashMap::default()),
            paused: StoredValue::new(false),
        }
    }

    pub fn show(&self, kind: ToastKind, message: impl Into<UiError>) {
        self.show_with(kind, message, ToastTimeout::Default);
    }

    pub fn show_with(&self, kind: ToastKind, message: impl Into<UiError>, timeout: ToastTimeout) {
        let message = shared_error(message);
        let chars = message.chars().count();

        // Same kind + text while still visible: bump the counter and restart
        // the timer instead of stacking a duplicate.
        let existing = self.toasts.with_untracked(|t| {
            t.iter().find(|x| x.kind == kind && x.message == message).map(|x| x.id)
        });
        if let Some(id) = existing {
            self.toasts.update(|t| {
                if let Some(x) = t.iter_mut().find(|x| x.id == id) {
                    x.count += 1;
                }
            });
            self.clear_timer(id);
            self.arm(id, kind, timeout, chars);
            return;
        }

        // Full stack: evict the oldest auto-dismissable toast; alerts only
        // give way to other alerts.
        let evict = self.toasts.with_untracked(|t| {
            if t.len() < MAX_TOASTS {
                return None;
            }
            t.iter().find(|x| x.kind != ToastKind::Alert).or_else(|| t.first()).map(|x| x.id)
        });
        if let Some(evict_id) = evict {
            self.dismiss(evict_id);
        }

        let id = self.next_id.get_untracked();
        self.next_id.set(id.wrapping_add(1));
        self.toasts.update(|t| t.push(Toast { id, message, kind, count: 1 }));
        self.arm(id, kind, timeout, chars);
    }

    pub fn dismiss(&self, id: usize) {
        self.clear_timer(id);
        self.toasts.update(|t| t.retain(|x| x.id != id));
    }

    /// Freezes all running timers (cursor entered the stack).
    pub fn pause(&self) {
        self.paused.set_value(true);
        let now = js_sys::Date::now();
        self.timers.update_value(|m| {
            for state in m.values_mut() {
                if let TimerState::Running { handle, deadline_ms } = *state {
                    handle.clear();
                    *state = TimerState::Paused { remaining_ms: (deadline_ms - now).max(0.0) };
                }
            }
        });
    }

    /// Re-arms paused timers with their remaining time (cursor left).
    pub fn resume(&self) {
        self.paused.set_value(false);
        let pending: Vec<(usize, f64)> = self.timers.with_value(|m| {
            m.iter()
                .filter_map(|(id, state)| match state {
                    TimerState::Paused { remaining_ms } => Some((*id, *remaining_ms)),
                    _ => None,
                })
                .collect()
        });
        for (id, remaining_ms) in pending {
            self.start_timer(id, Duration::from_millis(remaining_ms.max(RESUME_GRACE_MS) as u64));
        }
    }

    pub const fn toasts_signal(&self) -> RwSignal<Vec<Toast>> {
        self.toasts
    }

    fn arm(&self, id: usize, kind: ToastKind, timeout: ToastTimeout, chars: usize) {
        let duration = match timeout {
            ToastTimeout::Default => kind.default_timeout(chars),
            ToastTimeout::After(d) => Some(d),
            ToastTimeout::Sticky => None,
        };
        let Some(duration) = duration else {
            self.timers.update_value(|m| {
                m.insert(id, TimerState::Sticky);
            });
            return;
        };
        if self.paused.get_value() {
            self.timers.update_value(|m| {
                m.insert(id, TimerState::Paused { remaining_ms: duration.as_millis() as f64 });
            });
            return;
        }
        self.start_timer(id, duration);
    }

    fn start_timer(&self, id: usize, duration: Duration) {
        let toasts = self.toasts;
        let timers = self.timers;
        let fired = move || {
            toasts.update(|t| t.retain(|x| x.id != id));
            timers.update_value(|m| {
                m.remove(&id);
            });
        };
        if let Ok(handle) = set_timeout_with_handle(fired, duration) {
            let deadline_ms = js_sys::Date::now() + duration.as_millis() as f64;
            self.timers.update_value(|m| {
                m.insert(id, TimerState::Running { handle, deadline_ms });
            });
        }
    }

    fn clear_timer(&self, id: usize) {
        self.timers.update_value(|m| {
            if let Some(TimerState::Running { handle, .. }) = m.remove(&id) {
                handle.clear();
            }
        });
    }
}

#[component]
pub fn ToastContainer(manager: ToastManager) -> impl IntoView {
    let toasts = manager.toasts_signal();

    view! {
        <div
            class="toast-container"
            on:mouseenter=move |_| manager.pause()
            on:mouseleave=move |_| manager.resume()
        >
            <For
                each=move || toasts.get()
                // Count is part of the key so a dedup bump re-renders the row.
                key=|t| (t.id, t.count)
                children=move |toast| {
                    let id = toast.id;
                    view! {
                        <div class=toast.kind.class() role=toast.kind.role()>
                            <div class="toast-body">
                                <span>{toast.message.clone()}</span>
                                {(toast.count > 1).then(|| view! {
                                    <span class="toast-count">
                                        {format!("\u{00D7}{}", toast.count)}
                                    </span>
                                })}
                            </div>
                            <button
                                class="toast-close"
                                on:click=move |_| manager.dismiss(id)
                            >
                                "\u{00D7}"
                            </button>
                        </div>
                    }
                }
            />
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_scales_with_length() {
        assert_eq!(ToastKind::Confirmation.default_timeout(0), Some(Duration::from_millis(2000)));
        assert_eq!(ToastKind::Confirmation.default_timeout(20), Some(Duration::from_millis(2600)));
        assert_eq!(ToastKind::Notice.default_timeout(10), Some(Duration::from_millis(2850)));
        assert_eq!(ToastKind::Warning.default_timeout(0), Some(Duration::from_millis(4000)));
    }

    #[test]
    fn timeout_clamps_at_kind_cap() {
        assert_eq!(
            ToastKind::Confirmation.default_timeout(1000),
            Some(Duration::from_millis(5000))
        );
        assert_eq!(ToastKind::Notice.default_timeout(1000), Some(Duration::from_millis(8000)));
        assert_eq!(ToastKind::Warning.default_timeout(1000), Some(Duration::from_millis(10_000)));
    }

    #[test]
    fn alert_is_sticky() {
        assert_eq!(ToastKind::Alert.default_timeout(0), None);
        assert_eq!(ToastKind::Alert.default_timeout(1000), None);
    }
}
