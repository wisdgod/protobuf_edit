use leptos::prelude::*;

#[component]
pub(crate) fn ThemeSwitcher(is_night: Memo<bool>, on_toggle: UnsyncCallback<()>) -> impl IntoView {
    let class = move || {
        if is_night.get() { "theme-switcher theme-switcher--night" } else { "theme-switcher" }
    };

    view! {
        <button
            type="button"
            class=class
            on:click=move |_| on_toggle.run(())
            aria-label="Toggle theme"
            title="Toggle theme"
        >
            <div class="theme-switcher__sun" aria-hidden="true"></div>
            <div class="theme-switcher__moon-overlay" aria-hidden="true"></div>

            <div class="theme-switcher__cloud-ball theme-switcher__cloud-ball--1" aria-hidden="true"></div>
            <div class="theme-switcher__cloud-ball theme-switcher__cloud-ball--2" aria-hidden="true"></div>
            <div class="theme-switcher__cloud-ball theme-switcher__cloud-ball--3" aria-hidden="true"></div>
            <div class="theme-switcher__cloud-ball theme-switcher__cloud-ball--4" aria-hidden="true"></div>

            <div class="theme-switcher__star theme-switcher__star--1" aria-hidden="true"></div>
            <div class="theme-switcher__star theme-switcher__star--2" aria-hidden="true"></div>
            <div class="theme-switcher__star theme-switcher__star--3" aria-hidden="true"></div>
            <div class="theme-switcher__star theme-switcher__star--4" aria-hidden="true"></div>
        </button>
    }
}
