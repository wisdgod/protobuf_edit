use leptos::oco::Oco;

pub(crate) type UiError = Oco<'static, str>;
pub(crate) type UiResult<T> = Result<T, UiError>;

pub(crate) fn shared_error(message: impl Into<UiError>) -> UiError {
    let mut message = message.into();
    message.upgrade_inplace();
    message
}
