use std::borrow::Cow;

pub(crate) type UiError = Cow<'static, str>;
pub(crate) type UiResult<T> = Result<T, UiError>;
