use core::fmt;

use crate::error::TreeError;
use crate::wire::WireType;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
/// Half-open byte range inside a message source buffer.
pub struct Span {
    start: u32,
    end: u32,
}

impl Span {
    #[inline]
    pub const fn new(start: u32, end: u32) -> Option<Self> {
        if start <= end { Some(Self { start, end }) } else { None }
    }

    #[inline]
    pub const fn start(self) -> u32 {
        self.start
    }

    #[inline]
    pub const fn end(self) -> u32 {
        self.end
    }

    #[inline]
    pub const fn len(self) -> u32 {
        self.end - self.start
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Span").field(&self.start).field(&self.end).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Component spans of one wire field.
pub struct FieldSpans {
    pub field: Span,
    pub tag: Span,
    pub value: ValueSpans,
}

impl FieldSpans {
    #[inline]
    pub const fn payload(self) -> Span {
        match self.value {
            ValueSpans::Varint { value }
            | ValueSpans::I32 { value }
            | ValueSpans::I64 { value } => value,
            ValueSpans::Len { payload, .. } => payload,
            #[cfg(feature = "group")]
            ValueSpans::Group { body, .. } => body,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Value-specific spans within a field.
pub enum ValueSpans {
    Varint {
        value: Span,
    },
    I32 {
        value: Span,
    },
    I64 {
        value: Span,
    },
    Len {
        len: Span,
        payload: Span,
    },
    #[cfg(feature = "group")]
    Group {
        body: Span,
        end_tag: Span,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredSpans {
    pub(crate) field: Span,
    pub(crate) tag_len: u8,
    pub(crate) aux_len: u8,
    pub(crate) payload_len: u32,
}

impl StoredSpans {
    #[inline]
    pub(crate) fn tag_span(self) -> Result<Span, TreeError> {
        let start = self.field.start();
        let end = start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
        Span::new(start, end).ok_or(TreeError::DecodeError)
    }

    #[inline]
    pub(crate) fn expand(self, wire: WireType) -> Result<FieldSpans, TreeError> {
        Ok(FieldSpans { field: self.field, tag: self.tag_span()?, value: self.value_spans(wire)? })
    }

    #[inline]
    pub(crate) fn value_spans(self, wire: WireType) -> Result<ValueSpans, TreeError> {
        match wire {
            WireType::Varint => {
                let start = self.field.start();
                let value_start =
                    start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
                let value =
                    Span::new(value_start, self.field.end()).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::Varint { value })
            }
            WireType::I32 => {
                let end = self.field.end();
                let start = end.checked_sub(4).ok_or(TreeError::DecodeError)?;
                let value = Span::new(start, end).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::I32 { value })
            }
            WireType::I64 => {
                let end = self.field.end();
                let start = end.checked_sub(8).ok_or(TreeError::DecodeError)?;
                let value = Span::new(start, end).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::I64 { value })
            }
            WireType::Len => {
                let start = self.field.start();
                let len_start =
                    start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
                let len_end = len_start
                    .checked_add(self.aux_len as u32)
                    .ok_or(TreeError::CapacityExceeded)?;
                let len = Span::new(len_start, len_end).ok_or(TreeError::DecodeError)?;

                let payload_start = len_end;
                let payload_end = payload_start
                    .checked_add(self.payload_len)
                    .ok_or(TreeError::CapacityExceeded)?;
                let payload =
                    Span::new(payload_start, payload_end).ok_or(TreeError::DecodeError)?;
                debug_assert_eq!(payload_end, self.field.end());
                Ok(ValueSpans::Len { len, payload })
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let start = self.field.start();
                let body_start =
                    start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
                let body_end = self
                    .field
                    .end()
                    .checked_sub(self.aux_len as u32)
                    .ok_or(TreeError::DecodeError)?;
                let body = Span::new(body_start, body_end).ok_or(TreeError::DecodeError)?;
                let end_tag =
                    Span::new(body_end, self.field.end()).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::Group { body, end_tag })
            }
            #[cfg(feature = "group")]
            WireType::EGroup => Err(TreeError::DecodeError),
        }
    }

    #[inline]
    pub(crate) fn payload_span(self, wire: WireType) -> Result<Span, TreeError> {
        match wire {
            WireType::Len => {
                let ValueSpans::Len { payload, .. } = self.value_spans(wire)? else {
                    return Err(TreeError::DecodeError);
                };
                Ok(payload)
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let ValueSpans::Group { body, .. } = self.value_spans(wire)? else {
                    return Err(TreeError::DecodeError);
                };
                Ok(body)
            }
            _ => Err(TreeError::WireTypeMismatch),
        }
    }
}

#[inline]
pub(crate) fn slice_span(bytes: &[u8], span: Span) -> Result<&[u8], TreeError> {
    let start = span.start() as usize;
    let end = span.end() as usize;
    if end > bytes.len() {
        return Err(TreeError::DecodeError);
    }
    Ok(&bytes[start..end])
}

#[inline]
pub(crate) fn span_offset_by(span: Span, base: u32) -> Result<Span, TreeError> {
    let start = base.checked_add(span.start()).ok_or(TreeError::CapacityExceeded)?;
    let end = base.checked_add(span.end()).ok_or(TreeError::CapacityExceeded)?;
    Span::new(start, end).ok_or(TreeError::DecodeError)
}

#[inline]
pub(crate) fn value_spans_offset_by(value: ValueSpans, base: u32) -> Result<ValueSpans, TreeError> {
    match value {
        ValueSpans::Varint { value } => {
            Ok(ValueSpans::Varint { value: span_offset_by(value, base)? })
        }
        ValueSpans::I32 { value } => Ok(ValueSpans::I32 { value: span_offset_by(value, base)? }),
        ValueSpans::I64 { value } => Ok(ValueSpans::I64 { value: span_offset_by(value, base)? }),
        ValueSpans::Len { len, payload } => Ok(ValueSpans::Len {
            len: span_offset_by(len, base)?,
            payload: span_offset_by(payload, base)?,
        }),
        #[cfg(feature = "group")]
        ValueSpans::Group { body, end_tag } => Ok(ValueSpans::Group {
            body: span_offset_by(body, base)?,
            end_tag: span_offset_by(end_tag, base)?,
        }),
    }
}
