use crate::error::TreeError;
use crate::varint;
use crate::wire::Tag;

const MAX_VARINT32_BYTES: usize = 5;
const MAX_VARINT64_BYTES: usize = 10;

#[inline]
pub(super) fn decode_tag_prefix(data: &[u8]) -> Result<Option<(Tag, usize)>, TreeError> {
    if data.is_empty() {
        return Ok(None);
    }

    let Some((raw_tag, used)) = varint::decode32(data) else {
        return if data.len() >= MAX_VARINT32_BYTES {
            Err(TreeError::DecodeError)
        } else {
            Ok(None)
        };
    };

    let tag = Tag::new(raw_tag).ok_or(TreeError::InvalidTag)?;
    Ok(Some((tag, used as usize)))
}

#[inline]
pub(super) fn decode_varint32_prefix(data: &[u8]) -> Result<Option<(u32, usize)>, TreeError> {
    let Some((value, used)) = varint::decode32(data) else {
        return if data.len() >= MAX_VARINT32_BYTES {
            Err(TreeError::DecodeError)
        } else {
            Ok(None)
        };
    };
    Ok(Some((value, used as usize)))
}

#[inline]
pub(super) fn decode_varint64_prefix(data: &[u8]) -> Result<Option<(u64, usize)>, TreeError> {
    let Some((value, used)) = varint::decode64(data) else {
        return if data.len() >= MAX_VARINT64_BYTES {
            Err(TreeError::DecodeError)
        } else {
            Ok(None)
        };
    };
    Ok(Some((value, used as usize)))
}
