use crate::data_structures::{Buf, BufAllocError};
use crate::varint;

use super::tag::{FieldNumber, Tag, WireType};

#[inline]
pub fn encode_tag(
    buf: &mut Buf,
    field_number: FieldNumber,
    wire_type: WireType,
) -> Result<(), BufAllocError> {
    encode_tag_value(buf, Tag::from_parts(field_number, wire_type))
}

#[inline]
pub fn encode_tag_value(buf: &mut Buf, tag: Tag) -> Result<(), BufAllocError> {
    let _ = varint::encode32(buf, tag.get())?;
    Ok(())
}

#[inline]
pub fn decode_tag(data: &[u8]) -> Option<(Tag, u32)> {
    let (raw, n) = varint::decode32(data)?;
    let tag = Tag::new(raw)?;
    Some((tag, n))
}
