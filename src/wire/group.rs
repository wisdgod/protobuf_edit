use core::intrinsics::unlikely;

use crate::varint;

use super::codec::decode_tag;
use super::tag::{FieldNumber, WireType};

pub fn find_group_end(
    data: &[u8],
    body_start: usize,
    group_field_number: FieldNumber,
) -> Option<(usize, usize)> {
    let mut offset = body_start;

    loop {
        let end_tag_start = offset;
        let (tag, tag_len) = decode_tag(&data[offset..])?;
        offset = offset.checked_add(tag_len as usize)?;
        if unlikely(offset > data.len()) {
            return None;
        }

        let (field_number, wire_type) = tag.split();
        match wire_type {
            WireType::EGroup => {
                if field_number == group_field_number {
                    return Some((end_tag_start, offset));
                }
                return None;
            }
            WireType::SGroup => {
                let (_, next_after_end) = find_group_end(data, offset, field_number)?;
                offset = next_after_end;
            }
            _ => {
                offset = skip_scalar_value(data, offset, wire_type)?;
            }
        }
    }
}

#[inline]
fn skip_scalar_value(data: &[u8], offset: usize, wire_type: WireType) -> Option<usize> {
    match wire_type {
        WireType::Varint => {
            let (_, n) = varint::decode64(&data[offset..])?;
            let end = offset.checked_add(n as usize)?;
            if unlikely(end > data.len()) {
                return None;
            }
            Some(end)
        }
        WireType::I64 => {
            let end = offset.checked_add(8)?;
            if unlikely(end > data.len()) {
                return None;
            }
            Some(end)
        }
        WireType::Len => {
            let (len, n) = varint::decode32(&data[offset..])?;
            let body_start = offset.checked_add(n as usize)?;
            let body_end = body_start.checked_add(len as usize)?;
            if unlikely(body_end > data.len()) {
                return None;
            }
            Some(body_end)
        }
        WireType::I32 => {
            let end = offset.checked_add(4)?;
            if unlikely(end > data.len()) {
                return None;
            }
            Some(end)
        }
        WireType::SGroup | WireType::EGroup => None,
    }
}
