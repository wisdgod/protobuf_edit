use alloc::vec::Vec;

use crate::document::TreeError;
use crate::wire::{FieldNumber, WireType};

use super::decode::{decode_tag_prefix, decode_varint32_prefix, decode_varint64_prefix};
use super::state::GroupProgress;

pub(super) fn scan_group_progress_stateful(
    data: &[u8],
    scan_offset: &mut usize,
    scan_stack: &mut Vec<FieldNumber>,
    group_field_number: FieldNumber,
) -> Result<GroupProgress, TreeError> {
    loop {
        let tag_start = *scan_offset;

        let Some((tag, tag_len)) = decode_tag_prefix(&data[tag_start..])? else {
            *scan_offset = tag_start;
            return Ok(GroupProgress::Incomplete { known_payload_end: tag_start });
        };
        *scan_offset = scan_offset.checked_add(tag_len).ok_or(TreeError::CapacityExceeded)?;

        match tag.wire_type() {
            WireType::Varint => {
                let Some((_v, n)) = decode_varint64_prefix(&data[*scan_offset..])? else {
                    *scan_offset = tag_start;
                    return Ok(GroupProgress::Incomplete { known_payload_end: tag_start });
                };
                *scan_offset = scan_offset.checked_add(n).ok_or(TreeError::CapacityExceeded)?;
            }
            WireType::I64 => {
                let end = scan_offset.checked_add(8).ok_or(TreeError::CapacityExceeded)?;
                if data.len() < end {
                    *scan_offset = tag_start;
                    return Ok(GroupProgress::Incomplete { known_payload_end: tag_start });
                }
                *scan_offset = end;
            }
            WireType::Len => {
                let Some((payload_len, len_len)) = decode_varint32_prefix(&data[*scan_offset..])?
                else {
                    *scan_offset = tag_start;
                    return Ok(GroupProgress::Incomplete { known_payload_end: tag_start });
                };
                let payload_len =
                    usize::try_from(payload_len).map_err(|_| TreeError::CapacityExceeded)?;
                let payload_start =
                    scan_offset.checked_add(len_len).ok_or(TreeError::CapacityExceeded)?;
                let payload_end =
                    payload_start.checked_add(payload_len).ok_or(TreeError::CapacityExceeded)?;
                if data.len() < payload_end {
                    *scan_offset = tag_start;
                    return Ok(GroupProgress::Incomplete { known_payload_end: tag_start });
                }
                *scan_offset = payload_end;
            }
            WireType::I32 => {
                let end = scan_offset.checked_add(4).ok_or(TreeError::CapacityExceeded)?;
                if data.len() < end {
                    *scan_offset = tag_start;
                    return Ok(GroupProgress::Incomplete { known_payload_end: tag_start });
                }
                *scan_offset = end;
            }
            WireType::SGroup => {
                scan_stack.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
                scan_stack.push(tag.field_number());
            }
            WireType::EGroup => {
                if let Some(expected) = scan_stack.last().copied() {
                    if tag.field_number() != expected {
                        return Err(TreeError::DecodeError);
                    }
                    scan_stack.pop();
                    continue;
                }

                if tag.field_number() == group_field_number {
                    return Ok(GroupProgress::Complete {
                        end_start: tag_start,
                        end_after: *scan_offset,
                    });
                }
                return Err(TreeError::DecodeError);
            }
        }
    }
}
