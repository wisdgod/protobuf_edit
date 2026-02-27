use core::intrinsics::unlikely;
use crate::wire::{FieldNumber, Tag, WireType};

use super::{Ix, TreeError};

#[inline]
pub(super) const fn checked_push_plan(
    field_number: FieldNumber,
    wire_type: WireType,
    pool_len: usize,
    fields_len: usize,
) -> Result<(Tag, Ix, Ix), TreeError> {
    let tag = Tag::from_parts(field_number, wire_type);
    let slot = match to_ix(pool_len) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let field_ix = match to_ix(fields_len) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    Ok((tag, slot, field_ix))
}

#[inline]
pub(super) fn ensure_decode_len(len: usize) -> Result<(), TreeError> {
    if unlikely(len > const { i32::MAX as usize }) {
        return Err(TreeError::DecodeError);
    }
    Ok(())
}

#[inline]
pub(super) fn checked_advance(
    offset: usize,
    delta: usize,
    data_len: usize,
) -> Result<usize, TreeError> {
    let next = offset.checked_add(delta).ok_or(TreeError::DecodeError)?;
    if unlikely(next > data_len) {
        return Err(TreeError::DecodeError);
    }
    Ok(next)
}

#[inline]
pub(super) fn trusted_advance(offset: usize, delta: usize, data_len: usize) -> usize {
    let next = offset.checked_add(delta).expect("trusted advance overflow");
    debug_assert!(next <= data_len, "trusted advance exceeded input length");
    next
}

#[inline]
const fn to_ix(len: usize) -> Result<Ix, TreeError> {
    if len > Ix::MAX.as_inner() as usize {
        return Err(TreeError::CapacityExceeded);
    }
    // SAFETY: `len <= Ix::MAX` guaranteed above.
    Ok(unsafe { Ix::new_unchecked(len as u16) })
}
