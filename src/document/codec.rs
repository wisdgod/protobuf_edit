use core::intrinsics::{likely, unlikely};

use crate::data_structures::Buf;
use crate::varint;
use crate::wire::{self, WireType};

use super::helpers::{checked_advance, ensure_decode_len, trusted_advance};
use super::{Capacities, Document, RawVarint32, RawVarint64, TreeError, MAX_FIELDS};

impl Document {
    pub fn from_bytes(data: &[u8]) -> Result<Self, TreeError> {
        Self::from_bytes_decode_mode(data, None, false)
    }

    pub fn from_bytes_with_capacities(
        data: &[u8],
        capacities: Capacities,
    ) -> Result<Self, TreeError> {
        Self::from_bytes_decode_mode(data, Some(capacities), false)
    }

    pub fn from_bytes_precise(data: &[u8]) -> Result<Self, TreeError> {
        let capacities = decode_capacities(data)?;
        Self::from_bytes_decode_mode(data, Some(capacities), false)
    }

    #[inline]
    pub fn to_buf(&self) -> Result<Buf, TreeError> {
        let mut out = Buf::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    pub fn encoded_len(&self) -> Result<u32, TreeError> {
        #[inline]
        fn checked_add(total: &mut u32, add: u32) -> Result<(), TreeError> {
            *total = total.checked_add(add).ok_or(TreeError::CapacityExceeded)?;
            if unlikely(*total > i32::MAX as u32) {
                return Err(TreeError::CapacityExceeded);
            }
            Ok(())
        }

        let mut total = 0u32;
        for field in &self.fields {
            if field.removed {
                continue;
            }

            let (_field_number, wire_type) = field.tag.split();
            let slot = field.index.as_inner() as usize;

            let tag_len = field.raw.len();
            if unlikely(tag_len == 0) {
                return Err(TreeError::DecodeError);
            }
            checked_add(&mut total, tag_len as u32)?;
            match wire_type {
                WireType::Varint => {
                    let raw_len = self.varints[slot].raw.len();
                    if unlikely(raw_len == 0) {
                        return Err(TreeError::DecodeError);
                    }
                    checked_add(&mut total, raw_len as u32)?;
                }
                WireType::I64 => {
                    checked_add(&mut total, 8)?;
                }
                WireType::Len => {
                    let val = &self.lendels[slot].buf;
                    let raw_len = self.lendels[slot].raw.len();
                    if unlikely(raw_len == 0) {
                        return Err(TreeError::DecodeError);
                    }
                    checked_add(&mut total, raw_len as u32)?;
                    checked_add(&mut total, val.len())?;
                }
                #[cfg(feature = "group")]
                WireType::SGroup => {
                    checked_add(&mut total, self.groups[slot].buf.len())?;
                    let end_tag = crate::wire::Tag::from_parts(_field_number, WireType::EGroup);
                    checked_add(&mut total, varint::encoded_len32(end_tag.get()))?;
                }
                #[cfg(feature = "group")]
                WireType::EGroup => {
                    debug_assert!(false, "EndGroup should never be stored in fields")
                }
                WireType::I32 => {
                    checked_add(&mut total, 4)?;
                }
            }
        }
        Ok(total)
    }

    pub fn encode_into(&self, out: &mut Buf) -> Result<(), TreeError> {
        let encoded_len = self.encoded_len()?;
        let start_len = out.len();
        out.try_reserve(encoded_len)?;
        // SAFETY:
        // - `try_reserve(encoded_len)` guarantees enough writable capacity for this encode pass.
        // - `encoded_len()` and the encoder below share the same field/wire traversal logic.
        // - Encode helpers only fail on allocation; after reserving exact extra bytes this is infallible.
        unsafe { self.encode_into_unchecked(out) };
        debug_assert_eq!(out.len(), start_len + encoded_len);
        Ok(())
    }

    #[inline]
    unsafe fn encode_into_unchecked(&self, out: &mut Buf) {
        #[inline(always)]
        unsafe fn assume_ok<T, E>(ret: Result<T, E>) -> T {
            match ret {
                Ok(v) => v,
                // SAFETY: caller guarantees capacity/invariants that make this path unreachable.
                Err(_) => unsafe { core::hint::unreachable_unchecked() },
            }
        }

        for field in &self.fields {
            if field.removed {
                continue;
            }

            let (_field_number, wire_type) = field.tag.split();
            let slot = field.index.as_inner() as usize;

            let (tag_raw, tag_len) = field.raw.to_array();
            // SAFETY: covered by `encode_into_unchecked` contract.
            unsafe { assume_ok(out.extend_from_slice(&tag_raw[..tag_len])) };
            match wire_type {
                WireType::Varint => {
                    let (raw, raw_len) = self.varints[slot].raw.to_array();
                    // SAFETY: covered by `encode_into_unchecked` contract.
                    unsafe { assume_ok(out.extend_from_slice(&raw[..raw_len])) };
                }
                WireType::I64 => {
                    // SAFETY: covered by `encode_into_unchecked` contract.
                    unsafe {
                        assume_ok(out.extend_from_slice(&self.fixed64s[slot].value.to_le_bytes()))
                    };
                }
                WireType::Len => {
                    let val = &self.lendels[slot].buf;
                    let (raw, raw_len) = self.lendels[slot].raw.to_array();
                    // SAFETY: covered by `encode_into_unchecked` contract.
                    unsafe { assume_ok(out.extend_from_slice(&raw[..raw_len])) };
                    // SAFETY: covered by `encode_into_unchecked` contract.
                    unsafe { assume_ok(out.extend_from_slice(val.as_slice())) };
                }
                #[cfg(feature = "group")]
                WireType::SGroup => {
                    // SAFETY: covered by `encode_into_unchecked` contract.
                    unsafe { assume_ok(out.extend_from_slice(self.groups[slot].buf.as_slice())) };
                    // SAFETY: covered by `encode_into_unchecked` contract.
                    unsafe {
                        assume_ok(wire::encode_tag_value(
                            out,
                            crate::wire::Tag::from_parts(_field_number, WireType::EGroup),
                        ))
                    };
                }
                #[cfg(feature = "group")]
                WireType::EGroup => {
                    debug_assert!(false, "EndGroup should never be stored in fields")
                }
                WireType::I32 => {
                    // SAFETY: covered by `encode_into_unchecked` contract.
                    unsafe {
                        assume_ok(out.extend_from_slice(&self.fixed32s[slot].value.to_le_bytes()))
                    };
                }
            }
        }
    }
}

impl Document {
    #[inline]
    pub(super) fn from_bytes_borrowed(
        data: &[u8],
        capacities: Option<Capacities>,
    ) -> Result<Self, TreeError> {
        Self::from_bytes_decode_mode(data, capacities, true)
    }

    fn from_bytes_decode_mode(
        data: &[u8],
        capacities: Option<Capacities>,
        borrowed_payloads: bool,
    ) -> Result<Self, TreeError> {
        ensure_decode_len(data.len())?;
        let mut tree = match capacities {
            Some(caps) => Self::with_capacities(caps),
            None => Self::new(),
        };
        decode_into_tree(&mut tree, data, borrowed_payloads)?;
        Ok(tree)
    }
}

fn decode_capacities(data: &[u8]) -> Result<Capacities, TreeError> {
    ensure_decode_len(data.len())?;

    let data_len = data.len();
    let mut offset = 0usize;
    let mut capacities = Capacities::default();

    while likely(offset < data_len) {
        let (tag_value, tag_len) =
            wire::decode_tag(&data[offset..]).ok_or(TreeError::DecodeError)?;
        let (_field_number, wire_type) = tag_value.split();
        offset = trusted_advance(offset, tag_len as usize, data_len);

        capacities.fields = capacities.fields.checked_add(1).ok_or(TreeError::CapacityExceeded)?;
        if capacities.fields > MAX_FIELDS {
            return Err(TreeError::CapacityExceeded);
        }

        match wire_type {
            WireType::Varint => {
                let (_, n) = varint::decode64(&data[offset..]).ok_or(TreeError::DecodeError)?;
                offset = trusted_advance(offset, n as usize, data_len);
                capacities.varints =
                    capacities.varints.checked_add(1).ok_or(TreeError::CapacityExceeded)?;
            }
            WireType::I64 => {
                offset = checked_advance(offset, 8, data_len)?;
                capacities.fixed64s =
                    capacities.fixed64s.checked_add(1).ok_or(TreeError::CapacityExceeded)?;
            }
            WireType::Len => {
                let (len, n) = varint::decode32(&data[offset..]).ok_or(TreeError::DecodeError)?;
                let prefix_end = trusted_advance(offset, n as usize, data_len);
                offset = checked_advance(prefix_end, len as usize, data_len)?;
                capacities.lendels =
                    capacities.lendels.checked_add(1).ok_or(TreeError::CapacityExceeded)?;
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let (_, next_after_end) = wire::find_group_end(data, offset, _field_number)
                    .ok_or(TreeError::DecodeError)?;
                offset = next_after_end;
                capacities.groups =
                    capacities.groups.checked_add(1).ok_or(TreeError::CapacityExceeded)?;
            }
            #[cfg(feature = "group")]
            WireType::EGroup => return Err(TreeError::DecodeError),
            WireType::I32 => {
                offset = checked_advance(offset, 4, data_len)?;
                capacities.fixed32s =
                    capacities.fixed32s.checked_add(1).ok_or(TreeError::CapacityExceeded)?;
            }
        }
    }

    capacities.query = capacities.fields;
    Ok(capacities)
}

fn decode_into_tree(
    tree: &mut Document,
    data: &[u8],
    borrowed_payloads: bool,
) -> Result<(), TreeError> {
    #[inline]
    const fn ceil_mul_div(a: usize, b: usize, d: usize) -> usize {
        debug_assert!(d != 0);
        // Under the library's field-limit invariants, u64 is sufficient and cheaper than u128.
        let a = a as u64;
        let b = b as u64;
        let d = d as u64;
        (a * b).div_ceil(d) as usize
    }

    let data_len = data.len();
    let mut offset = 0usize;

    let mut seen_fields = 0usize;
    let mut seen_varints = 0usize;
    let mut seen_fixed32s = 0usize;
    let mut seen_fixed64s = 0usize;
    let mut seen_lendels = 0usize;
    #[cfg(feature = "group")]
    let mut seen_groups = 0usize;

    let mut reserved = false;

    while likely(offset < data_len) {
        let (tag_value, tag_len) =
            wire::decode_tag(&data[offset..]).ok_or(TreeError::DecodeError)?;
        let (field_number, wire_type) = tag_value.split();

        offset = trusted_advance(offset, tag_len as usize, data_len);
        seen_fields += 1;
        if seen_fields > MAX_FIELDS {
            return Err(TreeError::CapacityExceeded);
        }

        match wire_type {
            WireType::Varint => {
                let (value, n, raw) = RawVarint64::from_data(&data[offset..])?;
                let end = trusted_advance(offset, n as usize, data_len);
                tree.push_varint_with_raw(field_number, value, raw)?;
                seen_varints += 1;
                offset = end;
            }
            WireType::I64 => {
                let end = checked_advance(offset, 8, data_len)?;
                let bytes: [u8; 8] = data[offset..end]
                    .try_into()
                    .expect("checked_advance(8) guarantees exact 8-byte slice");
                tree.push_fixed64(field_number, u64::from_le_bytes(bytes))?;
                seen_fixed64s += 1;
                offset = end;
            }
            WireType::Len => {
                let (len, n, raw) = RawVarint32::from_data(&data[offset..])?;
                let prefix_end = trusted_advance(offset, n as usize, data_len);
                let body_end = checked_advance(prefix_end, len as usize, data_len)?;

                let mut buf = if borrowed_payloads {
                    // SAFETY: `data` outlives this function; borrowed buffers are only exposed
                    // through short-lived field views inside scoped APIs.
                    unsafe { Buf::from_borrowed_slice(&data[prefix_end..body_end]) }
                } else {
                    Buf::new()
                };
                if !borrowed_payloads {
                    buf.extend_from_slice(&data[prefix_end..body_end])?;
                }
                tree.push_length_delimited_with_raw(field_number, buf, raw)?;
                seen_lendels += 1;
                offset = body_end;
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let (group_end_tag_start, next_after_end) =
                    wire::find_group_end(data, offset, field_number)
                        .ok_or(TreeError::DecodeError)?;
                let mut buf = if borrowed_payloads {
                    // SAFETY: `data` outlives this function; borrowed buffers are only exposed
                    // through short-lived field views inside scoped APIs.
                    unsafe { Buf::from_borrowed_slice(&data[offset..group_end_tag_start]) }
                } else {
                    Buf::new()
                };
                if !borrowed_payloads {
                    buf.extend_from_slice(&data[offset..group_end_tag_start])?;
                }
                tree.push_group(field_number, buf)?;
                seen_groups += 1;
                offset = next_after_end;
            }
            #[cfg(feature = "group")]
            WireType::EGroup => return Err(TreeError::DecodeError),
            WireType::I32 => {
                let end = checked_advance(offset, 4, data_len)?;
                let bytes: [u8; 4] = data[offset..end]
                    .try_into()
                    .expect("checked_advance(4) guarantees exact 4-byte slice");
                tree.push_fixed32(field_number, u32::from_le_bytes(bytes))?;
                seen_fixed32s += 1;
                offset = end;
            }
        }

        // One-shot reserve based on observed field density. This avoids the full 2-pass scan while
        // still preventing pathological Vec/HashMap growth for large, field-dense messages.
        if !reserved && seen_fields >= 32 && offset >= 4096 {
            let mut est_fields = ceil_mul_div(seen_fields, data_len, offset);
            est_fields = est_fields.saturating_add((est_fields >> 3) + 8); // +12.5% headroom
            if est_fields > MAX_FIELDS {
                est_fields = MAX_FIELDS;
            }

            let caps = Capacities {
                fields: est_fields,
                varints: ceil_mul_div(seen_varints, est_fields, seen_fields),
                fixed32s: ceil_mul_div(seen_fixed32s, est_fields, seen_fields),
                fixed64s: ceil_mul_div(seen_fixed64s, est_fields, seen_fields),
                lendels: ceil_mul_div(seen_lendels, est_fields, seen_fields),
                #[cfg(feature = "group")]
                groups: ceil_mul_div(seen_groups, est_fields, seen_fields),
                query: ceil_mul_div(tree.query.len(), est_fields, seen_fields),
            };

            tree.reserve_capacities(caps);
            reserved = true;
        }
    }
    Ok(())
}
