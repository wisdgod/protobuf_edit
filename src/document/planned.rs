use crate::data_structures::Buf;
use crate::wire::{Tag, WireType};

use super::helpers::ensure_decode_len;
use super::{Capacities, FieldMut, FieldRef, Document, TreeError, MAX_FIELDS};

#[inline]
fn validate_step_capacity(cap: Capacities) -> Result<(), TreeError> {
    if cap.fields > MAX_FIELDS {
        return Err(TreeError::CapacityExceeded);
    }
    Ok(())
}

#[inline]
fn nested_payload_ref(field: FieldRef<'_>) -> Result<&[u8], TreeError> {
    match field.wire_type() {
        WireType::Len => field.as_bytes().ok_or(TreeError::WireTypeMismatch),
        #[cfg(feature = "group")]
        WireType::SGroup => field.as_group_bytes().ok_or(TreeError::WireTypeMismatch),
        _ => Err(TreeError::WireTypeMismatch),
    }
}

#[inline]
fn set_nested_payload_mut(field: &mut FieldMut<'_>, payload: Buf) -> Result<(), TreeError> {
    field.replace_nested_payload(payload)
}

fn visit_refs_path<F>(
    tree: &Document,
    plan: &[(Tag, Capacities)],
    depth: usize,
    f: &mut F,
) -> Result<(), TreeError>
where
    F: for<'a> FnMut(FieldRef<'a>),
{
    let (tag, _cap) = plan[depth];
    if depth + 1 == plan.len() {
        for field in tree.repeated_refs(tag) {
            f(field);
        }
        return Ok(());
    }

    let next_cap = plan[depth + 1].1;
    for field in tree.repeated_refs(tag) {
        let bytes = nested_payload_ref(field)?;
        let nested = Document::from_bytes_borrowed(bytes, Some(next_cap))?;
        visit_refs_path(&nested, plan, depth + 1, f)?;
    }
    Ok(())
}

fn visit_mut_path<F>(
    tree: &mut Document,
    plan: &[(Tag, Capacities)],
    depth: usize,
    f: &mut F,
) -> Result<(), TreeError>
where
    F: for<'a> FnMut(FieldMut<'a>) -> Result<(), TreeError>,
{
    let (tag, _cap) = plan[depth];
    if depth + 1 == plan.len() {
        tree.repeated_visit_mut(tag, f)?;
        return Ok(());
    }

    let next_cap = plan[depth + 1].1;
    let mut cursor = tree.bucket(tag).and_then(|bucket| bucket.head);
    while let Some(ix) = cursor {
        // SAFETY: cursor comes from the linked-list we maintain.
        cursor = unsafe { tree.field_unchecked(ix) }.next;
        let mut field = tree.field_mut(ix).expect("linked-list ix must be valid");
        let bytes = nested_payload_ref(field.as_ref())?;
        let mut nested = Document::from_bytes_borrowed(bytes, Some(next_cap))?;
        visit_mut_path(&mut nested, plan, depth + 1, f)?;
        set_nested_payload_mut(&mut field, nested.to_buf()?)?;
    }
    Ok(())
}

impl Document {
    pub fn edit_planned_mut<F>(
        data: &[u8],
        plan: &[(Tag, Capacities)],
        mut f: F,
    ) -> Result<Buf, TreeError>
    where
        F: for<'a> FnMut(FieldMut<'a>) -> Result<(), TreeError>,
    {
        ensure_decode_len(data.len())?;
        if plan.is_empty() {
            let mut out = Buf::new();
            out.extend_from_slice(data)?;
            return Ok(out);
        }
        for &(_tag, cap) in plan {
            validate_step_capacity(cap)?;
        }

        let mut tree = Self::from_bytes_borrowed(data, Some(plan[0].1))?;
        visit_mut_path(&mut tree, plan, 0, &mut f)?;
        tree.to_buf()
    }

    pub fn visit_planned_refs<F>(
        data: &[u8],
        plan: &[(Tag, Capacities)],
        mut f: F,
    ) -> Result<(), TreeError>
    where
        F: for<'a> FnMut(FieldRef<'a>),
    {
        ensure_decode_len(data.len())?;
        if plan.is_empty() {
            return Ok(());
        }
        for &(_tag, cap) in plan {
            validate_step_capacity(cap)?;
        }

        let tree = Self::from_bytes_borrowed(data, Some(plan[0].1))?;
        visit_refs_path(&tree, plan, 0, &mut f)
    }
}
