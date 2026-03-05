define_valid_range_type!(
    /// Unique field identifier inside a `Patch`.
    ///
    /// `u32::MAX` is reserved as `Option<FieldId>::None`.
    pub struct FieldId(u32 as u32 in 0..=4294967294);
);

define_valid_range_type!(
    /// Unique message identifier inside a `Patch`.
    ///
    /// `u32::MAX` is reserved as `Option<MessageId>::None`.
    pub struct MessageId(u32 as u32 in 0..=4294967294);
);
