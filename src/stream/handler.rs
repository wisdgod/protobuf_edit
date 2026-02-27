use crate::document::TreeError;
use crate::wire::Tag;

/// Callback interface for matched wire fields.
#[allow(unused_variables)]
pub trait WireHandler {
    #[inline]
    fn on_varint(&mut self, path: &[Tag], value: u64) -> Result<(), TreeError> {
        Ok(())
    }

    #[inline]
    fn on_i32(&mut self, path: &[Tag], value: [u8; 4]) -> Result<(), TreeError> {
        Ok(())
    }

    #[inline]
    fn on_i64(&mut self, path: &[Tag], value: [u8; 8]) -> Result<(), TreeError> {
        Ok(())
    }

    #[inline]
    fn on_length_delimited(
        &mut self,
        path: &[Tag],
        payload: &[u8],
        length: u32,
        is_last: bool,
    ) -> Result<(), TreeError> {
        Ok(())
    }

    #[cfg(feature = "group")]
    #[inline]
    fn on_group(&mut self, path: &[Tag], payload: &[u8], is_last: bool) -> Result<(), TreeError> {
        Ok(())
    }
}
