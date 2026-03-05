use crate::error::UiResult;
use crate::messages::MessageId;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EnvelopeFrame {
    pub flags: u8,
    pub header_offset: usize,
    pub payload_offset: usize,
    pub payload_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameDecompressionMeta {
    pub format: &'static str,
    pub output_len: usize,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EnvelopeFrameMeta {
    pub protobuf_error: Option<String>,
    pub decompression: Option<FrameDecompressionMeta>,
    pub decompression_error: Option<String>,
}

pub(crate) struct EnvelopeView {
    pub source_id: MessageId,
    pub bytes: Rc<Vec<u8>>,
    pub frames: Vec<EnvelopeFrame>,
    pub meta: Vec<EnvelopeFrameMeta>,
}

impl EnvelopeFrame {
    #[inline]
    pub(crate) fn is_compressed(self) -> bool {
        (self.flags & 0x01) != 0
    }

    #[inline]
    pub(crate) fn is_json(self) -> bool {
        (self.flags & 0x02) != 0
    }
}

pub(crate) fn parse_envelope_frames(bytes: &[u8]) -> UiResult<Vec<EnvelopeFrame>> {
    if bytes.is_empty() {
        return Err("Envelope is empty.".into());
    }

    let mut frames = Vec::new();
    let mut offset: usize = 0;

    while offset < bytes.len() {
        let remaining = bytes.len().saturating_sub(offset);
        if remaining < 5 {
            return Err(format!(
                "Envelope ended early at offset {offset}: expected 5-byte frame header, found {remaining} byte(s)."
            )
            .into());
        }

        let flags = bytes[offset];
        let len = u32::from_be_bytes([
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
        ]) as usize;

        let payload_offset = offset + 5;
        let payload_end =
            payload_offset.checked_add(len).ok_or("Envelope frame length overflowed.")?;
        if payload_end > bytes.len() {
            return Err(format!(
                "Envelope frame at offset {offset} declares {len} byte(s), but only {} byte(s) remain.",
                bytes.len().saturating_sub(payload_offset)
            )
            .into());
        }

        frames.push(EnvelopeFrame {
            flags,
            header_offset: offset,
            payload_offset,
            payload_len: len,
        });
        offset = payload_end;
    }

    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::{parse_envelope_frames, EnvelopeFrame};

    fn build_frame(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(flags);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn payload_bytes(frame: EnvelopeFrame, bytes: &[u8]) -> &[u8] {
        let start = frame.payload_offset;
        let end = start.checked_add(frame.payload_len).expect("payload end must not overflow");
        &bytes[start..end]
    }

    #[test]
    fn parses_two_frames() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_frame(0x00, &[0x08, 0x96, 0x01]));
        bytes.extend_from_slice(&build_frame(0x01, &[0x12, 0x03, 0x61, 0x62, 0x63]));

        let frames = parse_envelope_frames(&bytes).expect("frames must parse");
        assert_eq!(
            frames,
            vec![
                EnvelopeFrame { flags: 0x00, header_offset: 0, payload_offset: 5, payload_len: 3 },
                EnvelopeFrame { flags: 0x01, header_offset: 8, payload_offset: 13, payload_len: 5 },
            ]
        );
        assert_eq!(payload_bytes(frames[0], &bytes), &[0x08, 0x96, 0x01]);
        assert_eq!(payload_bytes(frames[1], &bytes), &[0x12, 0x03, 0x61, 0x62, 0x63]);
        assert!(!frames[0].is_compressed());
        assert!(frames[1].is_compressed());
    }

    #[test]
    fn rejects_truncated_header() {
        let bytes = [0x00, 0x00, 0x00, 0x00];
        let err = parse_envelope_frames(&bytes).unwrap_err();
        assert!(err.contains("expected 5-byte frame header"));
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut bytes = Vec::new();
        bytes.push(0x00);
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let err = parse_envelope_frames(&bytes).unwrap_err();
        assert!(err.contains("declares 3 byte(s)"));
    }
}
