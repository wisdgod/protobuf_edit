use std::rc::Rc;

#[derive(Clone)]
pub(crate) struct ByteView {
    bytes: Rc<Vec<u8>>,
    start: usize,
    end: usize,
}

impl ByteView {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        let bytes = Rc::new(bytes);
        let end = bytes.len();
        Self { bytes, start: 0, end }
    }

    pub(crate) fn from_rc(bytes: Rc<Vec<u8>>) -> Self {
        let end = bytes.len();
        Self { bytes, start: 0, end }
    }

    pub(crate) fn slice(bytes: Rc<Vec<u8>>, start: usize, end: usize) -> Option<Self> {
        if start > end || end > bytes.len() {
            return None;
        }
        Some(Self { bytes, start, end })
    }

    #[inline]
    pub(crate) fn bytes_rc(&self) -> Rc<Vec<u8>> {
        self.bytes.clone()
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
}
