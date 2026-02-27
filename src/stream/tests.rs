use super::{ChunkStream, WireHandler};
use crate::wire::WireType;
use crate::{wire, Buf, Document, Tag, TreeError};

fn fnn(n: u32) -> wire::FieldNumber {
    wire::FieldNumber::new(n).unwrap()
}

const fn ctag(n: u32, wire_type: WireType) -> Tag {
    let field = unsafe { wire::FieldNumber::new_unchecked(n) };
    Tag::from_parts(field, wire_type)
}

fn buf_from_slice(data: &[u8]) -> Buf {
    let mut buf = Buf::new();
    buf.extend_from_slice(data).expect("tiny test fixture should fit");
    buf
}

#[derive(Default)]
struct Collect {
    varints: alloc::vec::Vec<(alloc::vec::Vec<Tag>, u64)>,
    i32s: alloc::vec::Vec<(alloc::vec::Vec<Tag>, [u8; 4])>,
    i64s: alloc::vec::Vec<(alloc::vec::Vec<Tag>, [u8; 8])>,
    lens: alloc::vec::Vec<(alloc::vec::Vec<Tag>, alloc::vec::Vec<u8>, u32, bool)>,
    #[cfg(feature = "group")]
    groups: alloc::vec::Vec<(alloc::vec::Vec<Tag>, alloc::vec::Vec<u8>, bool)>,
}

impl WireHandler for Collect {
    fn on_varint(&mut self, path: &[Tag], value: u64) -> Result<(), TreeError> {
        self.varints.push((path.to_vec(), value));
        Ok(())
    }

    fn on_i32(&mut self, path: &[Tag], value: [u8; 4]) -> Result<(), TreeError> {
        self.i32s.push((path.to_vec(), value));
        Ok(())
    }

    fn on_i64(&mut self, path: &[Tag], value: [u8; 8]) -> Result<(), TreeError> {
        self.i64s.push((path.to_vec(), value));
        Ok(())
    }

    fn on_length_delimited(
        &mut self,
        path: &[Tag],
        payload: &[u8],
        length: u32,
        is_last: bool,
    ) -> Result<(), TreeError> {
        self.lens.push((path.to_vec(), payload.to_vec(), length, is_last));
        Ok(())
    }

    #[cfg(feature = "group")]
    fn on_group(&mut self, path: &[Tag], payload: &[u8], is_last: bool) -> Result<(), TreeError> {
        self.groups.push((path.to_vec(), payload.to_vec(), is_last));
        Ok(())
    }
}

fn make_leaf_message(values: &[&[u8]]) -> Buf {
    let mut tree = Document::new();
    for v in values {
        let _ = tree.push_length_delimited(fnn(1), buf_from_slice(v)).unwrap();
    }
    tree.to_buf().unwrap()
}

fn make_wrapper_message(field_number: u32, payloads: &[Buf]) -> Buf {
    let mut tree = Document::new();
    for payload in payloads {
        let _ = tree.push_length_delimited(fnn(field_number), payload.clone()).unwrap();
    }
    tree.to_buf().unwrap()
}

fn make_deep_nested_message(depth: usize) -> Buf {
    let mut payload = make_leaf_message(&[b"x"]);
    let mut i = 0usize;
    while i < depth {
        payload = make_wrapper_message(1, &[payload]);
        i += 1;
    }
    payload
}

#[test]
fn chunk_stream_parses_across_byte_chunks() {
    let mut root = Document::new();
    let _ = root.push_varint(fnn(1), 300).unwrap();
    let _ = root.push_fixed32(fnn(2), 0x1122_3344).unwrap();
    let _ = root.push_length_delimited(fnn(3), buf_from_slice(b"xyz")).unwrap();
    let src = root.to_buf().unwrap();

    const P1: [Tag; 1] = [ctag(1, WireType::Varint)];
    const P2: [Tag; 1] = [ctag(2, WireType::I32)];
    const P3: [Tag; 1] = [ctag(3, WireType::Len)];
    let trie = crate::const_trie!(4, 6, [&P1, &P2, &P3]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    for b in src.as_slice() {
        parser.feed(core::slice::from_ref(b), &mut collect).unwrap();
    }
    parser.finish().unwrap();

    assert_eq!(collect.varints.len(), 1);
    assert_eq!(collect.varints[0].0.as_slice(), P1);
    assert_eq!(collect.varints[0].1, 300);

    assert_eq!(collect.i32s.len(), 1);
    assert_eq!(collect.i32s[0].0.as_slice(), P2);
    assert_eq!(u32::from_le_bytes(collect.i32s[0].1), 0x1122_3344);

    assert_eq!(collect.lens.len(), 1);
    let (path, payload, len, is_last) = collect.lens.last().unwrap();
    assert_eq!(path.as_slice(), P3);
    assert_eq!(payload.as_slice(), b"xyz");
    assert_eq!(*len, 3);
    assert!(*is_last);
}

#[test]
fn chunk_stream_reports_offset_and_total_len() {
    let mut root = Document::new();
    let _ = root.push_varint(fnn(1), 7).unwrap();
    let _ = root.push_length_delimited(fnn(2), buf_from_slice(b"ab")).unwrap();
    let src = root.to_buf().unwrap();

    const P1: [Tag; 1] = [ctag(1, WireType::Varint)];
    const P2: [Tag; 1] = [ctag(2, WireType::Len)];
    let trie = crate::const_trie!(3, 4, [&P1, &P2]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    parser.feed(src.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(parser.offset(), src.len() as u64);
    assert_eq!(collect.varints.len(), 1);
    assert_eq!(collect.varints[0].0.as_slice(), P1);
    assert_eq!(collect.varints[0].1, 7);

    assert_eq!(collect.lens.len(), 1);
    assert_eq!(collect.lens[0].0.as_slice(), P2);
    assert_eq!(collect.lens[0].1.as_slice(), b"ab");
    assert_eq!(collect.lens[0].2, 2);
    assert!(collect.lens[0].3);
}

#[test]
fn chunk_stream_len_callback_may_repeat_and_last_is_complete() {
    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(9), buf_from_slice(b"abcdef")).unwrap();
    let src = root.to_buf().unwrap();

    const P9: [Tag; 1] = [ctag(9, WireType::Len)];
    let trie = crate::const_trie!(2, 2, [&P9]);

    let mut parser = ChunkStream::with_trie(trie);
    parser.set_emit_partial_matches(true);

    let mut collect = Collect::default();
    let bytes = src.as_slice();

    parser.feed(&bytes[..3], &mut collect).unwrap();
    assert_eq!(collect.lens.len(), 1);
    assert_eq!(collect.lens[0].0.as_slice(), P9);
    assert_eq!(collect.lens[0].1.as_slice(), b"a");
    assert!(!collect.lens[0].3);

    parser.feed(&bytes[3..5], &mut collect).unwrap();
    assert_eq!(collect.lens.len(), 2);
    assert_eq!(collect.lens[1].0.as_slice(), P9);
    assert_eq!(collect.lens[1].1.as_slice(), b"abc");
    assert!(!collect.lens[1].3);

    parser.feed(&bytes[5..], &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.lens.len(), 3);
    let (path, payload, len, is_last) = collect.lens.last().unwrap();
    assert_eq!(path.as_slice(), P9);
    assert_eq!(payload.as_slice(), b"abcdef");
    assert_eq!(*len, 6);
    assert!(*is_last);
}

#[test]
fn chunk_stream_finish_errors_on_partial_field() {
    let tag = wire::Tag::from_parts(fnn(1), WireType::Varint).get();
    let mut data = Buf::new();
    let _ = crate::varint::encode32(&mut data, tag).unwrap();
    data.push(0x80).unwrap();

    const P1: [Tag; 1] = [ctag(1, WireType::Varint)];
    let trie = crate::const_trie!(2, 2, [&P1]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    parser.feed(data.as_slice(), &mut collect).unwrap();
    assert!(matches!(parser.finish(), Err(TreeError::DecodeError)));
}

#[test]
fn chunk_stream_reset_start_new_payload() {
    let mut child = Document::new();
    let _ = child.push_varint(fnn(2), 42).unwrap();
    let payload = child.to_buf().unwrap();

    const P2: [Tag; 1] = [ctag(2, WireType::Varint)];
    let trie = crate::const_trie!(2, 2, [&P2]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();

    parser.feed(payload.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    parser.reset();
    parser.feed(payload.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.varints.len(), 2);
    assert_eq!(collect.varints[0].0.as_slice(), P2);
    assert_eq!(collect.varints[1].0.as_slice(), P2);
    assert_eq!(collect.varints[0].1, 42);
    assert_eq!(collect.varints[1].1, 42);
}

#[test]
fn chunk_stream_accepts_dyn_handler() {
    let mut root = Document::new();
    let _ = root.push_varint(fnn(1), 123).unwrap();
    let src = root.to_buf().unwrap();

    const P1: [Tag; 1] = [ctag(1, WireType::Varint)];
    let trie = crate::const_trie!(2, 2, [&P1]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    let handler: &mut dyn WireHandler = &mut collect;
    parser.feed(src.as_slice(), handler).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.varints.len(), 1);
    assert_eq!(collect.varints[0].0.as_slice(), P1);
    assert_eq!(collect.varints[0].1, 123);
}

#[test]
fn chunk_stream_zero_length_len_field_yields_empty_payload() {
    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(4), Buf::new()).unwrap();
    let src = root.to_buf().unwrap();

    const P4: [Tag; 1] = [ctag(4, WireType::Len)];
    let trie = crate::const_trie!(2, 2, [&P4]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    parser.feed(src.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.lens.len(), 1);
    assert_eq!(collect.lens[0].0.as_slice(), P4);
    assert_eq!(collect.lens[0].1.as_slice(), b"");
    assert_eq!(collect.lens[0].2, 0);
    assert!(collect.lens[0].3);
}

#[test]
fn chunk_stream_matches_nested_len_path() {
    let leaf = make_leaf_message(&[b"target"]);
    let level_79 = make_wrapper_message(79, &[leaf]);
    let level_28 = make_wrapper_message(28, &[level_79]);
    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(3), level_28).unwrap();
    let src = root.to_buf().unwrap();

    const P: [Tag; 4] = [
        ctag(3, WireType::Len),
        ctag(28, WireType::Len),
        ctag(79, WireType::Len),
        ctag(1, WireType::Len),
    ];
    let trie = crate::const_trie!(5, 5, [&P]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    for chunk in src.as_slice().chunks(2) {
        parser.feed(chunk, &mut collect).unwrap();
    }
    parser.finish().unwrap();

    assert_eq!(collect.lens.len(), 1);
    assert_eq!(collect.lens[0].0.as_slice(), P);
    assert_eq!(collect.lens[0].1.as_slice(), b"target");
    assert_eq!(collect.lens[0].2, 6);
    assert!(collect.lens[0].3);
}

#[test]
fn chunk_stream_matches_len_prefix_and_nested_child() {
    let mut child = Document::new();
    let _ = child.push_varint(fnn(2), 9).unwrap();
    let child_payload = child.to_buf().unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(1), child_payload.clone()).unwrap();
    let src = root.to_buf().unwrap();

    const P_PARENT: [Tag; 1] = [ctag(1, WireType::Len)];
    const P_CHILD: [Tag; 2] = [ctag(1, WireType::Len), ctag(2, WireType::Varint)];
    let trie = crate::const_trie!(3, 4, [&P_PARENT, &P_CHILD]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    parser.feed(src.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.lens.len(), 1);
    assert_eq!(collect.lens[0].0.as_slice(), P_PARENT);
    assert_eq!(collect.lens[0].1.as_slice(), child_payload.as_slice());
    assert_eq!(collect.lens[0].2, child_payload.len());
    assert!(collect.lens[0].3);

    assert_eq!(collect.varints.len(), 1);
    assert_eq!(collect.varints[0].0.as_slice(), P_CHILD);
    assert_eq!(collect.varints[0].1, 9);
}

#[test]
fn chunk_stream_depth_limit_100() {
    const D100: [Tag; 100] = [ctag(1, WireType::Len); 100];
    const D102: [Tag; 102] = [ctag(1, WireType::Len); 102];
    let trie_ok = crate::const_trie!(101, 101, [&D100]);
    let trie_deep = crate::const_trie!(103, 103, [&D102]);

    let mut ok_root = Document::new();
    let _ = ok_root.push_length_delimited(fnn(1), make_deep_nested_message(98)).unwrap();
    let ok_src = ok_root.to_buf().unwrap();

    let mut parser = ChunkStream::with_trie(trie_ok);
    let mut collect = Collect::default();
    parser.feed(ok_src.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();
    assert!(collect.lens.iter().any(|(path, _, _, _)| path.len() == 100));

    let mut bad_root = Document::new();
    let _ = bad_root.push_length_delimited(fnn(1), make_deep_nested_message(100)).unwrap();
    let bad_src = bad_root.to_buf().unwrap();

    let mut parser = ChunkStream::with_trie(trie_deep);
    let mut collect = Collect::default();
    let err = parser.feed(bad_src.as_slice(), &mut collect).unwrap_err();
    assert!(matches!(err, TreeError::DecodeError));
}

#[test]
fn chunk_stream_matches_multiple_paths() {
    let leaf = make_leaf_message(&[b"n"]);
    let level_79 = make_wrapper_message(79, &[leaf]);
    let level_28 = make_wrapper_message(28, &[level_79]);

    let mut root = Document::new();
    let _ = root.push_varint(fnn(10), 99).unwrap();
    let _ = root.push_length_delimited(fnn(3), level_28).unwrap();
    let src = root.to_buf().unwrap();

    const P_VARINT: [Tag; 1] = [ctag(10, WireType::Varint)];
    const P_NESTED: [Tag; 4] = [
        ctag(3, WireType::Len),
        ctag(28, WireType::Len),
        ctag(79, WireType::Len),
        ctag(1, WireType::Len),
    ];
    let trie = crate::const_trie!(6, 7, [&P_VARINT, &P_NESTED]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    parser.feed(src.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.varints.len(), 1);
    assert_eq!(collect.varints[0].0.as_slice(), P_VARINT);
    assert_eq!(collect.varints[0].1, 99);

    assert_eq!(collect.lens.len(), 1);
    assert_eq!(collect.lens[0].0.as_slice(), P_NESTED);
    assert_eq!(collect.lens[0].1.as_slice(), b"n");
}

#[test]
fn chunk_stream_skips_untracked_len_payloads() {
    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(9), buf_from_slice(&[0x80])).unwrap();
    let _ = root.push_varint(fnn(1), 7).unwrap();
    let src = root.to_buf().unwrap();

    const P1: [Tag; 1] = [ctag(1, WireType::Varint)];
    let trie = crate::const_trie!(2, 2, [&P1]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    parser.feed(src.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.varints.len(), 1);
    assert_eq!(collect.varints[0].0.as_slice(), P1);
    assert_eq!(collect.varints[0].1, 7);
}

#[cfg(feature = "group")]
#[test]
fn chunk_stream_group_callback_may_repeat_and_last_is_complete() {
    let mut msg = Buf::new();
    wire::encode_tag(&mut msg, fnn(1), WireType::SGroup).unwrap();
    wire::encode_tag(&mut msg, fnn(2), WireType::Varint).unwrap();
    crate::varint::encode64(&mut msg, 7).unwrap();
    wire::encode_tag(&mut msg, fnn(1), WireType::EGroup).unwrap();

    let mut expected_payload = Buf::new();
    wire::encode_tag(&mut expected_payload, fnn(2), WireType::Varint).unwrap();
    crate::varint::encode64(&mut expected_payload, 7).unwrap();

    const P: [Tag; 1] = [ctag(1, WireType::SGroup)];
    let trie = crate::const_trie!(2, 2, [&P]);

    let bytes = msg.as_slice();
    let mut parser = ChunkStream::with_trie(trie);
    parser.set_emit_partial_matches(true);
    let mut collect = Collect::default();

    parser.feed(&bytes[..3], &mut collect).unwrap();
    assert_eq!(collect.groups.len(), 1);
    assert_eq!(collect.groups[0].0.as_slice(), P);
    assert_eq!(collect.groups[0].1.as_slice(), expected_payload.as_slice());
    assert!(!collect.groups[0].2);

    parser.feed(&bytes[3..], &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.groups.len(), 2);
    assert_eq!(collect.groups[1].0.as_slice(), P);
    assert_eq!(collect.groups[1].1.as_slice(), expected_payload.as_slice());
    assert!(collect.groups[1].2);
}

#[cfg(feature = "group")]
#[test]
fn chunk_stream_matches_nested_path_inside_group() {
    let mut msg = Buf::new();
    wire::encode_tag(&mut msg, fnn(1), WireType::SGroup).unwrap();
    wire::encode_tag(&mut msg, fnn(2), WireType::Varint).unwrap();
    crate::varint::encode64(&mut msg, 7).unwrap();
    wire::encode_tag(&mut msg, fnn(1), WireType::EGroup).unwrap();

    const P: [Tag; 2] = [ctag(1, WireType::SGroup), ctag(2, WireType::Varint)];
    let trie = crate::const_trie!(3, 3, [&P]);

    let mut parser = ChunkStream::with_trie(trie);
    let mut collect = Collect::default();
    parser.feed(msg.as_slice(), &mut collect).unwrap();
    parser.finish().unwrap();

    assert_eq!(collect.varints.len(), 1);
    assert_eq!(collect.varints[0].0.as_slice(), P);
    assert_eq!(collect.varints[0].1, 7);
}

#[test]
fn chunk_stream_is_compact() {
    #[cfg(not(feature = "group"))]
    assert!(core::mem::size_of::<ChunkStream>() <= 208);
    #[cfg(feature = "group")]
    assert!(core::mem::size_of::<ChunkStream>() <= 232);
}
