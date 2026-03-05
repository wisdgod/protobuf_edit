use rustc_hash::FxBuildHasher;
use std::collections::{HashMap, HashSet};

pub(crate) type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
pub(crate) type FxHashSet<T> = HashSet<T, FxBuildHasher>;
