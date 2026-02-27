use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;

pub(crate) type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
