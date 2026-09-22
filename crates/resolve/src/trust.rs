use std::collections::HashMap;

use weft_core::PublicKey;

pub const MAX_DISTANCE: u8 = 3;
pub const MAX_LISTS: usize = 1024;

#[derive(Debug, Clone)]
pub struct Trust {
    root: PublicKey,
    hops: HashMap<PublicKey, (u8, PublicKey)>,
    lists: usize,
}

impl Trust {
    pub(crate) fn new(root: PublicKey) -> Self {
        Self { root, hops: HashMap::from([(root, (0, root))]), lists: 0 }
    }

    pub(crate) fn reach(&mut self, key: PublicKey, distance: u8, via: PublicKey) -> bool {
        if self.hops.contains_key(&key) {
            return false;
        }
        self.hops.insert(key, (distance, via));
        true
    }

    pub(crate) fn read(&mut self) -> bool {
        if self.lists >= MAX_LISTS {
            return false;
        }
        self.lists += 1;
        true
    }

    pub fn root(&self) -> PublicKey {
        self.root
    }

    pub fn lists(&self) -> usize {
        self.lists
    }

    pub fn distance(&self, key: &PublicKey) -> Option<u8> {
        self.hops.get(key).map(|(d, _)| *d)
    }

    pub fn path(&self, key: &PublicKey) -> Vec<PublicKey> {
        let mut path = Vec::new();
        let mut at = *key;
        while let Some((_, via)) = self.hops.get(&at) {
            path.push(at);
            if at == self.root {
                path.reverse();
                return path;
            }
            at = *via;
        }
        Vec::new()
    }

    pub fn counts(&self) -> [usize; MAX_DISTANCE as usize + 1] {
        let mut counts = [0; MAX_DISTANCE as usize + 1];
        for (d, _) in self.hops.values() {
            counts[usize::from(*d)] += 1;
        }
        counts
    }
}
