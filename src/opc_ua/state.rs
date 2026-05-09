//! Pending-read correlation state for OPC UA.
//!
//! When a ReadRequest arrives we capture its NodeIds keyed by
//! `(secure_channel_id, request_id)`. When the matching ReadResponse arrives
//! we pull the NodeIds back out and pair them positionally with the response's
//! `DataValue[]` results.

use std::collections::HashMap;

use crate::opc_ua::node_id::DecodedNodeId;

/// Default TTL for a pending read. OPC UA reads are quick (sub-second to
/// seconds); 60 seconds is generous and bounds memory if responses are lost.
pub const DEFAULT_PENDING_TTL_US: u64 = 60_000_000;

/// Default cap on outstanding reads. Excess entries are LRU-evicted.
pub const DEFAULT_MAX_PENDING: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct PendingConfig {
    pub ttl_us: u64,
    pub max_pending: usize,
}

impl Default for PendingConfig {
    fn default() -> Self {
        Self {
            ttl_us: DEFAULT_PENDING_TTL_US,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingKey {
    pub secure_channel_id: u32,
    pub request_id: u32,
}

#[derive(Debug, Clone)]
struct PendingEntry {
    nodes: Vec<DecodedNodeId>,
    inserted_us: u64,
}

#[derive(Debug)]
pub struct PendingReads {
    entries: HashMap<PendingKey, PendingEntry>,
    config: PendingConfig,
}

impl Default for PendingReads {
    fn default() -> Self {
        Self::with_config(PendingConfig::default())
    }
}

impl PendingReads {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: PendingConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    pub fn insert(&mut self, key: PendingKey, nodes: Vec<DecodedNodeId>, now_us: u64) {
        if self.entries.len() >= self.config.max_pending && !self.entries.contains_key(&key) {
            self.evict_lru_one();
        }
        self.entries.insert(
            key,
            PendingEntry {
                nodes,
                inserted_us: now_us,
            },
        );
    }

    pub fn take(&mut self, key: &PendingKey) -> Option<Vec<DecodedNodeId>> {
        self.entries.remove(key).map(|e| e.nodes)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop entries whose TTL has expired. Returns count removed.
    pub fn evict_expired(&mut self, now_us: u64) -> usize {
        let ttl = self.config.ttl_us;
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now_us.saturating_sub(e.inserted_us) < ttl);
        before - self.entries.len()
    }

    fn evict_lru_one(&mut self) {
        let Some(victim) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.inserted_us)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        self.entries.remove(&victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::OpcUaNodeId;

    fn key(req_id: u32) -> PendingKey {
        PendingKey {
            secure_channel_id: 1,
            request_id: req_id,
        }
    }

    fn node(n: u32) -> DecodedNodeId {
        DecodedNodeId {
            namespace_index: 0,
            identifier: OpcUaNodeId::Numeric(n),
        }
    }

    #[test]
    fn insert_and_take_round_trip() {
        let mut p = PendingReads::new();
        p.insert(key(1), vec![node(10), node(20)], 100);
        let taken = p.take(&key(1)).expect("take");
        assert_eq!(taken.len(), 2);
        assert!(p.take(&key(1)).is_none(), "second take should miss");
    }

    #[test]
    fn ttl_evicts_expired() {
        let cfg = PendingConfig {
            ttl_us: 1_000_000,
            max_pending: 1024,
        };
        let mut p = PendingReads::with_config(cfg);
        p.insert(key(1), vec![node(1)], 100);
        p.insert(key(2), vec![node(2)], 1_500_000);
        assert_eq!(p.evict_expired(2_000_000), 1);
        assert!(p.take(&key(1)).is_none());
        assert!(p.take(&key(2)).is_some());
    }

    #[test]
    fn lru_evicts_oldest_under_pressure() {
        let cfg = PendingConfig {
            ttl_us: u64::MAX,
            max_pending: 2,
        };
        let mut p = PendingReads::with_config(cfg);
        p.insert(key(1), vec![node(1)], 100);
        p.insert(key(2), vec![node(2)], 200);
        p.insert(key(3), vec![node(3)], 300); // evicts key(1)
        assert!(p.take(&key(1)).is_none());
        assert!(p.take(&key(2)).is_some());
        assert!(p.take(&key(3)).is_some());
    }
}
