//! Bronze deduplication for multi-collector overlap.
//!
//! Uses SHA-256 hashing of (timestamp_bucket, src_ip, dst_ip, src_port, dst_port, protocol)
//! with a sliding time window to detect and suppress duplicates.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

/// Sliding-window deduplication engine.
pub struct DedupEngine {
    /// Map of hash → first-seen timestamp (nanoseconds).
    seen: HashMap<[u8; 32], u64>,
    /// Time window for dedup (in nanoseconds).
    window_ns: u64,
    /// Bucket size for timestamp quantisation (nanoseconds).
    bucket_ns: u64,
}

impl DedupEngine {
    /// Create a new dedup engine.
    ///
    /// * `window` — how long to remember a record before allowing a duplicate.
    /// * `bucket` — timestamp quantisation granularity (records in the same
    ///   bucket are considered simultaneous).
    pub fn new(window: Duration, bucket: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            window_ns: window.as_nanos() as u64,
            bucket_ns: bucket.as_nanos() as u64,
        }
    }

    /// Returns `true` if this record is a duplicate (i.e. should be dropped).
    pub fn is_duplicate(
        &mut self,
        timestamp_ns: u64,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
    ) -> bool {
        // Evict expired entries first.
        self.evict(timestamp_ns);

        let hash = self.compute_hash(timestamp_ns, src_ip, dst_ip, src_port, dst_port, protocol);

        if let std::collections::hash_map::Entry::Vacant(e) = self.seen.entry(hash) {
            e.insert(timestamp_ns);
            false
        } else {
            true
        }
    }

    /// Evict entries older than `now - window`.
    fn evict(&mut self, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(self.window_ns);
        self.seen.retain(|_, ts| *ts >= cutoff);
    }

    fn compute_hash(
        &self,
        timestamp_ns: u64,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
    ) -> [u8; 32] {
        let bucket = if self.bucket_ns > 0 {
            timestamp_ns / self.bucket_ns
        } else {
            timestamp_ns
        };

        let mut hasher = Sha256::new();
        hasher.update(bucket.to_be_bytes());
        hasher.update(src_ip.as_bytes());
        hasher.update(dst_ip.as_bytes());
        hasher.update(src_port.to_be_bytes());
        hasher.update(dst_port.to_be_bytes());
        hasher.update(protocol.as_bytes());

        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_detection_within_window() {
        let mut dedup = DedupEngine::new(Duration::from_secs(5), Duration::from_secs(1));

        // First occurrence — not a duplicate.
        assert!(!dedup.is_duplicate(1_000_000_000, "10.0.0.1", "10.0.0.2", 12345, 502, "modbus",));

        // Same record within the same bucket — duplicate.
        assert!(dedup.is_duplicate(1_000_000_500, "10.0.0.1", "10.0.0.2", 12345, 502, "modbus",));
    }

    #[test]
    fn test_different_records_not_duplicate() {
        let mut dedup = DedupEngine::new(Duration::from_secs(5), Duration::from_secs(1));

        assert!(!dedup.is_duplicate(1_000_000_000, "10.0.0.1", "10.0.0.2", 12345, 502, "modbus",));

        // Different source port — not a duplicate.
        assert!(!dedup.is_duplicate(1_000_000_000, "10.0.0.1", "10.0.0.2", 12346, 502, "modbus",));
    }

    #[test]
    fn test_eviction_after_window() {
        let mut dedup = DedupEngine::new(Duration::from_secs(2), Duration::from_secs(1));

        assert!(!dedup.is_duplicate(1_000_000_000, "10.0.0.1", "10.0.0.2", 12345, 502, "modbus",));

        // 3 seconds later — past the 2-second window. The original entry
        // is evicted, and the bucket is different, so it is NOT a dup.
        assert!(!dedup.is_duplicate(4_000_000_000, "10.0.0.1", "10.0.0.2", 12345, 502, "modbus",));
    }
}
