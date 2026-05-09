//! Sparkplug session state — alias→metric_name resolution per
//! `(broker_endpoint, group_id, edge_node_id, device_id?)`.
//!
//! Sparkplug B uses BIRTH messages to bind compact uint64 aliases to full
//! metric names; subsequent DATA messages typically carry only the alias. To
//! resolve a DATA metric back to its name we need state that crosses MQTT
//! frames. Session lifetime is decoupled from any pcap segment boundary —
//! eviction is driven by NDEATH, bdSeq supersession, TTL since last touch,
//! and a max-session cap with LRU eviction under memory pressure.

use std::collections::HashMap;
use std::net::SocketAddr;

/// Default time-to-live since last touch before a session is evicted.
/// Industrial Sparkplug deployments routinely have hours-long quiet periods,
/// so the default is generous.
pub const DEFAULT_SESSION_TTL_US: u64 = 24 * 60 * 60 * 1_000_000; // 24 hours

/// Default max session count before LRU eviction kicks in.
pub const DEFAULT_MAX_SESSIONS: usize = 4096;

/// How often (in publish events) to run the TTL sweep. Memory-pressure
/// enforcement runs unconditionally on every insert.
pub const TTL_SWEEP_EVERY_N_PUBLISHES: u64 = 1024;

/// Eviction policy for [`SessionStore`].
#[derive(Debug, Clone, Copy)]
pub struct EvictionConfig {
    /// Time since last touch before a session is eligible for eviction.
    pub ttl_us: u64,
    /// Max number of sessions before LRU eviction kicks in.
    pub max_sessions: usize,
}

impl Default for EvictionConfig {
    fn default() -> Self {
        Self {
            ttl_us: DEFAULT_SESSION_TTL_US,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

/// Composite key identifying one Sparkplug session — i.e. one
/// (broker, group, edge[/device]) tuple's alias namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub broker_endpoint: SocketAddr,
    pub group_id: String,
    pub edge_node_id: String,
    pub device_id: Option<String>,
}

/// Per-session alias table.
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    aliases: HashMap<u64, String>,
    /// Latest observed bdSeq from a BIRTH. None if no BIRTH has been seen.
    /// A BIRTH with a strictly-newer bdSeq supersedes prior state.
    bd_seq: Option<u64>,
    /// True once we've emitted a "gap" anomaly for this session — used to
    /// fire the unresolvable-alias signal at most once per gap epoch.
    /// Reset to false on any new BIRTH (which closes the gap).
    gap_anomaly_emitted: bool,
    /// Microseconds-since-epoch of the most recent touch on this session.
    /// Drives TTL and LRU eviction.
    last_touched_us: u64,
}

impl SessionState {
    pub fn resolve(&self, alias: u64) -> Option<&str> {
        self.aliases.get(&alias).map(String::as_str)
    }

    pub fn bind(&mut self, alias: u64, name: String) {
        self.aliases.insert(alias, name);
    }

    /// Mark a BIRTH as observed. Returns true if this BIRTH supersedes any
    /// prior state (caller should then call `clear_aliases` and re-bind).
    pub fn record_birth(&mut self, bd_seq: Option<u64>) -> bool {
        let supersedes = match (self.bd_seq, bd_seq) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(prev), Some(new)) => new >= prev,
        };
        if supersedes {
            self.bd_seq = bd_seq;
            self.gap_anomaly_emitted = false;
        }
        supersedes
    }

    pub fn clear_aliases(&mut self) {
        self.aliases.clear();
    }

    pub fn record_death(&mut self) {
        self.aliases.clear();
    }

    pub fn note_gap_anomaly_if_first(&mut self) -> bool {
        if self.gap_anomaly_emitted {
            false
        } else {
            self.gap_anomaly_emitted = true;
            true
        }
    }

    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    pub fn last_touched_us(&self) -> u64 {
        self.last_touched_us
    }

    /// Update the touch timestamp. Caller invokes on every access.
    fn touch(&mut self, now_us: u64) {
        self.last_touched_us = now_us;
    }
}

/// Multi-session state store keyed by [`SessionKey`].
#[derive(Debug)]
pub struct SessionStore {
    sessions: HashMap<SessionKey, SessionState>,
    config: EvictionConfig,
    publishes_since_sweep: u64,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::with_config(EvictionConfig::default())
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: EvictionConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            config,
            publishes_since_sweep: 0,
        }
    }

    /// Get-or-create a session, bumping its touch timestamp and enforcing
    /// the max-session cap.
    pub fn entry_mut(&mut self, key: SessionKey, now_us: u64) -> &mut SessionState {
        let inserting = !self.sessions.contains_key(&key);
        if inserting && self.sessions.len() >= self.config.max_sessions {
            self.evict_lru_one();
        }
        let entry = self.sessions.entry(key).or_default();
        entry.touch(now_us);
        entry
    }

    pub fn get(&self, key: &SessionKey) -> Option<&SessionState> {
        self.sessions.get(key)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn config(&self) -> EvictionConfig {
        self.config
    }

    /// Increment the publish counter and return whether the caller should run
    /// a TTL sweep this turn. Sweeps are amortized across many publishes.
    pub fn should_sweep(&mut self) -> bool {
        self.publishes_since_sweep = self.publishes_since_sweep.saturating_add(1);
        if self.publishes_since_sweep >= TTL_SWEEP_EVERY_N_PUBLISHES {
            self.publishes_since_sweep = 0;
            true
        } else {
            false
        }
    }

    /// Remove sessions whose `last_touched_us + ttl_us <= now_us`. Returns the
    /// number evicted.
    pub fn evict_expired(&mut self, now_us: u64) -> usize {
        let ttl = self.config.ttl_us;
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| now_us.saturating_sub(s.last_touched_us) < ttl);
        before - self.sessions.len()
    }

    /// Evict the single least-recently-touched session.
    fn evict_lru_one(&mut self) {
        let Some(victim) = self
            .sessions
            .iter()
            .min_by_key(|(_, s)| s.last_touched_us)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        self.sessions.remove(&victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SessionKey {
        SessionKey {
            broker_endpoint: "10.0.0.1:1883".parse().unwrap(),
            group_id: "Plant1".into(),
            edge_node_id: "PLC-A".into(),
            device_id: None,
        }
    }

    #[test]
    fn first_birth_supersedes_and_resets_gap() {
        let mut s = SessionState::default();
        assert!(s.note_gap_anomaly_if_first());
        assert!(!s.note_gap_anomaly_if_first());
        assert!(s.record_birth(Some(1)));
        assert!(s.note_gap_anomaly_if_first());
    }

    #[test]
    fn newer_bdseq_supersedes() {
        let mut s = SessionState::default();
        assert!(s.record_birth(Some(5)));
        s.bind(1, "Temp".into());
        assert!(s.record_birth(Some(6)));
        s.clear_aliases();
        s.bind(1, "Temp2".into());
        assert_eq!(s.resolve(1), Some("Temp2"));
    }

    #[test]
    fn older_bdseq_does_not_supersede() {
        let mut s = SessionState::default();
        assert!(s.record_birth(Some(10)));
        assert!(!s.record_birth(Some(5)));
    }

    #[test]
    fn store_keys_per_session() {
        let mut store = SessionStore::new();
        store.entry_mut(key(), 0).bind(1, "A".into());
        let mut other = key();
        other.edge_node_id = "PLC-B".into();
        store.entry_mut(other.clone(), 0).bind(1, "B".into());
        assert_eq!(store.get(&key()).unwrap().resolve(1), Some("A"));
        assert_eq!(store.get(&other).unwrap().resolve(1), Some("B"));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn death_clears_aliases_keeps_bd_seq() {
        let mut s = SessionState::default();
        s.record_birth(Some(1));
        s.bind(1, "T".into());
        s.record_death();
        assert_eq!(s.resolve(1), None);
        assert_eq!(s.alias_count(), 0);
        assert!(s.record_birth(Some(1)));
    }

    #[test]
    fn ttl_evicts_idle_sessions() {
        let cfg = EvictionConfig {
            ttl_us: 1_000_000, // 1 second
            max_sessions: 1024,
        };
        let mut store = SessionStore::with_config(cfg);
        store.entry_mut(key(), 100).bind(1, "Old".into());
        let mut k2 = key();
        k2.edge_node_id = "Fresh".into();
        store.entry_mut(k2.clone(), 1_500_000).bind(1, "New".into());

        // Sweep at t=2_000_000: "Old" was at 100, ttl=1s, so 2s − 100us ≫ 1s → evict.
        let evicted = store.evict_expired(2_000_000);
        assert_eq!(evicted, 1);
        assert!(store.get(&key()).is_none());
        assert!(store.get(&k2).is_some());
    }

    #[test]
    fn touch_resets_ttl_clock() {
        let cfg = EvictionConfig {
            ttl_us: 1_000_000,
            max_sessions: 1024,
        };
        let mut store = SessionStore::with_config(cfg);
        store.entry_mut(key(), 100); // create at t=100us
        // Touch again at t=900_000 — bumps last_touched.
        store.entry_mut(key(), 900_000);
        // Sweep at t=1_500_000 — only 600_000us since last touch < 1s TTL.
        assert_eq!(store.evict_expired(1_500_000), 0);
        assert!(store.get(&key()).is_some());
    }

    #[test]
    fn lru_evicts_when_max_sessions_exceeded() {
        let cfg = EvictionConfig {
            ttl_us: u64::MAX,
            max_sessions: 2,
        };
        let mut store = SessionStore::with_config(cfg);
        let k1 = key();
        let mut k2 = key();
        k2.edge_node_id = "B".into();
        let mut k3 = key();
        k3.edge_node_id = "C".into();

        store.entry_mut(k1.clone(), 100);
        store.entry_mut(k2.clone(), 200);
        // Inserting k3 with cap=2 should evict the LRU (k1 at t=100).
        store.entry_mut(k3.clone(), 300);
        assert_eq!(store.len(), 2);
        assert!(store.get(&k1).is_none());
        assert!(store.get(&k2).is_some());
        assert!(store.get(&k3).is_some());
    }

    #[test]
    fn touch_protects_against_lru_eviction() {
        let cfg = EvictionConfig {
            ttl_us: u64::MAX,
            max_sessions: 2,
        };
        let mut store = SessionStore::with_config(cfg);
        let k1 = key();
        let mut k2 = key();
        k2.edge_node_id = "B".into();
        let mut k3 = key();
        k3.edge_node_id = "C".into();

        store.entry_mut(k1.clone(), 100);
        store.entry_mut(k2.clone(), 200);
        // Touch k1 to make it the most-recently used.
        store.entry_mut(k1.clone(), 250);
        // Now k2 (last touched 200) should be the LRU victim.
        store.entry_mut(k3.clone(), 300);
        assert!(store.get(&k1).is_some());
        assert!(store.get(&k2).is_none());
        assert!(store.get(&k3).is_some());
    }

    #[test]
    fn should_sweep_amortizes_across_many_publishes() {
        let mut store = SessionStore::new();
        let mut sweeps = 0;
        for _ in 0..(TTL_SWEEP_EVERY_N_PUBLISHES * 3) {
            if store.should_sweep() {
                sweeps += 1;
            }
        }
        assert_eq!(sweeps, 3);
    }
}
