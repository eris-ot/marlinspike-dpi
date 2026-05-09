//! Allen-Bradley PCCC (Programmable Controller Communication Commands) —
//! the legacy data-table protocol used by SLC-500, PLC-5, and MicroLogix
//! controllers. Carried over CIP service 0x4B (Execute PCCC) inside
//! EtherNet/IP.
//!
//! [`decoder`] holds the [`PcccDecoder`] which parses PCCC PDUs lifted out
//! of CIP service messages and produces `ProcessReading` events for typed
//! reads/writes.

pub mod decoder;

pub use decoder::PcccDecoder;
