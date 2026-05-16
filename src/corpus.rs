//! ICS Defense corpus manifest and validation helpers.
//!
//! The roadmap docs treat the public ICS Defense PCAP archive as both a
//! planning corpus and a regression corpus. This module keeps the checked-in
//! manifest close to the engine so we can validate active decoders against
//! named fixtures without baking the external corpus into the repository.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{BronzeEventFamily, DpiEngine, SegmentMeta};

const DEFAULT_ICS_DEFENSE_MANIFEST: &str = include_str!("../corpus/ics-defense-manifest.yaml");

#[derive(Debug, thiserror::Error)]
pub enum CorpusManifestError {
    #[error("failed to read manifest {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse manifest {context}: {source}")]
    Parse {
        context: String,
        #[source]
        source: serde_yaml::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusManifestSummary {
    pub archive_directories: usize,
    pub capture_files: usize,
    #[serde(default)]
    pub non_pcap_sidecars: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorpusRoadmapPhase {
    #[serde(rename = "phase_1")]
    Phase1,
    #[serde(rename = "phase_2")]
    Phase2,
    #[serde(rename = "phase_3")]
    Phase3,
    #[serde(rename = "phase_4")]
    Phase4,
    #[serde(rename = "corpus_only")]
    CorpusOnly,
    #[serde(rename = "low_priority")]
    LowPriority,
}

impl CorpusRoadmapPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Phase1 => "phase_1",
            Self::Phase2 => "phase_2",
            Self::Phase3 => "phase_3",
            Self::Phase4 => "phase_4",
            Self::CorpusOnly => "corpus_only",
            Self::LowPriority => "low_priority",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    Active,
    Partial,
    Planned,
    CorpusOnly,
    LowPriority,
}

impl ImplementationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Partial => "partial",
            Self::Planned => "planned",
            Self::CorpusOnly => "corpus_only",
            Self::LowPriority => "low_priority",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusDirectory {
    pub archive_dir: String,
    pub file_count: usize,
    pub normalized_family: String,
    pub roadmap_phase: CorpusRoadmapPhase,
    pub disposition: String,
    pub implementation_status: ImplementationStatus,
    pub representative_fixture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureSpec {
    pub id: String,
    pub archive_dir: String,
    pub path: String,
    pub normalized_family: String,
    #[serde(default = "default_min_events")]
    pub min_events: usize,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub expected_protocols: Vec<String>,
    #[serde(default)]
    pub expected_event_families: Vec<String>,
    #[serde(default)]
    pub expected_operations: Vec<String>,
    #[serde(default)]
    pub max_parse_anomalies: Option<usize>,
}

const fn default_min_events() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub version: String,
    pub snapshot_date: String,
    pub reference_catalog: String,
    pub resolved_corpus_source: String,
    pub summary: CorpusManifestSummary,
    #[serde(default)]
    pub directories: Vec<CorpusDirectory>,
    #[serde(default)]
    pub fixtures: Vec<FixtureSpec>,
}

impl CorpusManifest {
    pub fn from_yaml_str(
        input: &str,
        context: impl Into<String>,
    ) -> Result<Self, CorpusManifestError> {
        serde_yaml::from_str(input).map_err(|source| CorpusManifestError::Parse {
            context: context.into(),
            source,
        })
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, CorpusManifestError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|source| CorpusManifestError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_yaml_str(&content, path.display().to_string())
    }

    pub fn default_ics_defense() -> Result<Self, CorpusManifestError> {
        Self::from_yaml_str(
            DEFAULT_ICS_DEFENSE_MANIFEST,
            "embedded ICS Defense manifest",
        )
    }

    pub fn capture_file_total(&self) -> usize {
        self.directories.iter().map(|entry| entry.file_count).sum()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FixtureValidationObservation {
    pub event_count: usize,
    pub protocols_seen: Vec<String>,
    pub event_families_seen: Vec<String>,
    pub operations_seen: Vec<String>,
    pub parse_anomalies: usize,
}

impl FixtureValidationObservation {
    pub fn from_output(output: &crate::DpiSegmentOutput) -> Self {
        let mut protocols_seen = BTreeSet::new();
        let mut event_families_seen = BTreeSet::new();
        let mut operations_seen = BTreeSet::new();
        let mut parse_anomalies = 0usize;

        for event in &output.events {
            if let Some(protocol) = event.protocol() {
                protocols_seen.insert(protocol.to_string());
            }
            event_families_seen.insert(event.family_name().to_string());
            if let Some(operation) = event.operation() {
                operations_seen.insert(operation.to_string());
            }
            if matches!(event.family, BronzeEventFamily::ParseAnomaly(_)) {
                parse_anomalies += 1;
            }
        }

        Self {
            event_count: output.events.len(),
            protocols_seen: protocols_seen.into_iter().collect(),
            event_families_seen: event_families_seen.into_iter().collect(),
            operations_seen: operations_seen.into_iter().collect(),
            parse_anomalies,
        }
    }
}

impl FixtureSpec {
    fn contains(haystack: &[String], needle: &str) -> bool {
        haystack.iter().any(|value| value == needle)
    }

    pub fn validate_observation(
        &self,
        observation: &FixtureValidationObservation,
    ) -> Result<(), String> {
        let mut failures = Vec::new();

        if observation.event_count < self.min_events {
            failures.push(format!(
                "expected at least {} events, observed {}",
                self.min_events, observation.event_count
            ));
        }

        for protocol in &self.expected_protocols {
            if !Self::contains(&observation.protocols_seen, protocol) {
                failures.push(format!("missing expected protocol `{protocol}`"));
            }
        }

        for family in &self.expected_event_families {
            if !Self::contains(&observation.event_families_seen, family) {
                failures.push(format!("missing expected event family `{family}`"));
            }
        }

        for operation in &self.expected_operations {
            if !Self::contains(&observation.operations_seen, operation) {
                failures.push(format!("missing expected operation `{operation}`"));
            }
        }

        if let Some(limit) = self.max_parse_anomalies
            && observation.parse_anomalies > limit
        {
            failures.push(format!(
                "expected at most {limit} parse anomalies, observed {}",
                observation.parse_anomalies
            ));
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureResultStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixtureResult {
    pub id: String,
    pub archive_dir: String,
    pub normalized_family: String,
    pub relative_path: String,
    pub resolved_path: String,
    pub status: FixtureResultStatus,
    pub message: String,
    pub observation: Option<FixtureValidationObservation>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CorpusValidationOptions {
    pub filter: Option<String>,
    pub allow_missing_fixtures: bool,
}

impl CorpusValidationOptions {
    fn matches_fixture(&self, fixture: &FixtureSpec) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        let filter = filter.to_ascii_lowercase();
        [
            fixture.id.as_str(),
            fixture.archive_dir.as_str(),
            fixture.normalized_family.as_str(),
            fixture.path.as_str(),
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains(&filter))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusValidationSummary {
    pub manifest_version: String,
    pub snapshot_date: String,
    pub corpus_root: String,
    pub selected_fixtures: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<FixtureResult>,
}

impl CorpusValidationSummary {
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

pub fn validate_corpus_manifest(
    manifest: &CorpusManifest,
    corpus_root: impl AsRef<Path>,
    options: &CorpusValidationOptions,
) -> CorpusValidationSummary {
    let corpus_root = corpus_root.as_ref();
    let mut results = Vec::new();

    for fixture in manifest
        .fixtures
        .iter()
        .filter(|fixture| options.matches_fixture(fixture))
    {
        let resolved_path = corpus_root.join(&fixture.path);
        if !resolved_path.exists() {
            let should_skip = options.allow_missing_fixtures && !fixture.required;
            results.push(FixtureResult {
                id: fixture.id.clone(),
                archive_dir: fixture.archive_dir.clone(),
                normalized_family: fixture.normalized_family.clone(),
                relative_path: fixture.path.clone(),
                resolved_path: resolved_path.display().to_string(),
                status: if should_skip {
                    FixtureResultStatus::Skipped
                } else {
                    FixtureResultStatus::Failed
                },
                message: if should_skip {
                    "fixture not present under corpus root".to_string()
                } else {
                    "fixture missing under corpus root".to_string()
                },
                observation: None,
            });
            continue;
        }

        let bytes = match fs::read(&resolved_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                results.push(FixtureResult {
                    id: fixture.id.clone(),
                    archive_dir: fixture.archive_dir.clone(),
                    normalized_family: fixture.normalized_family.clone(),
                    relative_path: fixture.path.clone(),
                    resolved_path: resolved_path.display().to_string(),
                    status: FixtureResultStatus::Failed,
                    message: format!("failed to read fixture: {error}"),
                    observation: None,
                });
                continue;
            }
        };

        let mut engine = DpiEngine::new();
        let output = match engine.process_capture_to_vec(
            &SegmentMeta::new(fixture.id.clone()),
            std::io::Cursor::new(bytes),
        ) {
            Ok(output) => output,
            Err(error) => {
                results.push(FixtureResult {
                    id: fixture.id.clone(),
                    archive_dir: fixture.archive_dir.clone(),
                    normalized_family: fixture.normalized_family.clone(),
                    relative_path: fixture.path.clone(),
                    resolved_path: resolved_path.display().to_string(),
                    status: FixtureResultStatus::Failed,
                    message: format!("engine failed to process capture: {error}"),
                    observation: None,
                });
                continue;
            }
        };

        let observation = FixtureValidationObservation::from_output(&output);
        match fixture.validate_observation(&observation) {
            Ok(()) => results.push(FixtureResult {
                id: fixture.id.clone(),
                archive_dir: fixture.archive_dir.clone(),
                normalized_family: fixture.normalized_family.clone(),
                relative_path: fixture.path.clone(),
                resolved_path: resolved_path.display().to_string(),
                status: FixtureResultStatus::Passed,
                message: "fixture satisfied expectations".to_string(),
                observation: Some(observation),
            }),
            Err(message) => results.push(FixtureResult {
                id: fixture.id.clone(),
                archive_dir: fixture.archive_dir.clone(),
                normalized_family: fixture.normalized_family.clone(),
                relative_path: fixture.path.clone(),
                resolved_path: resolved_path.display().to_string(),
                status: FixtureResultStatus::Failed,
                message,
                observation: Some(observation),
            }),
        }
    }

    let passed = results
        .iter()
        .filter(|result| result.status == FixtureResultStatus::Passed)
        .count();
    let failed = results
        .iter()
        .filter(|result| result.status == FixtureResultStatus::Failed)
        .count();
    let skipped = results
        .iter()
        .filter(|result| result.status == FixtureResultStatus::Skipped)
        .count();

    CorpusValidationSummary {
        manifest_version: manifest.version.clone(),
        snapshot_date: manifest.snapshot_date.clone(),
        corpus_root: corpus_root.display().to_string(),
        selected_fixtures: results.len(),
        passed,
        failed,
        skipped,
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CorpusManifest, CorpusRoadmapPhase, FixtureSpec, FixtureValidationObservation,
        ImplementationStatus,
    };

    #[test]
    fn embedded_manifest_matches_snapshot_counts() {
        let manifest = CorpusManifest::default_ics_defense().unwrap();

        assert_eq!(manifest.summary.archive_directories, 41);
        assert_eq!(manifest.summary.capture_files, 251);
        assert_eq!(manifest.capture_file_total(), 251);
        assert_eq!(manifest.directories.len(), 41);
        assert!(
            manifest
                .summary
                .non_pcap_sidecars
                .contains(&"DNP3/.DS_Store".to_string()),
            "expected sidecar inventory to include DNP3/.DS_Store"
        );
    }

    #[test]
    fn embedded_manifest_tracks_phase_coverage() {
        let manifest = CorpusManifest::default_ics_defense().unwrap();

        assert!(manifest.directories.iter().any(|entry| {
            entry.archive_dir == "S7COMM"
                && entry.roadmap_phase == CorpusRoadmapPhase::Phase1
                && entry.implementation_status == ImplementationStatus::Active
        }));
        assert!(manifest.directories.iter().any(|entry| {
            entry.archive_dir == "IEC61850"
                && entry.roadmap_phase == CorpusRoadmapPhase::Phase2
                && entry.implementation_status == ImplementationStatus::Partial
        }));
        assert!(manifest.directories.iter().any(|entry| {
            entry.archive_dir == "Malware"
                && entry.roadmap_phase == CorpusRoadmapPhase::CorpusOnly
                && entry.implementation_status == ImplementationStatus::CorpusOnly
        }));
    }

    #[test]
    fn fixture_validation_reports_missing_protocols() {
        let fixture = FixtureSpec {
            id: "dhcp-discover".to_string(),
            archive_dir: "DHCP".to_string(),
            path: "DHCP/dhcp-discover.pcap".to_string(),
            normalized_family: "dhcp".to_string(),
            min_events: 1,
            required: false,
            expected_protocols: vec!["dhcp".to_string()],
            expected_event_families: vec!["protocol_transaction".to_string()],
            expected_operations: vec![],
            max_parse_anomalies: Some(0),
        };

        let observation = FixtureValidationObservation {
            event_count: 2,
            protocols_seen: vec!["arp".to_string()],
            event_families_seen: vec!["asset_observation".to_string()],
            operations_seen: vec![],
            parse_anomalies: 1,
        };

        let error = fixture.validate_observation(&observation).unwrap_err();
        assert!(error.contains("missing expected protocol `dhcp`"));
        assert!(error.contains("missing expected event family `protocol_transaction`"));
        assert!(error.contains("expected at most 0 parse anomalies, observed 1"));
    }
}
