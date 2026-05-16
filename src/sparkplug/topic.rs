//! Sparkplug B topic parsing.
//!
//! Sparkplug B topics follow the form:
//!   `spBv1.0/<group_id>/<message_type>/<edge_node_id>[/<device_id>]`
//!
//! `message_type` is one of NBIRTH, NDEATH, NDATA, NCMD, DBIRTH, DDEATH, DDATA,
//! DCMD, STATE. Node-level messages (N*) carry no `device_id`; device-level
//! messages (D*) require it.

/// Sparkplug B message type, parsed from the third topic segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Node birth — full metric definitions including alias-to-name binding.
    NBirth,
    /// Node death — bdSeq advances, edge node going offline.
    NDeath,
    /// Node data — metric values, typically referenced by alias only.
    NData,
    /// Node command (host → edge).
    NCmd,
    /// Device birth — under an edge node.
    DBirth,
    /// Device death.
    DDeath,
    /// Device data.
    DData,
    /// Device command.
    DCmd,
    /// Host application state.
    State,
}

impl MessageType {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "NBIRTH" => Self::NBirth,
            "NDEATH" => Self::NDeath,
            "NDATA" => Self::NData,
            "NCMD" => Self::NCmd,
            "DBIRTH" => Self::DBirth,
            "DDEATH" => Self::DDeath,
            "DDATA" => Self::DData,
            "DCMD" => Self::DCmd,
            "STATE" => Self::State,
            _ => return None,
        })
    }

    /// True for messages that carry metric values (BIRTH or DATA, node or device).
    pub fn carries_metrics(self) -> bool {
        matches!(
            self,
            Self::NBirth | Self::NData | Self::DBirth | Self::DData
        )
    }

    /// True for BIRTH messages (which establish alias bindings).
    pub fn is_birth(self) -> bool {
        matches!(self, Self::NBirth | Self::DBirth)
    }

    /// True for DEATH messages.
    pub fn is_death(self) -> bool {
        matches!(self, Self::NDeath | Self::DDeath)
    }
}

/// Parsed Sparkplug B topic. Borrows from the input string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparkplugTopic<'a> {
    pub group_id: &'a str,
    pub message_type: MessageType,
    pub edge_node_id: &'a str,
    /// Present only for D* messages and the STATE topic when device-scoped.
    pub device_id: Option<&'a str>,
}

/// Parse a Sparkplug B topic string. Returns `None` for topics that don't match
/// `spBv1.0/<group>/<msg_type>/<edge>[/<device>]`.
pub fn parse_topic(topic: &str) -> Option<SparkplugTopic<'_>> {
    let mut parts = topic.split('/');
    if parts.next()? != "spBv1.0" {
        return None;
    }
    let group_id = parts.next()?;
    let msg_type_str = parts.next()?;
    let edge_node_id = parts.next()?;
    let device_id = parts.next();
    // No further segments allowed.
    if parts.next().is_some() {
        return None;
    }
    let message_type = MessageType::parse(msg_type_str)?;
    if group_id.is_empty() || edge_node_id.is_empty() {
        return None;
    }
    if let Some(d) = device_id
        && d.is_empty()
    {
        return None;
    }
    Some(SparkplugTopic {
        group_id,
        message_type,
        edge_node_id,
        device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_node_data() {
        let t = parse_topic("spBv1.0/Plant1/NDATA/PLC-A").expect("topic");
        assert_eq!(t.group_id, "Plant1");
        assert_eq!(t.message_type, MessageType::NData);
        assert_eq!(t.edge_node_id, "PLC-A");
        assert_eq!(t.device_id, None);
    }

    #[test]
    fn parses_device_birth() {
        let t = parse_topic("spBv1.0/Plant1/DBIRTH/PLC-A/Drive-17").expect("topic");
        assert_eq!(t.message_type, MessageType::DBirth);
        assert_eq!(t.device_id, Some("Drive-17"));
    }

    #[test]
    fn rejects_non_sparkplug_namespace() {
        assert!(parse_topic("factory/line1/temp").is_none());
        assert!(parse_topic("spAv1.0/g/NDATA/e").is_none());
    }

    #[test]
    fn rejects_unknown_message_type() {
        assert!(parse_topic("spBv1.0/g/FOO/e").is_none());
    }

    #[test]
    fn rejects_too_few_segments() {
        assert!(parse_topic("spBv1.0/g/NDATA").is_none());
        assert!(parse_topic("spBv1.0").is_none());
    }

    #[test]
    fn rejects_empty_segments() {
        assert!(parse_topic("spBv1.0//NDATA/e").is_none());
        assert!(parse_topic("spBv1.0/g/NDATA/").is_none());
        assert!(parse_topic("spBv1.0/g/NDATA/e/").is_none());
    }

    #[test]
    fn rejects_too_many_segments() {
        assert!(parse_topic("spBv1.0/g/NDATA/e/d/extra").is_none());
    }

    #[test]
    fn message_type_classification() {
        assert!(MessageType::NBirth.carries_metrics());
        assert!(MessageType::DData.carries_metrics());
        assert!(!MessageType::NDeath.carries_metrics());
        assert!(!MessageType::NCmd.carries_metrics());
        assert!(MessageType::NBirth.is_birth());
        assert!(MessageType::DBirth.is_birth());
        assert!(!MessageType::NData.is_birth());
        assert!(MessageType::NDeath.is_death());
        assert!(MessageType::DDeath.is_death());
    }
}
