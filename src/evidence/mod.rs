mod engine;
mod model;
mod policy;

pub use engine::{EvidenceEngine, EvidenceInput};

pub use model::{
    ConfidenceLevel, DetectionClassification, DetectionResult, EvidenceCategory, EvidenceDirection,
    EvidenceItem, EvidenceKind, PolicyMetadata,
};

pub use policy::{
    ClassificationRuleSet, CloudflareWebProxyV1, ConfidenceRuleSet, DetectionPolicy, DnsRuleSet,
    RuleSet, ScoreCap,
};
