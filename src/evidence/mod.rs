mod engine;
mod model;

pub use engine::{
    EvidenceEngine,
    EvidenceInput,
};

pub use model::{
    ConfidenceLevel,
    DetectionClassification,
    DetectionResult,
    EvidenceCategory,
    EvidenceDirection,
    EvidenceItem,
    EvidenceKind,
};