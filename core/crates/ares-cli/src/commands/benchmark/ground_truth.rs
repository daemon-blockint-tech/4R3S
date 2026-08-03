/// Ground-truth entry for a single protocol in the benchmark dataset.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundTruthEntry {
    pub name: String,
    #[serde(default)]
    pub source: String, // "stub" or "real"
    #[serde(default)]
    pub real_repo_path: String,
    pub expected_categories: Vec<String>,
    pub expected_critical_high: usize,
    #[allow(dead_code)]
    pub notes: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundTruthFile {
    pub protocols: Vec<GroundTruthEntry>,
}
