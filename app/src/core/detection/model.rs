//! Model signature file (LEDA §3): forest, feature names, extractor tables and
//! triggers, exported by `ai/lotl/export.py`.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use serde::Deserialize;

use super::featurize::Featurizer;

/// Trigger names the detector knows (`ai/lotl/prototype.py` TRIGGERS).
pub const TRIGGERS: [&str; 4] = ["start", "exec", "interp_child", "rule_hit"];

#[derive(Deserialize)]
pub struct Signature {
    pub version: u32,
    /// Malicious when the mean tree P(malicious) is above this.
    pub threshold: f64,
    pub triggers: Vec<String>,
    pub extractor: ExtractorConfig,
    /// DictVectorizer column names, in column order.
    pub features: Vec<String>,
    pub trees: Vec<Tree>,
}

/// Tables of `ai/lotl/features.py` and `MAX_ANCESTORS` of `ai/lotl/chains.py`.
#[derive(Deserialize)]
pub struct ExtractorConfig {
    pub max_ancestors: usize,
    pub content_apps: Vec<String>,
    pub interpreters: Vec<String>,
    pub tools: Vec<String>,
    pub servers: Vec<String>,
    pub lotl_bins: Vec<String>,
    /// (fragment, label)
    pub paths: Vec<(String, String)>,
    pub long_params: Vec<String>,
    /// (fragment, label)
    pub cmdline_rules: Vec<(String, String)>,
    /// (name, Python regex, matched case-insensitively)
    pub patterns: Vec<(String, String)>,
}

/// One sklearn decision tree; node 0 is the root, a leaf has `left == -1`.
#[derive(Deserialize)]
pub struct Tree {
    left: Vec<i64>,
    right: Vec<i64>,
    feature: Vec<i64>,
    threshold: Vec<f64>,
    /// P(malicious) at the node (used at leaves).
    p1: Vec<f64>,
}

pub struct Model {
    pub sig: Signature,
    pub featurizer: Featurizer,
    index: HashMap<String, usize>,
}

impl Model {
    pub fn load(path: &Path) -> io::Result<Model> {
        let err = |e: String| io::Error::other(format!("{}: {e}", path.display()));
        let text = std::fs::read_to_string(path).map_err(|e| err(e.to_string()))?;
        Self::parse(&text).map_err(err)
    }

    pub fn parse(json: &str) -> Result<Model, String> {
        let sig: Signature = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if sig.version != 1 {
            return Err(format!("unsupported signature version {}", sig.version));
        }
        if let Some(t) = sig.triggers.iter().find(|t| !TRIGGERS.contains(&t.as_str())) {
            return Err(format!("unknown trigger '{t}'"));
        }
        if sig.trees.is_empty() {
            return Err("no trees".into());
        }
        let n_features = sig.features.len() as i64;
        for (i, t) in sig.trees.iter().enumerate() {
            let n = t.left.len();
            let lens = [t.right.len(), t.feature.len(), t.threshold.len(), t.p1.len()];
            // Every internal node must point at real children and a real column, so `predict` cannot panic.
            let node_ok = |k: usize| {
                t.left[k] == -1
                    || [t.left[k], t.right[k]].iter().all(|&c| (0..n as i64).contains(&c))
                        && (0..n_features).contains(&t.feature[k])
            };
            if n == 0 || lens.iter().any(|&l| l != n) || !(0..n).all(node_ok) {
                return Err(format!("tree {i} is malformed"));
            }
        }
        let featurizer = Featurizer::new(&sig.extractor)?;
        let index = sig.features.iter().enumerate().map(|(i, f)| (f.clone(), i)).collect();
        Ok(Model { sig, featurizer, index })
    }

    /// Mean P(malicious) over the trees, as sklearn `predict_proba(...)[:, 1]`.
    pub fn predict(&self, f: &HashMap<String, f64>) -> f64 {
        // sklearn casts X to float32 and compares it with float64 thresholds;
        // names the vectorizer never saw are dropped, as DictVectorizer does.
        let mut x = vec![0f32; self.sig.features.len()];
        for (name, v) in f {
            if let Some(&i) = self.index.get(name) {
                x[i] = *v as f32;
            }
        }
        let total: f64 = self
            .sig
            .trees
            .iter()
            .map(|t| {
                let mut n = 0;
                while t.left[n] != -1 {
                    let go_left = f64::from(x[t.feature[n] as usize]) <= t.threshold[n];
                    n = if go_left { t.left[n] } else { t.right[n] } as usize;
                }
                t.p1[n]
            })
            .sum();
        total / self.sig.trees.len() as f64
    }

    /// The score when it is above the signature's threshold.
    pub fn is_malicious(&self, f: &HashMap<String, f64>) -> Option<f64> {
        Some(self.predict(f)).filter(|&s| s > self.sig.threshold)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[derive(Deserialize)]
    pub struct GoldenCase {
        pub chain: Vec<String>,
        pub cmdline: String,
        pub features: HashMap<String, f64>,
        pub p1: f64,
    }

    #[derive(Deserialize)]
    struct Golden {
        golden: Vec<GoldenCase>,
    }

    const PARITY: &str = include_str!("parity.json");

    /// Signature and golden cases from `python -m lotl.export --golden`.
    pub fn fixture() -> (Model, Vec<GoldenCase>) {
        let golden: Golden = serde_json::from_str(PARITY).unwrap();
        (Model::parse(PARITY).unwrap(), golden.golden)
    }

    #[test]
    fn forest_matches_python() {
        let (model, cases) = fixture();
        assert!(cases.iter().any(|c| c.p1 > 0.5) && cases.iter().any(|c| c.p1 <= 0.5));
        for c in &cases {
            let p = model.predict(&c.features);
            assert!((p - c.p1).abs() < 1e-9, "{:?} {}: rust {p} python {}", c.chain, c.cmdline, c.p1);
            assert_eq!(model.is_malicious(&c.features).is_some(), c.p1 > 0.5, "{:?} {}", c.chain, c.cmdline);
        }
    }

    #[test]
    fn rejects_bad_signatures() {
        let err = |v: &serde_json::Value| Model::parse(&v.to_string()).err().unwrap_or_default();
        let mut v: serde_json::Value = serde_json::from_str(PARITY).unwrap();
        v["triggers"] = serde_json::json!(["exec", "bogus"]);
        assert!(err(&v).contains("bogus"));
        v["triggers"] = serde_json::json!(["exec"]);
        v["trees"][0]["left"][0] = serde_json::json!(1_000_000);
        assert!(err(&v).contains("tree 0"));
    }
}
