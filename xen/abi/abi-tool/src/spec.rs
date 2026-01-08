use std::collections::{BTreeSet, HashMap};

use bimap::BiBTreeMap;
use indexmap::IndexMap; /* use indexmap to keep consistent ordering */
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash)]
pub struct CType(#[serde(default)] pub String);

impl Default for CType {
    fn default() -> Self {
        Self("uint64_t".into())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CAnnotations {
    #[serde(rename = "struct")]
    pub cstruct: Option<String>,
    #[serde(default)]
    pub mapping: HashMap<String, String>,
    #[serde(default)]
    pub params: HashMap<String, CType>,
}

pub struct RustAnnotations {

}

#[derive(Debug, Deserialize)]
pub struct HypercallOp {
    #[serde(default)]
    pub input: BiBTreeMap<String, u8>,
    #[serde(default)]
    pub output: BiBTreeMap<String, u8>,

    pub c_lang: Option<CAnnotations>,
}

impl HypercallOp {
    pub fn used_registers(&self) -> BTreeSet<u8> {
        self.input
            .right_values()
            .chain(self.output.right_values())
            .chain(&[0])
            .cloned()
            .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct HypercallSubOp {
    pub index: u32,
    #[serde(flatten)]
    pub op: HypercallOp,
}

#[derive(Debug, Deserialize)]
pub struct AbiSpec {
    pub hypercall_index: u32,
    pub name: String,

    pub direct: Option<HypercallOp>,

    #[serde(default)]
    pub subops: IndexMap<String, HypercallSubOp>,
}
