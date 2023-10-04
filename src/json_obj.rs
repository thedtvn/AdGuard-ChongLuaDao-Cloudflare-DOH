use serde_derive::Deserialize;
use serde_derive::Serialize;

pub type CldList = Vec<CldI>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CldI {
    #[serde(rename = "type")]
    pub type_field: Option<String>,
    #[serde(rename = "_id")]
    pub id: String,
    pub url: String,
    pub level: String,
    pub created: String,
}