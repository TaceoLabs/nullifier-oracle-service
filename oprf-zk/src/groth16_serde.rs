use ark_bn254::Bn254;
use serde::{Deserialize, Serialize};

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// The `A` element in `G1`.
    #[serde(rename = "pi_a")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1")]
    pub a: ark_bn254::G1Affine,
    /// The `B` element in `G2`.
    #[serde(rename = "pi_b")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g2")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g2")]
    pub b: ark_bn254::G2Affine,
    /// The `C` element in `G1`.
    #[serde(rename = "pi_c")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1")]
    pub c: ark_bn254::G1Affine,
}

impl From<Groth16Proof> for ark_groth16::Proof<Bn254> {
    fn from(value: Groth16Proof) -> Self {
        Self {
            a: value.a,
            b: value.b,
            c: value.c,
        }
    }
}

impl From<ark_groth16::Proof<Bn254>> for Groth16Proof {
    fn from(value: ark_groth16::Proof<Bn254>) -> Self {
        Self {
            a: value.a,
            b: value.b,
            c: value.c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Groth16Proof;

    const PROOF: &str = r#"{"pi_a":["9116723326348226310312399687760458379430965793646629199281973649756047436480","2874270905534102053533448138397225723399614825643556082270186179665334613224","1"],"pi_b":[["13328302993272298376458050653251338379859716533551615072852727463498727372592","12701171633796457182683671489148506476790474186771723028154216779603805469575"],["8082634848749541028482697284805475720753045849064639479971735063238995549772","20245972516592660684651816366736428662226358885768931974840625194221925755315"],["1","0"]],"pi_c":["3011399641379772467981372516841419028913642315726922827824714699429906533335","10895927520860009543604229709848836725831147762816413949621715866949585547965","1"]}"#;

    #[test]
    fn test_groth16_proof_serde() {
        let proof: Groth16Proof = serde_json::from_str(PROOF).unwrap();
        let serialized = serde_json::to_string(&proof).unwrap();
        assert_eq!(PROOF, serialized);
    }
}
