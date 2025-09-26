use ark_ff::{PrimeField as _, Zero};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use poseidon2::Poseidon2;

type BaseField = ark_babyjubjub::Fq;

pub struct UserCredentials {
    pub credential_type_id: BaseField,
    /// The index in the merkle tree
    pub user_id: u64,
    pub genesis_issued_at: BaseField,
    pub expires_at: BaseField,
    pub claims_hash: BaseField,
    pub associated_data_hash: BaseField,

    // private key
    pub cred_sk: EdDSAPrivateKey,
}

impl UserCredentials {
    const CRED_DS: &[u8] = b"POSEIDON2+EDDSA-BJJ+DLBE-v1";

    // Returns the domain separator for the hashing of the credential message as a field element
    fn get_cred_ds() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::CRED_DS)
    }

    pub fn pk(&self) -> EdDSAPublicKey {
        self.cred_sk.public()
    }

    pub fn credential_message(&self) -> BaseField {
        let poseidon2_8 = Poseidon2::<_, 8, 5>::default();
        let mut input = [
            Self::get_cred_ds(),
            self.credential_type_id,
            BaseField::from(self.user_id),
            self.genesis_issued_at,
            self.expires_at,
            self.claims_hash,
            self.associated_data_hash,
            BaseField::zero(),
        ];
        poseidon2_8.permutation_in_place(&mut input);
        input[1]
    }

    pub fn sign(&self) -> EdDSASignature {
        self.cred_sk.sign(self.credential_message())
    }
}
