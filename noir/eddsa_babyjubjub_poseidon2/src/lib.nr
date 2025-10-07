use babyjubjub::{BabyJubJubPoint, BabyJubJubScalar};

pub struct EdDSASignature {
    r: BabyJubJubPoint,
    s: BabyJubJubScalar,
}

impl EdDSASignature {
    pub fn new(r: BabyJubJubPoint, s: BabyJubJubScalar) -> EdDSASignature {
        EdDSASignature { r, s }
    }

    // Create an EdDSA signature from its raw parts. This verifies that R is a valid point on the curve and that s is a valid scalar.
    pub fn from_parts(r_x: Field, r_y: Field, s: Field) -> EdDSASignature {
        let s = BabyJubJubScalar::new(s);
        let r = BabyJubJubPoint::new(r_x, r_y);

        EdDSASignature { r, s }
    }
}

pub struct EdDSAPublicKey {
    pk: BabyJubJubPoint,
}

impl EdDSAPublicKey {
    // Create an EdDSA public key from a BabyJubJubPoint. This verifies that pk additionally is in the correct subgroup and not the identity point.
    pub fn new(pk: BabyJubJubPoint) -> EdDSAPublicKey {
        assert(pk.is_in_correct_subgroup()); // Ensure the public key is in the correct subgroup
        assert(!pk.is_zero()); // Ensure the public key is not the identity point
        EdDSAPublicKey { pk }
    }
    // Create an EdDSA public key from its raw parts. This verifies that pk is a valid point on the curve and in the correct subgroup and not the identity point.
    pub fn from_parts(x: Field, y: Field) -> EdDSAPublicKey {
        let pk = BabyJubJubPoint::new(x, y);
        EdDSAPublicKey::new(pk)
    }

    pub fn verify(self, sig: EdDSASignature, message: Field) -> bool {
        // we have already ensured that s in < l in its constructor
        // we have checked that R is on the curve in its constructor
        // we have checked that pk is on the curve, in the correct subgroup and not zero in its constructor

        let h = poseidon2::bn254::perm::x5_8([
            360302137480307891234917541314130533,
            sig.r.x(),
            sig.r.y(),
            self.pk.x(),
            self.pk.y(),
            message,
            0,
            0,
        ])[1];

        // calculate h*A + R
        let right2 = self.pk.mul_with_basefield(h);
        let right = right2.add(sig.r);

        // calculate s*B
        let left = BabyJubJubPoint::generator().mul(sig.s);

        // calculate v = s*B - h*A - R
        let v = left.sub(right);

        // clear cofactor by multiplying with 8
        let v8 = v.double().double().double();
        v8.is_zero() // check if v8 is the identity point
    }
}

mod tests {
    use super::EdDSAPublicKey;
    use super::EdDSASignature;

    #[test]
    fn test_eddsa_signature_verification() {
        let pk = EdDSAPublicKey::from_parts(
            15861662102942198476185518224532077347254150735350796263259682790715259346390,
            17622332940847650587004774926435083207962382856110852169511204932927794212320,
        );
        let sig = EdDSASignature::from_parts(
            19090079173373584153996824137084726661643725553797485823319088208683554498717,
            3643574957097202527589616469273298197083911730855228311907034680488748021268,
            2128104906629434075529508057546284580247227319347477887390422344724817923329,
        );
        let m = 3126080974277891902445700130528654565374341115115698716199527644337840721369;
        assert(pk.verify(sig, m));
    }
}
