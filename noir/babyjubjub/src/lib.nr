pub struct BabyJubJubPoint {
    x: Field,
    y: Field,
}

impl BabyJubJubPoint {
    pub fn new_unchecked(x: Field, y: Field) -> BabyJubJubPoint {
        BabyJubJubPoint { x, y }
    }

    fn is_on_curve(self) -> bool {
        let a = 168700;
        let d = 168696;
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        a * x2 + y2 == 1 + d * x2 * y2
    }

    pub fn new(x: Field, y: Field) -> BabyJubJubPoint {
        let p = BabyJubJubPoint::new_unchecked(x, y);
        assert(p.is_on_curve());
        p
    }
    pub fn xy(self) -> (Field, Field) {
        (self.x, self.y)
    }

    pub fn x(self) -> Field {
        self.x
    }
    pub fn y(self) -> Field {
        self.y
    }

    pub fn add(self, other: BabyJubJubPoint) -> BabyJubJubPoint {
        // based on the circom implementation at <https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/circuits/babyjub.circom>
        let a = 168700;
        let d = 168696;
        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let delta = (-a * self.x + self.y) * (other.x + other.y);
        let tau = beta * gamma;
        // TODO: check if doing unconstrained inversion helps?
        let x = (beta + gamma) / (1 + d * tau);
        let y = (delta + a * beta - gamma) / (1 - d * tau);
        BabyJubJubPoint { x, y }
    }

    pub fn double(self) -> BabyJubJubPoint {
        // Implement point doubling on Baby Jubjub curve
        // Placeholder implementation
        self.add(self)
    }

    pub fn neg(self) -> BabyJubJubPoint {
        BabyJubJubPoint { x: -self.x, y: self.y }
    }

    pub fn sub(self, other: BabyJubJubPoint) -> BabyJubJubPoint {
        self.add(other.neg())
    }

    pub fn generator() -> BabyJubJubPoint {
        // Baby Jubjub generator point
        BabyJubJubPoint {
            x: 5299619240641551281634865583518297030282874472190772894086521144482721001553,
            y: 16950150798460657717958625567821834550301663161624707787222815936182638968203,
        }
    }
    pub fn zero() -> BabyJubJubPoint {
        BabyJubJubPoint { x: 0, y: 1 }
    }

    pub fn is_zero(self) -> bool {
        (self.x == 0) & (self.y == 1)
    }

    pub fn mul(self, scalar: BabyJubJubScalar) -> BabyJubJubPoint {
        self.bit_mul(scalar.to_le_bits())
    }

    pub fn mul_with_basefield(self, scalar: Field) -> BabyJubJubPoint {
        let bits: [u1; 254] = scalar.to_le_bits();
        self.bit_mul(bits)
    }
    // Scalar multiplication with scalar represented by a bit array (little-endian convention).
    // If k is the natural number represented by `bits`, then this computes p + ... + p k times.
    // TODO: this is just a very basic implementation that is not at all optimized for performance.
    // Can do a lot better in the Montgomery form, and even here in projective coordinates.
    pub fn bit_mul<let N: u32>(self, bits: [u1; N]) -> BabyJubJubPoint {
        let mut out = BabyJubJubPoint::zero();

        for i in 0..N {
            out = out.double();
            out = out
                .add(
                    if (bits[N - i - 1] == 0) {
                        BabyJubJubPoint::zero()
                    } else {
                        self
                    },
                );
        }

        out
    }

    pub fn is_in_correct_subgroup(self) -> bool {
        // Check if the point is in the prime-order subgroup of Baby Jubjub by verifying that [l]P = 0, where l is the order of the subgroup.
        let characteristic: [u1; 251] = [
            1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1,
            1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0,
            0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1,
            1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0,
            0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1,
            1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1,
        ];
        let check_point = self.bit_mul(characteristic);
        check_point.is_zero()
    }
}

pub struct BabyJubJubScalar {
    s: Field,
}

impl BabyJubJubScalar {
    pub fn new(s: Field) -> BabyJubJubScalar {
        // Ensure the scalar is within the valid range for Baby Jubjub
        assert(s.lt(2736030358979909402780800718157159386076813972158567259200215660948447373041));
        BabyJubJubScalar { s }
    }

    pub fn value(self) -> Field {
        self.s
    }

    pub fn to_le_bits(self) -> [u1; 251] {
        self.s.to_le_bits()
    }
}

mod tests {
    use super::BabyJubJubPoint;
    use super::BabyJubJubScalar;
    #[test]
    fn test_babyjubjub_addition() {
        let p1 = BabyJubJubPoint::generator();
        let p2 = BabyJubJubPoint::zero();
        let p3 = p1.add(p2);
        assert(p3.is_on_curve());
        assert(p3.xy() == p1.xy());
        let p4 = p1.add(p1);
        assert(p4.is_on_curve());
        assert(
            p4.xy()
                == (
                    10031262171927540148667355526369034398030886437092045105752248699557385197826,
                    633281375905621697187330766174974863687049529291089048651929454608812697683,
                ),
        );
    }

    #[test]
    fn test_babyjubjub_doubling() {
        let p1 = BabyJubJubPoint::generator();
        let p2 = p1.double();
        assert(p2.is_on_curve());
        assert(
            p2.xy()
                == (
                    10031262171927540148667355526369034398030886437092045105752248699557385197826,
                    633281375905621697187330766174974863687049529291089048651929454608812697683,
                ),
        );
    }

    #[test]
    fn test_babyjubjub_mul() {
        let p = BabyJubJubPoint::generator();
        let s = BabyJubJubScalar::new(1);
        let r = p.mul(s);
        assert(r.is_on_curve());
        assert(r.xy() == p.xy());

        let s2 = BabyJubJubScalar::new(0);
        let r2 = p.mul(s2);
        assert(r2.is_on_curve());
        assert(r2.is_zero());

        let s3 = BabyJubJubScalar::new(2);
        let r3 = p.mul(s3);
        assert(r3.is_on_curve());
        assert(r3.xy() == p.double().xy());

        let s4 = BabyJubJubScalar::new(123456789);
        let r4 = p.mul(s4);
        assert(r4.is_on_curve());
        assert(
            r4.xy()
                == (
                    15919299401931535325513703139194931338293993994510664661086800834970360591752,
                    1645780246786685895560641778865228215443840970280597910012614014295481144366,
                ),
        );
    }
}
