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
}
