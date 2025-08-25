struct BabyJubJubPoint {
    x: Field,
    y: Field,
}

impl BabyJubJubPoint {
    fn add(self, other: BabyJubJubPoint) -> BabyJubJubPoint {
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

    fn double(self) -> BabyJubJubPoint {
        // Implement point doubling on Baby Jubjub curve
        // Placeholder implementation
        self.add(self)
    }
}
