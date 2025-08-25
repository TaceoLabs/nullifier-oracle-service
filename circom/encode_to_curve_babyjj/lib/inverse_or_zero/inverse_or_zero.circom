pragma circom 2.2.2;

// Returns the inverse of the provided element if it exists. Returns 0 otherwise.
template InverseOrZero() {
    signal input in;
    signal output inv;

    // Compute the inverse if it exists (i.e. input is not 0) 
    inv <-- in != 0 ? 1/in : 0;
    // Constraint that the value is indeed 0 or the inverse by checking:
    // (in * inv * inv - in == 0)
    // iff in = 0  => 0 * 0 * 0 - 0 == 0
    // iff in != 1 => in * inv * in - in == 0 | 1 * in - in == 0
    signal in_inv <== in * inv;
    in_inv * in - in === 0;
}
