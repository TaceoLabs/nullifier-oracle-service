pragma circom 2.2.2;

// Returns the inverse of the provided element if it exists. Returns 0 otherwise.
// A slight modification to the stdlib IsZero template, returning inv instead of the boolean.
// Overall strategy:
// - At least on of in or is_zero must be 0 (second to last constraint)
// - If in != 0
//   - is_zero must be 0 => in * inv == 1, therefore inv is correct
// - If in == 0
//   - is_zero = 1, due to first constraint => inv must be 0 due to last constraint
template InverseOrZero() {
    signal input in;
    signal output inv;

    signal is_zero;

    // Compute the inverse if it exists (i.e. input is not 0) 
    inv <-- in != 0 ? 1/in : 0;

    // Compute the is_zero flag
    is_zero <==  1 - in * inv;
    // Constrain at least on of in or is_zero to be zero.
    in*is_zero === 0;
    // Constrain at least on of inv or is_zero to be zero.
    inv*is_zero === 0;
}
