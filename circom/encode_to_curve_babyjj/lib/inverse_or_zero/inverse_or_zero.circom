pragma circom 2.2.2;

template InverseOrZero() {
    signal input in;
    signal output inv;

    inv <-- in != 0 ? 1/in : 0;
    signal in_square <== in * in;
    in_square * inv - in === 0;
}
