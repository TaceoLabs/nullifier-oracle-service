use crate::Poseidon2Params;
use ark_ff::PrimeField;
use std::any::TypeId;

/// A struct represnting the Poseidon2 permutation.
#[derive(Clone, Debug)]
pub struct Poseidon2<F: PrimeField, const T: usize, const D: u64> {
    /// The parameter set containing the parameters for the Poseidon2 permutation.
    pub params: &'static Poseidon2Params<F, T, D>,
}

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2<F, T, D> {
    /// Creates a new instance of the Poseidon2 permuation with given parameters
    pub fn new(params: &'static Poseidon2Params<F, T, D>) -> Self {
        Self { params }
    }

    /// Returns the number of rounds in the Poseidon2 permutation.
    pub fn num_rounds(&self) -> usize {
        self.params.rounds_f_beginning + self.params.rounds_f_end + self.params.rounds_p
    }

    /// Returns the number of S-boxes used in the Poseidon2 permutation.
    pub fn num_sbox(&self) -> usize {
        (self.params.rounds_f_beginning + self.params.rounds_f_end) * T + self.params.rounds_p
    }

    fn sbox(input: &mut [F; T]) {
        input.iter_mut().for_each(Self::single_sbox);
    }

    fn single_sbox(input: &mut F) {
        match D {
            3 => {
                let input2 = input.square();
                *input *= input2;
            }
            5 => {
                let input2 = input.square();
                let input4 = input2.square();
                *input *= input4;
            }
            7 => {
                let input2 = input.square();
                let input4 = input2.square();
                *input *= input4;
                *input *= input2;
            }
            _ => {
                *input = input.pow([D]);
            }
        }
    }

    /**
     * hardcoded algorithm that evaluates matrix multiplication using the following MDS matrix:
     * /         \
     * | 5 7 1 3 |
     * | 4 6 1 1 |
     * | 1 3 5 7 |
     * | 1 1 4 6 |
     * \         /
     *
     * Algorithm is taken directly from the Poseidon2 paper.
     */
    fn matmul_m4(input: &mut [F; 4]) {
        let t_0 = input[0] + input[1]; // A + B
        let t_1 = input[2] + input[3]; // C + D
        let t_2 = input[1].double() + t_1; // 2B + C + D
        let t_3 = input[3].double() + t_0; // A + B + 2D
        let t_4 = t_1.double().double() + t_3; // A + B + 4C + 6D
        let t_5 = t_0.double().double() + t_2; // 4A + 6B + C + D
        let t_6 = t_3 + t_5; // 5A + 7B + C + 3D
        let t_7 = t_2 + t_4; // A + 3B + 5C + 7D
        input[0] = t_6;
        input[1] = t_5;
        input[2] = t_7;
        input[3] = t_4;
    }

    /// The matrix multiplication in the external rounds of the Poseidon2 permutation.
    pub fn matmul_external(input: &mut [F; T]) {
        match T {
            2 => {
                // Matrix circ(2, 1)
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1] += sum;
            }
            3 => {
                // Matrix circ(2, 1, 1)
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2] += sum;
            }
            4 => {
                Self::matmul_m4(input.as_mut_slice().try_into().unwrap());
            }
            8 | 12 | 16 | 20 | 24 => {
                // Applying cheap 4x4 MDS matrix to each 4-element part of the state
                for state in input.chunks_exact_mut(4) {
                    Self::matmul_m4(state.try_into().unwrap());
                }

                // Applying second cheap matrix for t > 4
                let mut stored = [F::zero(); 4];
                for l in 0..4 {
                    stored[l] = input[l];
                    for j in 1..T / 4 {
                        stored[l] += input[4 * j + l];
                    }
                }
                for i in 0..T {
                    input[i] += stored[i % 4];
                }
            }
            _ => {
                panic!("Invalid Statesize");
            }
        }
    }

    /// The matrix multiplication in the internal rounds of the Poseidon2 permutation.
    pub fn matmul_internal(&self, input: &mut [F; T]) {
        match T {
            2 => {
                // Matrix [[2, 1], [1, 3]]
                debug_assert_eq!(self.params.mat_internal_diag_m_1[0], F::one());
                debug_assert_eq!(self.params.mat_internal_diag_m_1[1], F::from(2u64));
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1].double_in_place();
                input[1] += sum;
            }
            3 => {
                // Matrix [[2, 1, 1], [1, 2, 1], [1, 1, 3]]
                debug_assert_eq!(self.params.mat_internal_diag_m_1[0], F::one());
                debug_assert_eq!(self.params.mat_internal_diag_m_1[1], F::one());
                debug_assert_eq!(self.params.mat_internal_diag_m_1[2], F::from(2u64));
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2].double_in_place();
                input[2] += sum;
            }
            _ => {
                // Compute input sum
                let sum: F = input.iter().sum();
                // Add sum + diag entry * element to each element

                for (s, m) in input
                    .iter_mut()
                    .zip(self.params.mat_internal_diag_m_1.iter())
                {
                    *s *= m;
                    *s += sum;
                }
            }
        }
    }

    /// The round constant additon in the external rounds of the Poseidon2 permutation.
    pub fn add_rc_external(&self, input: &mut [F; T], rc_offset: usize) {
        for (s, rc) in input
            .iter_mut()
            .zip(self.params.round_constants_external[rc_offset].iter())
        {
            *s += rc;
        }
    }

    /// The round constant additon in the internal rounds of the Poseidon2 permutation.
    pub fn add_rc_internal(&self, input: &mut [F; T], rc_offset: usize) {
        input[0] += &self.params.round_constants_internal[rc_offset];
    }

    /// One external round of the Poseidon2 permuation.
    pub fn external_round(&self, state: &mut [F; T], r: usize) {
        self.add_rc_external(state, r);
        Self::sbox(state);
        Self::matmul_external(state);
    }

    /// One internal round of the Poseidon2 permuation.
    pub fn internal_round(&self, state: &mut [F; T], r: usize) {
        self.add_rc_internal(state, r);
        Self::single_sbox(&mut state[0]);
        self.matmul_internal(state);
    }

    /// Performs the Poseidon2 Permutation on the given state.
    pub fn permutation_in_place(&self, state: &mut [F; T]) {
        // Linear layer at beginning
        Self::matmul_external(state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.external_round(state, r);
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.internal_round(state, r);
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.external_round(state, r);
        }
    }

    /// Performs the Poseidon2 Permutation on the given state.
    pub fn permutation(&self, input: &[F; T]) -> [F; T] {
        let mut state = *input;
        self.permutation_in_place(&mut state);
        state
    }
}

impl<F: PrimeField, const T: usize> Default for Poseidon2<F, T, 5> {
    fn default() -> Self {
        if TypeId::of::<F>() == TypeId::of::<ark_bn254::Fr>() {
            match T {
                2 => {
                    let params = &super::POSEIDON2_BN254_T2_PARAMS;
                    let poseidon2 = Poseidon2::new(params);
                    // Safety: We checked that the types match
                    unsafe {
                        std::mem::transmute::<Poseidon2<ark_bn254::Fr, 2, 5>, Poseidon2<F, T, 5>>(
                            poseidon2,
                        )
                    }
                }
                3 => {
                    let params = &super::POSEIDON2_BN254_T3_PARAMS;
                    let poseidon2 = Poseidon2::new(params);
                    // Safety: We checked that the types match
                    unsafe {
                        std::mem::transmute::<Poseidon2<ark_bn254::Fr, 3, 5>, Poseidon2<F, T, 5>>(
                            poseidon2,
                        )
                    }
                }
                4 => {
                    let params = &super::POSEIDON2_BN254_T4_PARAMS;
                    let poseidon2 = Poseidon2::new(params);
                    // Safety: We checked that the types match
                    unsafe {
                        std::mem::transmute::<Poseidon2<ark_bn254::Fr, 4, 5>, Poseidon2<F, T, 5>>(
                            poseidon2,
                        )
                    }
                }
                8 => {
                    let params = &super::POSEIDON2_BN254_T8_PARAMS;
                    let poseidon2 = Poseidon2::new(params);
                    // Safety: We checked that the types match
                    unsafe {
                        std::mem::transmute::<Poseidon2<ark_bn254::Fr, 8, 5>, Poseidon2<F, T, 5>>(
                            poseidon2,
                        )
                    }
                }
                12 => {
                    let params = &super::POSEIDON2_BN254_T12_PARAMS;
                    let poseidon2 = Poseidon2::new(params);
                    // Safety: We checked that the types match
                    unsafe {
                        std::mem::transmute::<Poseidon2<ark_bn254::Fr, 12, 5>, Poseidon2<F, T, 5>>(
                            poseidon2,
                        )
                    }
                }
                16 => {
                    let params = &super::POSEIDON2_BN254_T16_PARAMS;
                    let poseidon2 = Poseidon2::new(params);
                    // Safety: We checked that the types match
                    unsafe {
                        std::mem::transmute::<Poseidon2<ark_bn254::Fr, 16, 5>, Poseidon2<F, T, 5>>(
                            poseidon2,
                        )
                    }
                }
                _ => panic!("No Poseidon2 implementation for T={T}"),
            }
        } else {
            panic!("No Poseidon2 implementation for this field");
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        POSEIDON2_BN254_T2_PARAMS, POSEIDON2_BN254_T3_PARAMS, POSEIDON2_BN254_T4_PARAMS,
        POSEIDON2_BN254_T8_PARAMS, POSEIDON2_BN254_T12_PARAMS, POSEIDON2_BN254_T16_PARAMS,
    };
    use std::array;

    use super::*;
    use ark_std::rand::thread_rng;

    const TESTRUNS: usize = 10;

    fn poseidon2_kat<F: PrimeField, const T: usize, const D: u64>(
        params: &'static Poseidon2Params<F, T, D>,
        input: &[F; T],
        expected: &[F; T],
    ) {
        let poseidon2 = Poseidon2::new(params);
        let result = poseidon2.permutation(input);
        assert_eq!(&result, expected);
    }

    fn poseidon2_consistent_perm<F: PrimeField, const T: usize, const D: u64>(
        params: &'static Poseidon2Params<F, T, D>,
    ) {
        let mut rng = &mut thread_rng();
        let input1: Vec<F> = (0..T).map(|_| F::rand(&mut rng)).collect();
        let mut input2 = input1.clone();
        input2.rotate_right(T / 2);

        let poseidon2 = Poseidon2::new(params);
        let perm1 = poseidon2.permutation(input1.as_slice().try_into().unwrap());
        let perm2 = poseidon2.permutation(&input1.try_into().unwrap());
        let perm3 = poseidon2.permutation(&input2.try_into().unwrap());

        assert_eq!(perm1, perm2);
        assert_ne!(perm1, perm3);
    }

    #[test]
    fn posedon2_bn254_t4_consistent_perm() {
        for _ in 0..TESTRUNS {
            poseidon2_consistent_perm(&POSEIDON2_BN254_T4_PARAMS);
        }
    }

    #[test]
    fn posedon2_bn254_t2_kat1() {
        let input = [ark_bn254::Fr::from(0u64), ark_bn254::Fr::from(1u64)];
        let expected = [
            crate::field_from_hex_string(
                "0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0d189ec589c41b8cffa88cfc523618a055abe8192c70f75aa72fc514560f6c61",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T2_PARAMS, &input, &expected);
    }

    #[test]
    fn posedon2_bn254_t3_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = [
            ark_bn254::Fr::from(0u64),
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(2u64),
        ];
        let expected = [
            crate::field_from_hex_string(
                "0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T3_PARAMS, &input, &expected);
    }

    #[test]
    fn posedon2_bn254_t4_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = [
            ark_bn254::Fr::from(0u64),
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(2u64),
            ark_bn254::Fr::from(3u64),
        ];
        let expected = [
            crate::field_from_hex_string(
                "0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T4_PARAMS, &input, &expected);
    }

    #[test]
    fn posedon2_bn254_t4_kat2() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = [
            crate::field_from_hex_string(
                "9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789",
            )
            .unwrap(),
        ];
        let expected = [
            crate::field_from_hex_string(
                "0x2bf1eaf87f7d27e8dc4056e9af975985bccc89077a21891d6c7b6ccce0631f95",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0c01fa1b8d0748becafbe452c0cb0231c38224ea824554c9362518eebdd5701f",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x018555a8eb50cf07f64b019ebaf3af3c925c93e631f3ecd455db07bbb52bbdd3",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0cbea457c91c22c6c31fd89afd2541efc2edf31736b9f721e823b2165c90fd41",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T4_PARAMS, &input, &expected);
    }

    #[test]
    fn posedon2_bn254_t8_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = array::from_fn(|i| ark_bn254::Fr::from(i as u64));
        let expected = [
            crate::field_from_hex_string(
                "0x1d1a50bcde871247856df135d56a4ca61af575f1140ed9b1503c77528cf345df",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x2d3943cf476ed49fd8a636660d8a76c83b55f07d06bc082005ad7eb1a21791c5",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x2fcda2dd846fadfde8104b1d05175dcf3cf8bd698ed8ea3ad2fbcf9c06e00310",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x28811ac7e0829171f9d3d81f1c0ff8f34b360d407a16b331a1cb6b5d992de094",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x2c07c1817cfccb67c1297935514885c07abad5a0e15477f6c076c0b0fb1ad6f3",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x1b6114397199bc44e37437dd3ba1754dff007d3315bfcdcdc14ec27d02452f52",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x1431250baf36fb61a07618caee4dd2f500da339a05c553e8f529a3349e617aa2",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0b19bfa00c8f1d505074130e7f8b49a8624b1905e280ceca5ba11099b081b265",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T8_PARAMS, &input, &expected);
    }

    #[test]
    fn posedon2_bn254_t12_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = array::from_fn(|i| ark_bn254::Fr::from(i as u64));
        let expected = [
            crate::field_from_hex_string(
                "0x3014e0ec17029f7e4f5cfe8c7c54fc3df6a5f7539f6aa304b2f3c747a9105618",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x2f90753e7aaf46c158cd12346da7dd37c3136353ec51525cabbaaf2b2350f9b2",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x2e28bdc8b2c68b09da0cb653ee7e54eca909cf2ae010784554aa3e165b1a105f",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x1d6a97ef87dbd3476a848af45beebe6b5d79cb047b37212e3e5839f1e80b397a",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x24e23df24b19b75f44218a08d107709d35561bc1b982cfc317d54568cd496519",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x185a08e623b85e797844191a1f184f7b8fc486253919eb20f1186a8331757018",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x069ed78df853a105c8949dae5b4e81cbe370e8f6e25735a688aa8ff3df9659eb",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x284395d79b64123211a4a59b81a90f9cfa8d8314dccde4cef22ec1e31431efd3",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0f24be5a8c95e3504ead0da9e792b77d7056f94461d69b04b33ea5d239f8e444",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x022469ccfef0ce5a237518c38dec31fc2804e633b3b365c23a9f703ca31ef393",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x1fcdcee218d5a0101bd233d572f184964854d445ca08d2bd6df6ceba5651e322",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0905469a776b7d5a3f18841edb90fa0d8c6de479c2789c042dafefb367ad1a2b",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T12_PARAMS, &input, &expected);
    }

    #[test]
    fn posedon2_bn254_t16_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = array::from_fn(|i| ark_bn254::Fr::from(i as u64));
        let expected = [
            crate::field_from_hex_string(
                "0x0fc2e6b758f493969e1d860f9a44ee3bdffdf796f382aa4ffb16fa4e9bcc333f",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0c118155a0dfeca3f91faf14a350511228ac33743be91249c6e0b3a635a50de4",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x1a02b3a6571f22bb6392322d3f9f5de145b4f00bdf483072ce6188c30ba0f83d",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x26631df6b2522ecde57413cd680ed590ded356e1c680f865f45be8eb960d1e06",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x250ac4dfed40dc37bac9abe46f7bff3a80481d52a157ac80a1e5d39a5ed60e18",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x17160980d8e7d9cb31addaf294cf047768bffd9fe433e8903b4ed262ee913f5b",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x1d708a9f0995c2e0cd2f55e5dc795126f7191a0eb934ac8172bf54e520361ff6",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x20721a18915e96e37e12c9697427f34d6a366787ea94ea65565c36813a0d77a3",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x08671a9e58105eed9ac673249dcf22f08f098e3c6eb28f9eaa55d67d755972d0",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x01e879484303c6d057128fbcc3a4222c779a62d3666df65d4e0b64c8031d7cc4",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x239e2ce87955ebe19aaad000b38725b729f51175ab7d688f15d997edf0e3b7fc",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x06be612f42b3ebdbade3fe199338c9118eb6b5fb760bda96e45443f130a8b2de",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x11b2c04b4eb9e4844e5ddbb19b56059a815ed5d69405ba51786961235d5f073c",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x006da33e2d57616c0ffc855b48d225a1237c3d80fc7e6b6e73b74e162b85c8a8",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0ef50c2615882523c6c73a69b4371332a066b2dc4b9630f186db47e3bfca88c8",
            )
            .unwrap(),
            crate::field_from_hex_string(
                "0x0e2ceb1f8fde5f80be1f41bd239fabdc2f6133a6a98920a55c42891c3a925152",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T16_PARAMS, &input, &expected);
    }
}
