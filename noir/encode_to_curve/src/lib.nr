use poseidon2::bn254::perm::x5_3;

fn mux1(cond: Field, if_false: Field, if_true: Field) -> Field {
    cond * (if_true - if_false) + if_false
}

fn inverse_or_zero(x: Field) -> Field {
    if x == 0 {
        0
    } else {
        1 / x
    }
}

/// An implementation of hash_to_field based on https://www.rfc-editor.org/rfc/rfc9380.html.
/// Since we use poseidon as the hash function, this automatically ensures the property that the output is a uniformly random field element, without needing to sample extra output and reduce mod p.
fn hash_to_field(input: Field) -> Field {
    // We return element 1; element 0 is the capacity of the sponge
    x5_3([0, input, 0])[1]
}

// Copied from <https://github.com/noir-lang/ec/blob/master/src/lib.nr>
// Power function of two Field arguments of arbitrary size.
// Adapted from std::field::pow_32.
fn pow(x: Field, y: Field) -> Field {
    let mut r = 1 as Field;
    let b: [u1; 254] = y.to_le_bits();

    for i in 0..254 {
        r *= r;
        r *= (b[254 - 1 - i] as Field) * x + (1 - b[254 - 1 - i] as Field);
    }

    r
}
// Copied from <https://github.com/noir-lang/ec/blob/master/src/lib.nr>
global C1: u32 = 28;
global C3: Field = 40770029410420498293352137776570907027550720424234931066070132305055;
global C5: Field = 19103219067921713944291392827692070036145651957329286315305642004821462161904;
// Tonelli-Shanks algorithm for computing the square root of a Field element.
// Requires C1 = max{c: 2^c divides (p-1)}, where p is the order of Field
// as well as C3 = (C2 - 1)/2, where C2 = (p-1)/(2^c1),
// and C5 = ZETA^C2, where ZETA is a non-square element of Field.
// These are pre-computed above as globals.
unconstrained fn sqrt(x: Field) -> Field {
    let mut z = pow(x, C3);
    let mut t = z * z * x;
    z *= x;
    let mut b = t;
    let mut c = C5;

    for i in 0..(C1 - 1) {
        for _j in 1..(C1 - i - 1) {
            b *= b;
        }

        z *= if b == 1 { 1 } else { c };

        c *= c;

        t *= if b == 1 { 1 } else { c };

        b = t;
    }

    z
}

unconstrained fn legendre(x: Field) -> Field {
    if x == 0 {
        0
    } else {
        pow(x, (0 - 1) / 2)
    }
}

fn is_quadratic_residue_or_zero(a: Field) -> bool {
    // SAFETY:
    // Constraint strategy, from (<https://eprint.iacr.org/2021/984.pdf>, page 4):
    // Let l = Legendre(a) in { -1, 0, 1 }.
    // Introduce a witness b intended to be a square root:
    // Enforce: l(l-1)(b^2 - n*a) + (l+1)(b^2 - a) == 0
    // For l =  1: (l(l-1)) = 0 and (l+1) = 2 => b^2 = a
    // For l = -1: (l(l-1)) = 2 and (l+1) = 0 => b^2 = n*a
    // For l =  0: (l(l-1)) = 0 and (l+1) = 1 => b^2 = a (which forces a to be 0 or a quadratic residue)
    let l = unsafe { legendre(a) };
    assert(l * (l - 1) * (l + 1) == 0, "l must be in {-1,0,1}"); // l in {-1,0,1}

    // n is the smallest non-quadratic residue in BN254
    let n = 5;
    let na = n * a;
    let sqrt_in = mux1((l == -1) as Field, a, na);
    // SAFETY: We constrain b to be the square root of either na or a, depending on the value of l.
    let b = unsafe { sqrt(sqrt_in) };

    let s_na = l * (l - 1); // 0 when l in {0,1}, 2 when l = -1
    let s_a = l + 1; // 0 when l = -1, 1 when l = 0, 2 when l = 1

    let b2 = b * b;
    let c_na = b2 - na;
    let c_a = b2 - a;
    assert(s_na * c_na + s_a * c_a == 0, "b must be a square root of na or a");
    l != -1
}

/// Currently implemented using the internal sgn0 function of Field.
fn sign_0(x: Field) -> bool {
    x.sgn0() == 1
}

/// Maps the input to a point on the Montgomery curve, without anyone knowing the DLOG of the curve point.
///
/// Returns the s and t coordinates of the point on the Montgomery curve.
///
/// let the Montgomery curve be defined by the equation K*t^2 = s^3 + J*s^2 + s.
/// We follow the Elligator2 mapping as described in https://www.rfc-editor.org/rfc/rfc9380.html#name-elligator-2-method.
fn map_to_curve_elligator2(input: Field) -> (Field, Field) {
    // Elligator2 mapping for Baby Jubjub curve
    // Based on the implementation in Circom: https://github.com/TaceoLabs/nullifier-oracle-service/blob/491416de204dcad8d46ee1296d59b58b5be54ed9/circom/encode_to_curve_babyjj/encode_to_curve_babyjj.circom
    let k = 1;
    let c1 = 168698;
    let c2 = 1;

    let z = 5;
    let tv1_0 = z * input * input;
    let e = tv1_0 == -1;
    let tv1 = mux1(e as Field, tv1_0, 0);
    let x1 = inverse_or_zero(tv1 + 1) * -c1;

    let gx1_0 = (x1 + c1) * x1;
    let gx1 = (gx1_0 + c2) * x1;
    let x2 = -x1 - c1;
    let gx2 = tv1 * gx1;
    let e2 = is_quadratic_residue_or_zero(gx1);

    let x = mux1(e2 as Field, x2, x1);
    let y2 = mux1(e2 as Field, gx2, gx1);

    // SAFETY: We constrain y to be a square root of y2 below
    let y = unsafe { sqrt(y2) };
    assert(y * y == y2, "y must be a square root of y2");

    let e3 = sign_0(y);

    let xor = e2 ^ e3;

    let multiplication = mux1(xor as Field, 1, -1);
    let y_1 = y * multiplication;

    (x * k, y_1 * k)
}

fn relational_map_mont_to_twisted_edwards_babyjubjub(s: Field, t: Field) -> (Field, Field) {
    let tv1 = s + 1;
    let tv2 = inverse_or_zero(tv1 * t);
    let v = tv1 * tv2;
    let w = tv2 * t;
    let tv11 = s - 1;
    let e = tv2 == 0;
    (s * v, mux1(e as Field, w * tv11, 1))
}

fn map_to_curve_twisted_edwards_babyjubjub(input: Field) -> (Field, Field) {
    let (s, t) = map_to_curve_elligator2(input);
    relational_map_mont_to_twisted_edwards_babyjubjub(s, t)
}

fn clear_cofactor_babyjubjub(x: Field, y: Field) -> babyjubjub::BabyJubJubPoint {
    let p = babyjubjub::BabyJubJubPoint::new_unchecked(x, y);
    p.double().double().double()
}

pub fn encode_to_curve_babyjubjub(input: Field) -> babyjubjub::BabyJubJubPoint {
    let u = hash_to_field(input);
    let (x, y) = map_to_curve_twisted_edwards_babyjubjub(u);
    clear_cofactor_babyjubjub(x, y)
}

mod tests {
    use super::{encode_to_curve_babyjubjub, map_to_curve_elligator2};
    #[test]
    fn kat_test() {
        let kat1 = encode_to_curve_babyjubjub(0);
        assert(
            kat1.xy()
                == (
                    20933827970802813890983825285326248243008219406120265623912040617116488051168,
                    19221830974981021604074333064965073057369542973805695443932626741929482323481,
                ),
        );
        let kat2 = encode_to_curve_babyjubjub(1);
        assert(
            kat2.xy()
                == (
                    158003743186178317583285349076672373866032857213932356251773095567170960213,
                    4814651661221091094003361804145731078627371241787264107209666662974858819435,
                ),
        );
        let kat3 = encode_to_curve_babyjubjub(-1);
        assert(
            kat3.xy()
                == (
                    1551705331698544401524786606720811740181943945870244569202198367044300364404,
                    20918696086212258109716309157665435087956178115434976279417465423469312201822,
                ),
        );
        let kat4 = encode_to_curve_babyjubjub(0x42);
        assert(
            kat4.xy()
                == (
                    5520721918672064917347280398526519562725607465061028485851804404263332149374,
                    15552952328295689847327188987393079505308628175404295821602016444687698081549,
                ),
        );
    }

    #[test]
    fn map_to_curve_tests() {
        let kat1 = map_to_curve_elligator2(
            0x2e5c8c8ff53da47080c341f261d1a10c1d54f6650b90bbed9dd30198ca1256b3,
        );
        assert(
            kat1
                == (
                    175237875522834448155549773453859181418677905226545111199128371026771239667,
                    21093709385442275369448476304363512163107465754712817413145095532362233379686,
                ),
        );
        let kat2 = map_to_curve_elligator2(0);
        assert(kat2 == (0, 0));
    }

    #[test]
    fn quadratic_residue_tests() {
        assert(super::is_quadratic_residue_or_zero(0) == true);
        assert(super::is_quadratic_residue_or_zero(1) == true);
        assert(super::is_quadratic_residue_or_zero(2) == true);
        assert(super::is_quadratic_residue_or_zero(3) == true);
        assert(super::is_quadratic_residue_or_zero(4) == true);
        assert(super::is_quadratic_residue_or_zero(5) == false);
        assert(super::is_quadratic_residue_or_zero(5 * 5) == true);
        assert(super::is_quadratic_residue_or_zero(5 * 5 * 5) == false);
        assert(super::is_quadratic_residue_or_zero(-5) == false);
        assert(super::is_quadratic_residue_or_zero(7) == false);
        assert(super::is_quadratic_residue_or_zero(11) == false);
        assert(super::is_quadratic_residue_or_zero(42) == false);
        assert(super::is_quadratic_residue_or_zero(-1) == true);
    }

    #[test]
    fn rational_map_tests() {
        let kat1 = super::relational_map_mont_to_twisted_edwards_babyjubjub(
            175237875522834448155549773453859181418677905226545111199128371026771239667,
            794533486396999852797929440893762925440898645703216930553108654213575115931,
        );
        assert(
            kat1
                == (
                    19749237763777877504811025958859187282736077178612498967835952987338546424382,
                    9825651499528233657748386613879383508828535951494059213535798845190111515722,
                ),
        );
    }

    #[test]
    fn sign_0_tests() {
        assert(super::sign_0(0) == false);
        assert(super::sign_0(1) == true);
        assert(super::sign_0(2) == false);
        assert(super::sign_0(3) == true);
        assert(super::sign_0(4) == false);
        assert(super::sign_0(-1) == false);
        assert(super::sign_0(-2) == true);
    }

    #[test]
    fn hash_to_field_tests() {
        let kat1 = super::hash_to_field(42);
        assert(kat1 == 0x2e5c8c8ff53da47080c341f261d1a10c1d54f6650b90bbed9dd30198ca1256b3);
    }

    #[test]
    fn clear_cofactor_babyjubjub_tests() {
        assert(
            super::clear_cofactor_babyjubjub(
                19749237763777877504811025958859187282736077178612498967835952987338546424382,
                9825651499528233657748386613879383508828535951494059213535798845190111515722,
            )
                .xy()
                == (
                    19639628802331067714920142964194687338561819679258049812441592321105943536842,
                    11346329236507494865585709204927959305406795872019529850625216399990666158973,
                ),
        );
        assert(super::clear_cofactor_babyjubjub(0, 1).xy() == (0, 1));
    }

}
