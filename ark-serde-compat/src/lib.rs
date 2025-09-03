use std::str::FromStr;

use ark_ec::{AffineRepr as _, CurveGroup as _};
use serde::{Serializer, de, ser::SerializeSeq as _};

pub mod groth16;

#[derive(Debug, thiserror::Error)]
pub enum SerializationError {
    #[error("invalid data")]
    InvalidData,
}

/// Serializes element of G1 using serializer
pub fn serialize_bn254_g1<S: Serializer>(
    p: &ark_bn254::G1Affine,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let strings = g1_to_strings_projective(p);
    let mut seq = ser.serialize_seq(Some(strings.len()))?;
    for ele in strings {
        seq.serialize_element(&ele)?;
    }
    seq.end()
}

/// Serializes element of G2 using serializer
pub fn serialize_bn254_g2<S: Serializer>(
    p: &ark_bn254::G2Affine,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let (x, y) = (p.x, p.y);
    let mut x_seq = ser.serialize_seq(Some(3))?;
    x_seq.serialize_element(&vec![x.c0.to_string(), x.c1.to_string()])?;
    x_seq.serialize_element(&vec![y.c0.to_string(), y.c1.to_string()])?;
    x_seq.serialize_element(&vec!["1", "0"])?;
    x_seq.end()
}

pub fn serialize_babyjubjub_affine<S: Serializer>(
    p: &ark_babyjubjub::EdwardsAffine,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let (x, y) = (p.x, p.y);
    let mut x_seq = ser.serialize_seq(Some(2))?;
    x_seq.serialize_element(&x.to_string())?;
    x_seq.serialize_element(&y.to_string())?;
    x_seq.end()
}

pub fn serialize_babyjubjub_scalar<S: Serializer>(
    p: &ark_babyjubjub::Fr,
    ser: S,
) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&p.to_string())
}

pub fn serialize_babyjubjub_base<S: Serializer>(
    p: &ark_babyjubjub::Fq,
    ser: S,
) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&p.to_string())
}

pub fn serialize_bn254_gt<S: Serializer>(p: &ark_bn254::Fq12, ser: S) -> Result<S::Ok, S::Error> {
    let a = p.c0;
    let b = p.c1;
    let aa = a.c0;
    let ab = a.c1;
    let ac = a.c2;
    let ba = b.c0;
    let bb = b.c1;
    let bc = b.c2;
    let a = vec![
        vec![aa.c0.to_string(), aa.c1.to_string()],
        vec![ab.c0.to_string(), ab.c1.to_string()],
        vec![ac.c0.to_string(), ac.c1.to_string()],
    ];
    let b = vec![
        vec![ba.c0.to_string(), ba.c1.to_string()],
        vec![bb.c0.to_string(), bb.c1.to_string()],
        vec![bc.c0.to_string(), bc.c1.to_string()],
    ];
    let mut seq = ser.serialize_seq(Some(2))?;
    seq.serialize_element(&a)?;
    seq.serialize_element(&b)?;
    seq.end()
}

pub fn serialize_bn254_g1_sequence<S: Serializer>(
    ps: &[ark_bn254::G1Affine],
    ser: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(ps.len()))?;
    for p in ps {
        seq.serialize_element(&g1_to_strings_projective(p))?;
    }
    seq.end()
}

pub fn serialize_babyjubjub_base_sequence<S: Serializer>(
    ps: &[ark_babyjubjub::Fq],
    ser: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(ps.len()))?;
    for p in ps {
        seq.serialize_element(&p.to_string())?;
    }
    seq.end()
}

pub fn deserialize_bn254_g1<'de, D>(deserializer: D) -> Result<ark_bn254::G1Affine, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254G1Visitor)
}

pub fn deserialize_bn254_g2<'de, D>(deserializer: D) -> Result<ark_bn254::G2Affine, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254G2Visitor)
}

pub fn deserialize_babyjubjub_affine<'de, D>(
    deserializer: D,
) -> Result<ark_babyjubjub::EdwardsAffine, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(BabyJubJubAffineVisitor)
}

pub fn deserialize_babyjubjub_scalar<'de, D>(
    deserializer: D,
) -> Result<ark_babyjubjub::Fr, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_str(BabyJubJubScalarVisitor)
}

pub fn deserialize_babyjubjub_base<'de, D>(deserializer: D) -> Result<ark_babyjubjub::Fq, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_str(BabyJubJubBaseVisitor)
}

pub fn deserialize_bn254_gt<'de, D>(deserializer: D) -> Result<ark_bn254::Fq12, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254GtVisitor)
}

pub fn deserialize_bn254_g1_sequence<'de, D>(
    deserializer: D,
) -> Result<Vec<ark_bn254::G1Affine>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254G1SeqVisitor)
}

pub fn deserialize_babyjubjub_base_sequence<'de, D>(
    deserializer: D,
) -> Result<Vec<ark_babyjubjub::Fq>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(BabyJubJubBaseSeqVisitor)
}

fn g1_to_strings_projective(p: &ark_bn254::G1Affine) -> Vec<String> {
    if let Some((x, y)) = p.xy() {
        vec![x.to_string(), y.to_string(), "1".to_owned()]
    } else {
        //point at infinity
        vec!["0".to_owned(), "1".to_owned(), "0".to_owned()]
    }
}

fn g1_from_strings_projective(
    x: &str,
    y: &str,
    z: &str,
) -> Result<ark_bn254::G1Affine, SerializationError> {
    let x = ark_bn254::Fq::from_str(x).map_err(|_| SerializationError::InvalidData)?;
    let y = ark_bn254::Fq::from_str(y).map_err(|_| SerializationError::InvalidData)?;
    let z = ark_bn254::Fq::from_str(z).map_err(|_| SerializationError::InvalidData)?;
    let p = ark_bn254::G1Projective::new_unchecked(x, y, z).into_affine();
    if p.is_zero() {
        return Ok(p);
    }
    if !p.is_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    Ok(p)
}

fn g2_from_strings_projective(
    x0: &str,
    x1: &str,
    y0: &str,
    y1: &str,
    z0: &str,
    z1: &str,
) -> Result<ark_bn254::G2Affine, SerializationError> {
    let x0 = ark_bn254::Fq::from_str(x0).map_err(|_| SerializationError::InvalidData)?;
    let x1 = ark_bn254::Fq::from_str(x1).map_err(|_| SerializationError::InvalidData)?;
    let y0 = ark_bn254::Fq::from_str(y0).map_err(|_| SerializationError::InvalidData)?;
    let y1 = ark_bn254::Fq::from_str(y1).map_err(|_| SerializationError::InvalidData)?;
    let z0 = ark_bn254::Fq::from_str(z0).map_err(|_| SerializationError::InvalidData)?;
    let z1 = ark_bn254::Fq::from_str(z1).map_err(|_| SerializationError::InvalidData)?;

    let x = ark_bn254::Fq2::new(x0, x1);
    let y = ark_bn254::Fq2::new(y0, y1);
    let z = ark_bn254::Fq2::new(z0, z1);
    let p = ark_bn254::G2Projective::new_unchecked(x, y, z).into_affine();
    if p.is_zero() {
        return Ok(p);
    }
    if !p.is_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    Ok(p)
}

fn babyjubjub_affine_from_strings(
    x: &str,
    y: &str,
) -> Result<ark_babyjubjub::EdwardsAffine, SerializationError> {
    let x = ark_babyjubjub::Fq::from_str(x).map_err(|_| SerializationError::InvalidData)?;
    let y = ark_babyjubjub::Fq::from_str(y).map_err(|_| SerializationError::InvalidData)?;
    let p = ark_babyjubjub::EdwardsAffine::new_unchecked(x, y);
    if p.is_zero() {
        return Ok(p);
    }
    if !p.is_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    Ok(p)
}

struct Bn254G1Visitor;

impl<'de> de::Visitor<'de> for Bn254G1Visitor {
    type Value = ark_bn254::G1Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 3 strings, representing a projective point on G1")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else {
            g1_from_strings_projective(&x, &y, &z)
                .map_err(|_| de::Error::custom("Invalid projective point on G1.".to_owned()))
        }
    }
}

struct Bn254G2Visitor;

impl<'de> de::Visitor<'de> for Bn254G2Visitor {
    type Value = ark_bn254::G2Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter
            .write_str("a sequence of 3 sequences, representing a projective point on G2. The 3 sequences each consist of two strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else if x.len() != 2 {
            Err(de::Error::custom(format!(
                "x coordinates need two field elements for G2, but got {}",
                x.len()
            )))
        } else if y.len() != 2 {
            Err(de::Error::custom(format!(
                "y coordinates need two field elements for G2, but got {}",
                y.len()
            )))
        } else if z.len() != 2 {
            Err(de::Error::custom(format!(
                "z coordinates need two field elements for G2, but got {}",
                z.len()
            )))
        } else {
            g2_from_strings_projective(&x[0], &x[1], &y[0], &y[1], &z[0], &z[1])
                .map_err(|_| de::Error::custom("Invalid projective point on G2.".to_owned()))
        }
    }
}

struct BabyJubJubScalarVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubScalarVisitor {
    type Value = ark_babyjubjub::Fr;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sting representing a babyjubjub scalar field point")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        ark_babyjubjub::Fr::from_str(v).map_err(|_| E::custom("Invalid data"))
    }
}

struct BabyJubJubBaseVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubBaseVisitor {
    type Value = ark_babyjubjub::Fq;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sting representing a babyjubjub base field point")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        ark_babyjubjub::Fq::from_str(v).map_err(|_| E::custom("Invalid data"))
    }
}

struct BabyJubJubAffineVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubAffineVisitor {
    type Value = ark_babyjubjub::EdwardsAffine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 2 strings, representing a affine babyjubjub point")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected babyjubjub affine coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected babyjubjub affine coordinates but y coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(3, &self))
        } else {
            babyjubjub_affine_from_strings(&x, &y)
                .map_err(|_| de::Error::custom("Invalid affine point on babyjubjub.".to_owned()))
        }
    }
}

struct Bn254GtVisitor;

impl<'de> de::Visitor<'de> for Bn254GtVisitor {
    type Value = ark_bn254::Fq12;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(
                "An element of Fq12 represented as string with radix 10. Must be a sequence of form [[[String; 2]; 3]; 2]."
            )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq
            .next_element::<Vec<Vec<String>>>()?
            .ok_or(de::Error::custom(
                "expected elements target group in {} as sequence of sequences",
            ))?;
        let y = seq
            .next_element::<Vec<Vec<String>>>()?
            .ok_or(de::Error::custom(
                "expected elements target group in {} as sequence of sequences",
            ))?;
        if x.len() != 3 || y.len() != 3 {
            Err(de::Error::custom(
                "need three elements for cubic extension field in {}",
            ))
        } else {
            let c0 = cubic_extension_field_from_vec(x).map_err(|_| {
                de::Error::custom("InvalidData for target group (cubic extension field)")
            })?;
            let c1 = cubic_extension_field_from_vec(y).map_err(|_| {
                de::Error::custom("InvalidData for target group (cubic extension field)")
            })?;
            Ok(ark_bn254::Fq12::new(c0, c1))
        }
    }
}

#[inline]
fn cubic_extension_field_from_vec(
    strings: Vec<Vec<String>>,
) -> Result<ark_bn254::Fq6, SerializationError> {
    if strings.len() != 3 {
        Err(SerializationError::InvalidData)
    } else {
        let c0 = quadratic_extension_field_from_vec(&strings[0])?;
        let c1 = quadratic_extension_field_from_vec(&strings[1])?;
        let c2 = quadratic_extension_field_from_vec(&strings[2])?;
        Ok(ark_bn254::Fq6::new(c0, c1, c2))
    }
}

#[inline]
fn quadratic_extension_field_from_vec(
    strings: &[String],
) -> Result<ark_bn254::Fq2, SerializationError> {
    if strings.len() != 2 {
        Err(SerializationError::InvalidData)
    } else {
        let c0 =
            ark_bn254::Fq::from_str(&strings[0]).map_err(|_| SerializationError::InvalidData)?;
        let c1 =
            ark_bn254::Fq::from_str(&strings[1]).map_err(|_| SerializationError::InvalidData)?;
        Ok(ark_bn254::Fq2::new(c0, c1))
    }
}

struct Bn254G1SeqVisitor;

impl<'de> de::Visitor<'de> for Bn254G1SeqVisitor {
    type Value = Vec<ark_bn254::G1Affine>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(
            "a sequence of elements representing projective points on G1, which in turn are sequences of three elements on the BaseField of the Curve.",
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(point) = seq.next_element::<Vec<String>>()? {
            //check if there are no more elements
            if point.len() != 3 {
                return Err(de::Error::invalid_length(point.len(), &self));
            } else {
                values.push(
                    g1_from_strings_projective(&point[0], &point[1], &point[2]).map_err(|_| {
                        de::Error::custom("Invalid projective point on G1.".to_owned())
                    })?,
                );
            }
        }
        Ok(values)
    }
}

struct BabyJubJubBaseSeqVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubBaseSeqVisitor {
    type Value = Vec<ark_babyjubjub::Fq>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of elements representing babyjubjub scalar points.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(v) = seq.next_element::<String>()? {
            values.push(
                ark_babyjubjub::Fq::from_str(&v).map_err(|_| de::Error::custom("Invalid data"))?,
            );
        }
        Ok(values)
    }
}
