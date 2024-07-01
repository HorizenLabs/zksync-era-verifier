// Copyright 2024, The Horizen Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Provide functions for deserialize fields and point for bn256 curves.

use std::mem::{size_of, size_of_val};

use bellman::{
    bn256::{Bn256, Fq, FqRepr, Fr, FrRepr},
    CurveAffine, Engine, GroupDecodingError, PrimeField, PrimeFieldDecodingError, PrimeFieldRepr,
};
use snafu::Snafu;

type G1 = <Bn256 as Engine>::G1Affine;
/// `Fq` serialize size in bytes
pub const FQ_SIZE: usize = size_of::<FqRepr>();
/// `Fr` serialize size in bytes
pub const FR_SIZE: usize = size_of::<FrRepr>();
/// `G1` point serialize size in bytes
pub const G1_SIZE: usize = 2 * FQ_SIZE;

/// Deserialization error.
#[derive(Debug, Snafu)]
pub enum DeserializeError {
    #[snafu(display("Not enough data: {provided}[{requested}]"))]
    NotEnoughData { provided: usize, requested: usize },
    #[snafu(display("Invalid Scalar"))]
    InvalidScalar {
        #[snafu(source)]
        cause: PrimeFieldDecodingError,
    },
    #[snafu(display("Invalid Point"))]
    InvalidPoint {
        #[snafu(source)]
        cause: GroupDecodingError,
    },
}

/// Deserialize a `Fq` field from a slice of bytes.
///
/// Errors:
///  - `DeserializeError::NotEnoughData` if the slice is too short.
///  - `DeserializeError::InvalidScalar` if the value is invalid.
///
pub fn fq(bytes: &[u8]) -> Result<Fq, DeserializeError> {
    let mut repr = FqRepr::default();
    repr.read_be(bytes)
        .map_err(|_| DeserializeError::NotEnoughData {
            provided: bytes.len(),
            requested: FQ_SIZE,
        })?;
    Fq::from_repr(repr).map_err(|cause| DeserializeError::InvalidScalar { cause })
}

/// Deserialize a `Fr` field from a slice of bytes.
///
/// Errors:
///  - `DeserializeError::NotEnoughData` if the slice is too short.
///  - `DeserializeError::InvalidScalar` if the value is invalid.
///
pub fn fr(bytes: &[u8]) -> Result<Fr, DeserializeError> {
    let mut repr = FrRepr::default();
    repr.read_be(bytes)
        .map_err(|_| DeserializeError::NotEnoughData {
            provided: bytes.len(),
            requested: FR_SIZE,
        })?;
    Fr::from_repr(repr).map_err(|cause| DeserializeError::InvalidScalar { cause })
}

/// Deserialize a `G1` point from a slice of bytes.
///
/// Errors:
///  - `DeserializeError::NotEnoughData` if the slice is too short.
///  - `DeserializeError::InvalidPoint` if the point is invalid (i.e. not in curve).
///
pub fn g1(bytes: &[u8]) -> Result<G1, DeserializeError> {
    if bytes.len() < 2 * size_of::<Fq>() {
        return Err(DeserializeError::NotEnoughData {
            provided: bytes.len(),
            requested: G1_SIZE,
        });
    }
    let x = fq(&bytes[0..FQ_SIZE])?;
    let y = fq(&bytes[FQ_SIZE..G1_SIZE])?;
    <<Bn256 as Engine>::G1Affine as CurveAffine>::from_xy_checked(x, y)
        .map_err(|cause| DeserializeError::InvalidPoint { cause })
}

/// A deserializer for `Fr`, `Fq` fields and `G1` points from bytes stream.
pub struct Deserializer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Deserializer<'a> {
    /// A new deserializer from a slice of bytes.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a `Fq` field from the stream if any.
    #[allow(dead_code)]
    pub fn fq(&mut self) -> Result<Fq, DeserializeError> {
        fq(&self.data[self.pos..]).inspect(|v| {
            self.pos += size_of_val(v);
        })
    }

    /// Read a `Fr` field from the stream if any.
    pub fn fr(&mut self) -> Result<Fr, DeserializeError> {
        fr(&self.data[self.pos..]).inspect(|v| {
            self.pos += size_of_val(v);
        })
    }

    /// Read a `G1` point from the stream if any.
    pub fn g1(&mut self) -> Result<G1, DeserializeError> {
        g1(&self.data[self.pos..]).inspect(|_v| {
            self.pos += G1_SIZE;
        })
    }
}

#[cfg(test)]
mod should {
    use bellman::Field;
    use hex_literal::hex;
    use rstest::rstest;

    use super::*;

    fn s_fr(s: &str) -> Fr {
        Fr::from_str(s).unwrap()
    }

    #[rstest]
    #[case::valid(&hex!("221cc01cc33c432ab679319c724544616069b0d6f4df5f537ec36887deead963"), Some(s_fr("15429434480382629811076398309856967832821062719195495222824635002227056630115")))]
    #[case::should_accept_more_bytes(&hex!("221cc01cc33c432ab679319c724544616069b0d6f4df5f537ec36887deead96300000000"), Some(s_fr("15429434480382629811076398309856967832821062719195495222824635002227056630115")))]
    #[case::zero(&hex!("0000000000000000000000000000000000000000000000000000000000000000"), Some(Fr::zero()))]
    #[should_panic(expected = "NotEnoughData")]
    #[case::not_enough_data(&hex!("6069b0d6f4df5f537ec36887deead963"), None)]
    #[should_panic(expected = "NotInField")]
    #[case::not_in_field(&hex!("F21cc01cc33c432ab679319c724544616069b0d6f4df5f537ec36887deead963"), None)]
    fn parse_fr(#[case] data: &[u8], #[case] expected: Option<Fr>) {
        match (fr(&data).unwrap(), expected) {
            (value, Some(expected)) => assert_eq!(expected, value),
            _ => {}
        }
    }

    fn s_fq(s: &str) -> Fq {
        Fq::from_str(s).unwrap()
    }

    #[rstest]
    #[case::valid(&hex!("221cc01cc33c432ab679319c724544616069b0d6f4df5f537ec36887deead963"), Some(s_fq("15429434480382629811076398309856967832821062719195495222824635002227056630115")))]
    #[case::should_accept_more_bytes(&hex!("221cc01cc33c432ab679319c724544616069b0d6f4df5f537ec36887deead96300000000"), Some(s_fq("15429434480382629811076398309856967832821062719195495222824635002227056630115")))]
    #[case::zero(&hex!("0000000000000000000000000000000000000000000000000000000000000000"), Some(Fq::zero()))]
    #[should_panic(expected = "NotEnoughData")]
    #[case::not_enough_data(&hex!("6069b0d6f4df5f537ec36887deead963"), None)]
    #[should_panic(expected = "NotInField")]
    #[case::not_in_field(&hex!("F21cc01cc33c432ab679319c724544616069b0d6f4df5f537ec36887deead963"), None)]
    fn parse_fq(#[case] data: &[u8], #[case] expected: Option<Fq>) {
        match (fq(&data).unwrap(), expected) {
            (value, Some(expected)) => assert_eq!(expected, value),
            _ => {}
        }
    }

    fn s_g1(sx: &str, sy: &str) -> G1 {
        let x = s_fq(sx);
        let y = s_fq(sy);
        <<Bn256 as Engine>::G1Affine as CurveAffine>::from_xy_checked(x, y).unwrap()
    }

    #[rstest]
    #[case::valid(&hex!(r#"02c6cf2fd56edca1f17f406cceef3de1c99bba6e499ed96ef4f453af011257c4
                           20944a838b2cd133a414ae6882fd8cc0dfb7daa14540d796ab937f65479beaca"#), 
                Some(s_g1("1255891367081055920421831970473576998260404123634067957691644006450968287172", 
                    "14736018795891246473445454453202444481849883402862866572040903618647765543626")))]
    #[case::should_accept_more_bytes(&hex!(r#"02c6cf2fd56edca1f17f406cceef3de1c99bba6e499ed96ef4f453af011257c4
                           20944a838b2cd133a414ae6882fd8cc0dfb7daa14540d796ab937f65479beaca
                           000000000000"#), 
                Some(s_g1("1255891367081055920421831970473576998260404123634067957691644006450968287172", 
                    "14736018795891246473445454453202444481849883402862866572040903618647765543626"))
                )]
    #[case::zero(&hex!(r#"0000000000000000000000000000000000000000000000000000000000000000
                           0000000000000000000000000000000000000000000000000000000000000000"#), 
                Some(s_g1("0", 
                    "0"))
                )]
    #[should_panic(expected = "NotEnoughData")]
    #[case::not_enough_data(&hex!("6069b0d6f4df5f537ec36887deead963"), None)]
    #[should_panic(expected = "NotEnoughData")]
    #[case::not_enough_data(&hex!("02c6cf2fd56edca1f17f406cceef3de1c99bba6e499ed96ef4f453af011257c4
                            6069b0d6f4df5f537ec36887deead963"), None)]
    #[should_panic(expected = "InvalidPoint")]
    #[case::not_a_valid_point(&hex!(r#"02c6cf2fd56edca1f17f406cceef3de1c99bba6e499ed96ef4f453af011257c4
                           20944a838b2cd133a414ae6882fd8cc0dfb7daa14540d796ab937f65479b0000"#), None)]
    fn parse_g1(#[case] data: &[u8], #[case] expected: Option<G1>) {
        match (g1(&data).unwrap(), expected) {
            (value, Some(expected)) => assert_eq!(expected, value),
            _ => {}
        }
    }

    #[test]
    fn deserialize_bytes_slice() {
        let data = hex!(
            "
            0000000000000000000000000000000000000000000000000000000000000002
            0000000000000000000000000000000000000000000000000000000000000003
            02c6cf2fd56edca1f17f406cceef3de1c99bba6e499ed96ef4f453af011257c4
            20944a838b2cd133a414ae6882fd8cc0dfb7daa14540d796ab937f65479beaca
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000"
        );
        let mut deserializer = Deserializer::new(&data);

        assert_eq!(deserializer.fr().unwrap(), s_fr("2"));
        assert_eq!(deserializer.fq().unwrap(), s_fq("3"));
        assert_eq!(
            deserializer.g1().unwrap(),
            s_g1(
                "1255891367081055920421831970473576998260404123634067957691644006450968287172",
                "14736018795891246473445454453202444481849883402862866572040903618647765543626"
            )
        );
        assert_eq!(deserializer.g1().unwrap(), s_g1("0", "0"));
        assert_eq!(2, deserializer.len());
    }
}
