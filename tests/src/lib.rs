// Copyright 2024, Horizen Labs, Inc.
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

//! Some utilities to parse json data for testing

use bellman::bn256::Fr;
use serde::Deserialize;

pub use pretty_assertions::{assert_eq, assert_ne, assert_str_eq};

/// A wrapper for deserialize json that contains a eth proof and public input
#[derive(Deserialize)]
pub struct ProofData {
    #[serde(default)]
    source: String,
    proof: Vec<String>,
    inputs: Vec<String>,
}

impl ProofData {
    /// Returns the source of the proof (just a note if it's provided)
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Return the bytes of the proof
    pub fn proof(&self) -> impl Iterator<Item = u8> + '_ {
        self.proof
            .iter()
            .map(|s| ethereum_types::U256::from_dec_str(s))
            .map(Result::unwrap)
            .map(|u256| {
                let mut bytes = [0; 32];
                u256.to_big_endian(&mut bytes[..]);
                bytes
            })
            .flat_map(|bytes| bytes.into_iter())
    }

    /// Return the inputs bytes
    pub fn inputs_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.inputs
            .iter()
            .map(|s| ethereum_types::U256::from_dec_str(s))
            .map(Result::unwrap)
            .map(|u256| {
                let mut bytes = [0; 32];
                u256.to_big_endian(&mut bytes[..]);
                bytes
            })
            .flat_map(|bytes| bytes.into_iter())
    }

    /// Return the inputs field
    pub fn inputs(&self) -> Vec<Fr> {
        let bytes = self.inputs_bytes().collect::<Vec<_>>();
        bytes
            .chunks_exact(deserialize::FR_SIZE)
            .map(deserialize::fr)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }
}

/// Assert that two vk are the same.
#[macro_export]
macro_rules! assert_vk_eq {
    ($left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                use $crate::assert_eq;
                assert_eq!(left_val.n, right_val.n, "n");
                assert_eq!(left_val.num_inputs, right_val.num_inputs, "num_inputs");
                assert_eq!(left_val.state_width, right_val.state_width, "state_width");
                assert_eq!(
                    left_val.num_witness_polys, right_val.num_witness_polys,
                    "num_witness_polys"
                );
                assert_eq!(
                    left_val.gate_setup_commitments, right_val.gate_setup_commitments,
                    "gate_setup_commitments"
                );
                assert_eq!(
                    left_val.gate_selectors_commitments, right_val.gate_selectors_commitments,
                    "gate_selectors_commitments"
                );
                assert_eq!(
                    left_val.permutation_commitments, right_val.permutation_commitments,
                    "permutation_commitments"
                );
                assert_eq!(
                    left_val.total_lookup_entries_length, right_val.total_lookup_entries_length,
                    "total_lookup_entries_length"
                );
                assert_eq!(
                    left_val.lookup_selector_commitment, right_val.lookup_selector_commitment,
                    "lookup_selector_commitment"
                );
                assert_eq!(
                    left_val.lookup_tables_commitments, right_val.lookup_tables_commitments,
                    "lookup_tables_commitments"
                );
                assert_eq!(
                    left_val.lookup_table_type_commitment, right_val.lookup_table_type_commitment,
                    "lookup_table_type_commitment"
                );
                assert_eq!(
                    left_val.non_residues, right_val.non_residues,
                    "non_residues"
                );
                assert_eq!(left_val.g2_elements, right_val.g2_elements, "g2_elements");
            }
        }
    };
}
