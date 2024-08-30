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

use bellman::{
    bn256::{Bn256, Fr},
    plonk::better_better_cs::{
        cs::{Circuit, Gate, GateInternal},
        gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
        proof::Proof,
    },
    Engine, Field, SynthesisError,
};

use deserialize::{DeserializeError, Deserializer};

mod gates;
mod vk;

/// The type alias for the ZkSync proof on ethereum.
pub type ZkSyncEthProof = Proof<Bn256, ZkSyncSnarkEthCircuit>;
pub use vk::{default as default_eth_vk, ZkSyncEthVk};

/// The ZkSync ethereum circuit.
#[derive(Clone)]
pub struct ZkSyncSnarkEthCircuit;

impl<E: Engine> Circuit<E> for ZkSyncSnarkEthCircuit {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate {}.into_internal(),
            gates::Rescue5CustomGate {}.into_internal(),
        ])
    }

    fn synthesize<CS: bellman::plonk::better_better_cs::cs::ConstraintSystem<E> + 'static>(
        &self,
        _cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        unimplemented!("This Circuit should just be used to verify proofs")
    }
}

/// Deserialize an ethereum ZkSync proof without filling the public inputs.
///
/// The serialized proof for ethereum omit the public inputs that will be
/// given by the smart contract; in order to verify the proof, the user
/// should provide the public inputs later.
///
/// ```ignore
/// let mut proof = deserialize(&proof_bytes).unwrap();
/// proof.inputs = public_inputs;
/// ```
///
pub fn deserialize(bytes: &[u8]) -> Result<ZkSyncEthProof, DeserializeError> {
    const PROOF_N: usize = 511;
    const POLY_OPENING_DILATATION: usize = 1;
    const POLY_OPENING_INDEX: usize = 3;

    let mut d = Deserializer::new(bytes);
    let mut proof = Proof::empty();

    proof.n = PROOF_N;
    proof.inputs = vec![Fr::zero()];
    proof.state_polys_commitments = vec![d.g1()?, d.g1()?, d.g1()?, d.g1()?];
    proof.copy_permutation_grand_product_commitment = d.g1()?;

    proof.lookup_s_poly_commitment = Some(d.g1()?);
    proof.lookup_grand_product_commitment = Some(d.g1()?);
    proof.quotient_poly_parts_commitments = vec![d.g1()?, d.g1()?, d.g1()?, d.g1()?];
    proof.state_polys_openings_at_z = vec![d.fr()?, d.fr()?, d.fr()?, d.fr()?];
    proof.state_polys_openings_at_dilations =
        vec![(POLY_OPENING_DILATATION, POLY_OPENING_INDEX, d.fr()?)];

    proof.gate_selectors_openings_at_z = vec![(0, d.fr()?)];
    proof.copy_permutation_polys_openings_at_z = vec![d.fr()?, d.fr()?, d.fr()?];
    proof.copy_permutation_grand_product_opening_at_z_omega = d.fr()?;
    proof.lookup_s_poly_opening_at_z_omega = Some(d.fr()?);
    proof.lookup_grand_product_opening_at_z_omega = Some(d.fr()?);
    proof.lookup_t_poly_opening_at_z = Some(d.fr()?);
    proof.lookup_t_poly_opening_at_z_omega = Some(d.fr()?);
    proof.lookup_selector_poly_opening_at_z = Some(d.fr()?);
    proof.lookup_table_type_poly_opening_at_z = Some(d.fr()?);
    proof.quotient_poly_opening_at_z = d.fr()?;
    proof.linearization_poly_opening_at_z = d.fr()?;
    proof.opening_proof_at_z = d.g1()?;
    proof.opening_proof_at_z_omega = d.g1()?;

    Ok(proof)
}
