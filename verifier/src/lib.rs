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

#![doc = include_str!("../../README.md")]

use bellman::{
    plonk::better_better_cs::{
        cs::{Circuit, VerificationKey},
        proof::Proof,
    },
    Engine, ScalarEngine, SynthesisError,
};

mod eth_proof;

/// Given a ethereum proof `proof` verify it against the give verification key `vk`.
///
/// ```
/// # use zksync_era_verifier::*;
/// # use tests::ProofData;
/// # let proof_data = serde_json::from_reader::<_, ProofData>(std::fs::File::open("./resources/proof.json").unwrap()).unwrap();
/// # let (proof_bytes, proof_inputs) = (proof_data.proof().collect::<Vec<_>>(), proof_data.inputs());
/// let mut proof: ZkSyncEthProof = deserialize_eth_proof(&proof_bytes).unwrap();
/// proof.inputs = proof_inputs;
/// let vk = default_eth_vk();
///
/// assert!(verify(&vk, &proof).unwrap());
///
/// ```
///
pub fn verify<E: Engine, C: Circuit<E>>(
    vk: &VerificationKey<E, C>,
    proof: &Proof<E, C>,
) -> Result<bool, SynthesisError> {
    bellman::plonk::better_better_cs::verifier::verify::<
        _,
        _,
        bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript<
            <E as ScalarEngine>::Fr,
        >,
    >(vk, proof, None)
}

pub use eth_proof::deserialize as deserialize_eth_proof;
pub use eth_proof::{default_eth_vk, ZkSyncEthProof, ZkSyncEthVk};

#[cfg(test)]
mod should {
    use super::*;
    use rstest::*;
    use tests::ProofData;

    #[fixture]
    fn proof(#[default("./resources/proof.json")] path: &str) -> ProofData {
        serde_json::from_reader::<_, ProofData>(std::fs::File::open(path).unwrap()).unwrap()
    }

    #[rstest]
    fn deserialize_eth_proof_without_errors(#[from(proof)] proof_data: ProofData) {
        let bytes = proof_data.proof().collect::<Vec<_>>();
        assert_eq!(44 * 32, bytes.len());

        let _proof: ZkSyncEthProof = deserialize_eth_proof(&bytes).unwrap();
    }

    #[rstest]
    fn verify_eth_proof(#[from(proof)] proof_data: ProofData) {
        let mut eth_proof: ZkSyncEthProof =
            deserialize_eth_proof(&proof_data.proof().collect::<Vec<_>>()).unwrap();

        eth_proof.inputs = proof_data.inputs();

        assert!(verify(&default_eth_vk(), &eth_proof).unwrap());
    }

    #[cfg(test)]
    mod reject_if {
        use super::*;

        use bellman::{bn256::Fr, Field};

        #[fixture]
        fn eth_proof(#[from(proof)] proof_data: ProofData) -> ZkSyncEthProof {
            let mut eth_proof: ZkSyncEthProof =
                deserialize_eth_proof(&proof_data.proof().collect::<Vec<_>>()).unwrap();

            eth_proof.inputs = proof_data.inputs();
            eth_proof
        }

        #[rstest]
        fn invalid_inputs(mut eth_proof: ZkSyncEthProof) {
            eth_proof.inputs[0].add_assign(&Fr::one());

            assert!(!verify(&default_eth_vk(), &eth_proof).unwrap());
        }

        #[rstest]
        fn invalid_proof(mut eth_proof: ZkSyncEthProof) {
            eth_proof
                .linearization_poly_opening_at_z
                .add_assign(&Fr::one());

            assert!(!verify(&default_eth_vk(), &eth_proof).unwrap());
        }
    }
}
