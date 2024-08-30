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

use tests::ProofData;
use zksync_era_verifier::{default_eth_vk, deserialize_eth_proof, verify, ZkSyncEthProof};

#[test]
fn verify_proof() {
    let proof_data = serde_json::from_reader::<_, ProofData>(
        std::fs::File::open("./resources/proof.json").unwrap(),
    )
    .unwrap();

    let mut eth_proof: ZkSyncEthProof =
        deserialize_eth_proof(&proof_data.proof().collect::<Vec<_>>()).unwrap();
    eth_proof.inputs = proof_data.inputs();

    let vk = default_eth_vk();

    assert!(verify(&vk, &eth_proof).unwrap());
}
