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

fn main() {
    // Run registered benchmarks.
    divan::main();
}
use deserialize::fr;
use tests::ProofData;
use zksync_era_verifier::{default_eth_vk, deserialize_eth_proof, verify, ZkSyncEthVk};

#[divan::bench]
fn zksync_verifier_with_default_vk() -> bool {
    fn compute(vk: ZkSyncEthVk, data: [u8; 44 * 32], pubs: [u8; 32]) -> bool {
        let mut proof = deserialize_eth_proof(&data).unwrap();
        proof.inputs = vec![fr(&pubs).unwrap()];

        verify(&vk, &proof).is_ok()
    }

    let vk = default_eth_vk();
    let proof_data = serde_json::from_reader::<_, ProofData>(
        std::fs::File::open("./resources/proof.json").unwrap(),
    )
    .unwrap();

    let proof: [u8; 44 * 32] = proof_data.proof().collect::<Vec<u8>>().try_into().unwrap();
    let inputs: [u8; 32] = proof_data
        .inputs_bytes()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    compute(
        divan::black_box(vk),
        divan::black_box(proof),
        divan::black_box(inputs),
    )
}
