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
    plonk::better_better_cs::cs::{Gate, GateInternal, PolyIdentifier, PolynomialInConstraint},
    Engine, Field, SynthesisError,
};

/// The Rescue5 gate: Use it just for verification.
///
/// The code come from https://github.com/matter-labs/franklin-crypto/blob/snark_wrapper/src/plonk/circuit/custom_rescue_gate.rs
/// where we copy and pasted just the code needed for verification and discarded the rest. We did it in order
/// to compile the verifier in stable Rust.
#[derive(Clone, Debug, Hash, Default)]
pub struct Rescue5CustomGate;

impl<E: Engine> GateInternal<E> for Rescue5CustomGate {
    fn name(&self) -> &'static str {
        "Alpha=5 custom gate for Rescue/Poseidon"
    }

    fn degree(&self) -> usize {
        2
    }

    fn can_include_public_inputs(&self) -> bool {
        false
    }

    fn all_queried_polynomials(
        &self,
    ) -> &'static [bellman::plonk::better_better_cs::cs::PolynomialInConstraint] {
        const POLYS: [PolynomialInConstraint; 4] = [
            PolynomialInConstraint::from_id(PolyIdentifier::VariablesPolynomial(0)),
            PolynomialInConstraint::from_id(PolyIdentifier::VariablesPolynomial(1)),
            PolynomialInConstraint::from_id(PolyIdentifier::VariablesPolynomial(2)),
            PolynomialInConstraint::from_id(PolyIdentifier::VariablesPolynomial(3)),
        ];

        &POLYS
    }

    fn setup_polynomials(&self) -> &'static [bellman::plonk::better_better_cs::cs::PolyIdentifier] {
        &[]
    }

    fn variable_polynomials(
        &self,
    ) -> &'static [bellman::plonk::better_better_cs::cs::PolyIdentifier] {
        const POLYS: [PolyIdentifier; 4] = [
            PolyIdentifier::VariablesPolynomial(0),
            PolyIdentifier::VariablesPolynomial(1),
            PolyIdentifier::VariablesPolynomial(2),
            PolyIdentifier::VariablesPolynomial(3),
        ];

        &POLYS
    }

    fn benefits_from_linearization(&self) -> bool {
        false
    }

    fn linearizes_over(
        &self,
    ) -> &'static [bellman::plonk::better_better_cs::cs::PolynomialInConstraint] {
        &[]
    }

    fn needs_opened_for_linearization(
        &self,
    ) -> &'static [bellman::plonk::better_better_cs::cs::PolynomialInConstraint] {
        &[]
    }

    fn num_quotient_terms(&self) -> usize {
        3
    }

    fn verify_on_row(
        &self,
        row: usize,
        poly_storage: &bellman::plonk::better_better_cs::cs::AssembledPolynomialStorage<'_, E>,
        _last_row: bool,
    ) -> E::Fr {
        let a_value = poly_storage.get_poly_at_step(PolyIdentifier::VariablesPolynomial(0), row);
        let b_value = poly_storage.get_poly_at_step(PolyIdentifier::VariablesPolynomial(1), row);
        let c_value = poly_storage.get_poly_at_step(PolyIdentifier::VariablesPolynomial(2), row);
        let d_value = poly_storage.get_poly_at_step(PolyIdentifier::VariablesPolynomial(3), row);

        let mut tmp = a_value;
        tmp.square();
        tmp.sub_assign(&b_value);

        if !tmp.is_zero() {
            return tmp;
        }

        let mut tmp = b_value;
        tmp.square();
        tmp.sub_assign(&c_value);

        if !tmp.is_zero() {
            return tmp;
        }

        let mut tmp = c_value;
        tmp.mul_assign(&a_value);
        tmp.sub_assign(&d_value);

        tmp
    }

    fn put_public_inputs_into_selector_id(&self) -> Option<usize> {
        None
    }

    fn contribute_into_quotient(
        &self,
        _domain_size: usize,
        _poly_storage: &mut bellman::plonk::better_better_cs::cs::AssembledPolynomialStorage<'_, E>,
        _monomials_storage: & bellman::plonk::better_better_cs::cs::AssembledPolynomialStorageForMonomialForms<'_, E>,
        _challenges: &[E::Fr],
        _omegas_bitreversed: &bellman::plonk::fft::cooley_tukey_ntt::BitReversedOmegas<E::Fr>,
        _omegas_inv_bitreversed: &bellman::plonk::fft::cooley_tukey_ntt::OmegasInvBitreversed<
            E::Fr,
        >,
        _worker: &bellman::worker::Worker,
    ) -> Result<
        bellman::plonk::polynomials::Polynomial<E::Fr, bellman::plonk::polynomials::Values>,
        SynthesisError,
    > {
        unreachable!("this gate implents stuff just for verifying");
    }

    fn contribute_into_linearization(
        &self,
        _domain_size: usize,
        _at: E::Fr,
        _queried_values: &std::collections::HashMap<
            bellman::plonk::better_better_cs::cs::PolynomialInConstraint,
            E::Fr,
        >,
        _monomials_storage: & bellman::plonk::better_better_cs::cs::AssembledPolynomialStorageForMonomialForms<'_, E>,
        _challenges: &[E::Fr],
        _worker: &bellman::worker::Worker,
    ) -> Result<
        bellman::plonk::polynomials::Polynomial<E::Fr, bellman::plonk::polynomials::Coefficients>,
        SynthesisError,
    > {
        unreachable!("this gate does not contribute into linearization");
    }

    fn contribute_into_verification_equation(
        &self,
        _domain_size: usize,
        _at: E::Fr,
        queried_values: &std::collections::HashMap<
            bellman::plonk::better_better_cs::cs::PolynomialInConstraint,
            E::Fr,
        >,
        challenges: &[E::Fr],
    ) -> Result<E::Fr, SynthesisError> {
        assert_eq!(
            challenges.len(),
            <Self as GateInternal<E>>::num_quotient_terms(self)
        );

        let a_value = *queried_values
            .get(&PolynomialInConstraint::from_id(
                PolyIdentifier::VariablesPolynomial(0),
            ))
            .ok_or(SynthesisError::AssignmentMissing)?;
        let b_value = *queried_values
            .get(&PolynomialInConstraint::from_id(
                PolyIdentifier::VariablesPolynomial(1),
            ))
            .ok_or(SynthesisError::AssignmentMissing)?;
        let c_value = *queried_values
            .get(&PolynomialInConstraint::from_id(
                PolyIdentifier::VariablesPolynomial(2),
            ))
            .ok_or(SynthesisError::AssignmentMissing)?;
        let d_value = *queried_values
            .get(&PolynomialInConstraint::from_id(
                PolyIdentifier::VariablesPolynomial(3),
            ))
            .ok_or(SynthesisError::AssignmentMissing)?;

        // a^2 - b = 0
        let mut result = a_value;
        result.square();
        result.sub_assign(&b_value);

        result.mul_assign(&challenges[0]);

        // b^2 - c = 0
        let mut tmp = b_value;
        tmp.square();
        tmp.sub_assign(&c_value);

        tmp.mul_assign(&challenges[1]);

        result.add_assign(&tmp);

        // c*a - d = 0;
        let mut tmp = c_value;
        tmp.mul_assign(&a_value);
        tmp.sub_assign(&d_value);

        tmp.mul_assign(&challenges[2]);

        result.add_assign(&tmp);

        Ok(result)
    }

    fn box_clone(&self) -> Box<dyn GateInternal<E>> {
        Box::from(self.clone())
    }

    fn contribute_into_linearization_commitment(
        &self,
        _domain_size: usize,
        _at: E::Fr,
        _queried_values: &std::collections::HashMap<
            bellman::plonk::better_better_cs::cs::PolynomialInConstraint,
            E::Fr,
        >,
        _commitments_storage: &std::collections::HashMap<
            bellman::plonk::better_better_cs::cs::PolyIdentifier,
            E::G1Affine,
        >,
        _challenges: &[E::Fr],
    ) -> Result<E::G1, SynthesisError> {
        unreachable!("this gate does not contribute into linearization");
    }
}

impl<E: Engine> Gate<E> for Rescue5CustomGate {}
