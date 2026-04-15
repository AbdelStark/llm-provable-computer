/// STARK prover and verifier.
/// Ported from the stark-anatomy Python reference implementation.
use blake2::{Blake2b512, Digest};

use super::field::FieldElement;
use super::fri::Fri;
use super::merkle::Merkle;
use super::multivariate::MPolynomial;
use super::polynomial::Polynomial;
use super::proof_stream::{ProofObject, ProofStream};

fn blake2b_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub struct Stark {
    pub expansion_factor: usize,
    pub num_colinearity_checks: usize,
    pub security_level: usize,
    pub num_randomizers: usize,
    pub num_registers: usize,
    pub original_trace_length: usize,
    pub generator: FieldElement,
    pub omega: FieldElement,
    pub omicron: FieldElement,
    pub omicron_domain: Vec<FieldElement>,
    pub fri: Fri,
}

impl Stark {
    pub fn new(
        expansion_factor: usize,
        num_colinearity_checks: usize,
        security_level: usize,
        num_registers: usize,
        num_cycles: usize,
        transition_constraints_degree: usize,
    ) -> Self {
        assert!(
            expansion_factor.is_power_of_two(),
            "expansion factor must be a power of 2"
        );
        assert!(
            expansion_factor >= 4,
            "expansion factor must be 4 or greater"
        );
        assert!(
            num_colinearity_checks * 2 >= security_level,
            "number of colinearity checks must be at least half of security level"
        );

        let num_randomizers = 4 * num_colinearity_checks;
        let randomized_trace_length = num_cycles + num_randomizers;
        let omicron_domain_length = {
            let bits = (randomized_trace_length * transition_constraints_degree) as f64;
            1usize << (bits.log2().ceil() as usize + 1).max(1)
        };
        let fri_domain_length = omicron_domain_length * expansion_factor;

        let generator = FieldElement::generator();
        let omega = FieldElement::primitive_nth_root(fri_domain_length as u128);
        let omicron = FieldElement::primitive_nth_root(omicron_domain_length as u128);
        let omicron_domain: Vec<FieldElement> = (0..omicron_domain_length)
            .map(|i| omicron.pow(i as u128))
            .collect();

        let fri = Fri::new(
            generator,
            omega,
            fri_domain_length,
            expansion_factor,
            num_colinearity_checks,
        );

        Stark {
            expansion_factor,
            num_colinearity_checks,
            security_level,
            num_randomizers,
            num_registers,
            original_trace_length: num_cycles,
            generator,
            omega,
            omicron,
            omicron_domain,
            fri,
        }
    }

    fn transition_degree_bounds(&self, transition_constraints: &[MPolynomial]) -> Vec<isize> {
        let mut point_degrees = vec![1isize];
        for _ in 0..2 * self.num_registers {
            point_degrees.push((self.original_trace_length + self.num_randomizers - 1) as isize);
        }
        transition_constraints
            .iter()
            .map(|a| {
                a.dictionary
                    .keys()
                    .map(|k| {
                        k.iter()
                            .zip(point_degrees.iter())
                            .map(|(&r, &l)| (r as isize) * l)
                            .sum::<isize>()
                    })
                    .max()
                    .unwrap_or(0)
            })
            .collect()
    }

    fn transition_quotient_degree_bounds(
        &self,
        transition_constraints: &[MPolynomial],
    ) -> Vec<isize> {
        self.transition_degree_bounds(transition_constraints)
            .iter()
            .map(|d| d - (self.original_trace_length as isize - 1))
            .collect()
    }

    fn max_degree(&self, transition_constraints: &[MPolynomial]) -> isize {
        let md = *self
            .transition_quotient_degree_bounds(transition_constraints)
            .iter()
            .max()
            .unwrap();
        let bits = format!("{:b}", md).len();
        (1isize << bits) - 1
    }

    fn transition_zerofier(&self) -> Polynomial {
        let domain: Vec<FieldElement> =
            self.omicron_domain[0..self.original_trace_length - 1].to_vec();
        Polynomial::zerofier_domain(&domain)
    }

    fn boundary_zerofiers(&self, boundary: &[(usize, usize, FieldElement)]) -> Vec<Polynomial> {
        let mut zerofiers = Vec::new();
        for s in 0..self.num_registers {
            let points: Vec<FieldElement> = boundary
                .iter()
                .filter(|(_, r, _)| *r == s)
                .map(|(c, _, _)| self.omicron.pow(*c as u128))
                .collect();
            zerofiers.push(Polynomial::zerofier_domain(&points));
        }
        zerofiers
    }

    fn boundary_interpolants(&self, boundary: &[(usize, usize, FieldElement)]) -> Vec<Polynomial> {
        let mut interpolants = Vec::new();
        for s in 0..self.num_registers {
            let filtered: Vec<(usize, FieldElement)> = boundary
                .iter()
                .filter(|(_, r, _)| *r == s)
                .map(|(c, _, v)| (*c, *v))
                .collect();
            if filtered.is_empty() {
                interpolants.push(Polynomial::zero());
                continue;
            }
            let domain: Vec<FieldElement> = filtered
                .iter()
                .map(|(c, _)| self.omicron.pow(*c as u128))
                .collect();
            let values: Vec<FieldElement> = filtered.iter().map(|(_, v)| *v).collect();
            interpolants.push(Polynomial::interpolate_domain(&domain, &values));
        }
        interpolants
    }

    fn boundary_quotient_degree_bounds(
        &self,
        randomized_trace_length: usize,
        boundary: &[(usize, usize, FieldElement)],
    ) -> Vec<isize> {
        let randomized_trace_degree = randomized_trace_length as isize - 1;
        self.boundary_zerofiers(boundary)
            .iter()
            .map(|bz| randomized_trace_degree - bz.degree())
            .collect()
    }

    fn sample_weights(&self, number: usize, randomness: &[u8]) -> Vec<FieldElement> {
        (0..number)
            .map(|i| {
                let mut input = randomness.to_vec();
                input.extend(vec![0u8; i]);
                let digest = blake2b_hash(&input);
                FieldElement::sample(&digest)
            })
            .collect()
    }

    /// STARK prover.
    pub fn prove(
        &self,
        trace: &[Vec<FieldElement>],
        transition_constraints: &[MPolynomial],
        boundary: &[(usize, usize, FieldElement)],
    ) -> Vec<u8> {
        let mut proof_stream = ProofStream::new();

        // Concatenate randomizers
        let mut trace = trace.to_vec();
        for _ in 0..self.num_randomizers {
            let random_row: Vec<FieldElement> = (0..self.num_registers)
                .map(|i| {
                    // Use a deterministic "random" based on trace length and register index
                    let seed: Vec<u8> = [
                        &(trace.len() as u64).to_le_bytes()[..],
                        &(i as u64).to_le_bytes()[..],
                        b"randomizer",
                    ]
                    .concat();
                    FieldElement::sample(&seed)
                })
                .collect();
            trace.push(random_row);
        }

        // Interpolate
        let trace_domain: Vec<FieldElement> = (0..trace.len())
            .map(|i| self.omicron.pow(i as u128))
            .collect();
        let mut trace_polynomials = Vec::new();
        for s in 0..self.num_registers {
            let single_trace: Vec<FieldElement> = (0..trace.len()).map(|c| trace[c][s]).collect();
            trace_polynomials.push(Polynomial::interpolate_domain(&trace_domain, &single_trace));
        }

        // Subtract boundary interpolants and divide out boundary zerofiers
        let boundary_interpolants = self.boundary_interpolants(boundary);
        let boundary_zerofiers = self.boundary_zerofiers(boundary);
        let boundary_quotients: Vec<Polynomial> = trace_polynomials
            .iter()
            .zip(boundary_interpolants.iter().zip(boundary_zerofiers.iter()))
            .map(|(trace_polynomial, (interpolant, zerofier))| {
                (trace_polynomial.clone() - interpolant.clone()) / zerofier.clone()
            })
            .collect();

        // Commit to boundary quotients
        let fri_domain = self.fri.eval_domain();
        let mut boundary_quotient_codewords = Vec::new();
        for quotient in boundary_quotients.iter().take(self.num_registers) {
            let codeword = quotient.evaluate_domain(&fri_domain);
            let codeword_bytes: Vec<Vec<u8>> = codeword.iter().map(|e| e.to_bytes_str()).collect();
            let merkle_root = Merkle::commit(&codeword_bytes);
            proof_stream.push(ProofObject::Bytes(merkle_root));
            boundary_quotient_codewords.push(codeword);
        }

        // Symbolically evaluate transition constraints
        let x = Polynomial::new(vec![FieldElement::zero(), FieldElement::one()]);
        let mut point: Vec<Polynomial> = vec![x.clone()];
        for tp in &trace_polynomials {
            point.push(tp.clone());
        }
        for tp in &trace_polynomials {
            point.push(tp.scale(self.omicron));
        }
        let transition_polynomials: Vec<Polynomial> = transition_constraints
            .iter()
            .map(|a| a.evaluate_symbolic(&point))
            .collect();

        // Divide out transition zerofier
        let transition_zerofier = self.transition_zerofier();
        let transition_quotients: Vec<Polynomial> = transition_polynomials
            .iter()
            .map(|tp| tp.clone() / transition_zerofier.clone())
            .collect();

        // Commit to randomizer polynomial
        let max_degree = self.max_degree(transition_constraints);
        let randomizer_polynomial = Polynomial::new(
            (0..=max_degree as usize)
                .map(|i| {
                    let seed = [&(i as u64).to_le_bytes()[..], b"rnd_poly"].concat();
                    FieldElement::sample(&seed)
                })
                .collect(),
        );
        let randomizer_codeword = randomizer_polynomial.evaluate_domain(&fri_domain);
        let randomizer_bytes: Vec<Vec<u8>> = randomizer_codeword
            .iter()
            .map(|e| e.to_bytes_str())
            .collect();
        let randomizer_root = Merkle::commit(&randomizer_bytes);
        proof_stream.push(ProofObject::Bytes(randomizer_root));

        // Get weights for nonlinear combination
        let num_weights = 1 + 2 * transition_quotients.len() + 2 * boundary_quotients.len();
        let weights = self.sample_weights(num_weights, &proof_stream.prover_fiat_shamir());

        // Compute terms of nonlinear combination polynomial
        let tq_degree_bounds = self.transition_quotient_degree_bounds(transition_constraints);
        let bq_degree_bounds = self.boundary_quotient_degree_bounds(trace.len(), boundary);

        let mut terms: Vec<Polynomial> = Vec::new();
        terms.push(randomizer_polynomial);
        for i in 0..transition_quotients.len() {
            terms.push(transition_quotients[i].clone());
            let shift = max_degree - tq_degree_bounds[i];
            terms.push(x.pow(shift as usize) * transition_quotients[i].clone());
        }
        for i in 0..self.num_registers {
            terms.push(boundary_quotients[i].clone());
            let shift = max_degree - bq_degree_bounds[i];
            terms.push(x.pow(shift as usize) * boundary_quotients[i].clone());
        }

        // Take weighted sum
        let mut combination = Polynomial::zero();
        for i in 0..terms.len() {
            combination = combination + Polynomial::new(vec![weights[i]]) * terms[i].clone();
        }

        // Compute matching codeword
        let combined_codeword = combination.evaluate_domain(&fri_domain);

        // Prove low degree of combination polynomial
        let indices = self.fri.prove(&combined_codeword, &mut proof_stream);

        // Process indices
        let mut duplicated_indices: Vec<usize> = indices.clone();
        for &i in &indices {
            duplicated_indices.push((i + self.expansion_factor) % self.fri.domain_length);
        }
        let mut quadrupled_indices = duplicated_indices.clone();
        for &i in &duplicated_indices {
            quadrupled_indices.push((i + self.fri.domain_length / 2) % self.fri.domain_length);
        }
        quadrupled_indices.sort();
        quadrupled_indices.dedup();

        // Open indicated positions in the boundary quotient codewords
        for bqc in &boundary_quotient_codewords {
            let bqc_bytes: Vec<Vec<u8>> = bqc.iter().map(|e| e.to_bytes_str()).collect();
            for &i in &quadrupled_indices {
                proof_stream.push(ProofObject::Element(bqc[i]));
                let path = Merkle::open(i, &bqc_bytes);
                proof_stream.push(ProofObject::Path(path));
            }
        }

        // Open indicated positions in the randomizer
        for &i in &quadrupled_indices {
            proof_stream.push(ProofObject::Element(randomizer_codeword[i]));
            let path = Merkle::open(i, &randomizer_bytes);
            proof_stream.push(ProofObject::Path(path));
        }

        proof_stream.serialize()
    }

    /// STARK verifier.
    pub fn verify(
        &self,
        proof: &[u8],
        transition_constraints: &[MPolynomial],
        boundary: &[(usize, usize, FieldElement)],
    ) -> bool {
        // Infer trace length from boundary conditions
        let original_trace_length = 1 + boundary.iter().map(|(c, _, _)| *c).max().unwrap_or(0);
        let randomized_trace_length = original_trace_length + self.num_randomizers;

        let mut proof_stream = match ProofStream::deserialize(proof) {
            Some(stream) => stream,
            None => return false,
        };

        // Get Merkle roots of boundary quotient codewords
        let mut boundary_quotient_roots = Vec::new();
        for _ in 0..self.num_registers {
            if let Some(ProofObject::Bytes(root)) = proof_stream.pull() {
                boundary_quotient_roots.push(root);
            } else {
                return false;
            }
        }

        // Get Merkle root of randomizer polynomial
        let randomizer_root = if let Some(ProofObject::Bytes(root)) = proof_stream.pull() {
            root
        } else {
            return false;
        };

        // Get weights
        let num_weights =
            1 + 2 * transition_constraints.len() + 2 * self.boundary_interpolants(boundary).len();
        let weights = self.sample_weights(num_weights, &proof_stream.verifier_fiat_shamir());

        // Verify low degree of combination polynomial
        let mut polynomial_values: Vec<(usize, FieldElement)> = Vec::new();
        let verifier_accepts = self.fri.verify(&mut proof_stream, &mut polynomial_values);
        polynomial_values.sort_by_key(|&(i, _)| i);
        if !verifier_accepts {
            return false;
        }

        let indices: Vec<usize> = polynomial_values.iter().map(|&(i, _)| i).collect();
        let values: Vec<FieldElement> = polynomial_values.iter().map(|&(_, v)| v).collect();

        // Read and verify leafs
        let mut duplicated_indices: Vec<usize> = indices.clone();
        for &i in &indices {
            duplicated_indices.push((i + self.expansion_factor) % self.fri.domain_length);
        }
        duplicated_indices.sort();
        duplicated_indices.dedup();

        let mut leafs: Vec<std::collections::HashMap<usize, FieldElement>> = Vec::new();
        for root in &boundary_quotient_roots {
            let mut leaf_map = std::collections::HashMap::new();
            for &i in &duplicated_indices {
                let element = if let Some(ProofObject::Element(e)) = proof_stream.pull() {
                    e
                } else {
                    return false;
                };
                let path = if let Some(ProofObject::Path(p)) = proof_stream.pull() {
                    p
                } else {
                    return false;
                };
                if !Merkle::verify(root, i, &path, &element.to_bytes_str()) {
                    return false;
                }
                leaf_map.insert(i, element);
            }
            leafs.push(leaf_map);
        }

        // Read and verify randomizer leafs
        let mut randomizer: std::collections::HashMap<usize, FieldElement> =
            std::collections::HashMap::new();
        for &i in &duplicated_indices {
            let element = if let Some(ProofObject::Element(e)) = proof_stream.pull() {
                e
            } else {
                return false;
            };
            let path = if let Some(ProofObject::Path(p)) = proof_stream.pull() {
                p
            } else {
                return false;
            };
            if !Merkle::verify(&randomizer_root, i, &path, &element.to_bytes_str()) {
                return false;
            }
            randomizer.insert(i, element);
        }

        // Precompute boundary interpolants and zerofiers
        let boundary_interpolants = self.boundary_interpolants(boundary);
        let boundary_zerofiers = self.boundary_zerofiers(boundary);
        let transition_zerofier = self.transition_zerofier();
        let tq_degree_bounds = self.transition_quotient_degree_bounds(transition_constraints);
        let bq_degree_bounds =
            self.boundary_quotient_degree_bounds(randomized_trace_length, boundary);
        let max_degree = self.max_degree(transition_constraints);

        // Verify leafs of combination polynomial
        for i in 0..indices.len() {
            let current_index = indices[i];
            let domain_current_index = self.generator * self.omega.pow(current_index as u128);
            let next_index = (current_index + self.expansion_factor) % self.fri.domain_length;
            let domain_next_index = self.generator * self.omega.pow(next_index as u128);

            // Get trace values by applying correction to boundary quotient values
            let mut current_trace = vec![FieldElement::zero(); self.num_registers];
            let mut next_trace = vec![FieldElement::zero(); self.num_registers];
            for s in 0..self.num_registers {
                let zerofier = &boundary_zerofiers[s];
                let interpolant = &boundary_interpolants[s];

                current_trace[s] = leafs[s][&current_index]
                    * zerofier.evaluate(domain_current_index)
                    + interpolant.evaluate(domain_current_index);
                next_trace[s] = leafs[s][&next_index] * zerofier.evaluate(domain_next_index)
                    + interpolant.evaluate(domain_next_index);
            }

            let mut point: Vec<FieldElement> = vec![domain_current_index];
            point.extend_from_slice(&current_trace);
            point.extend_from_slice(&next_trace);
            let transition_constraints_values: Vec<FieldElement> = transition_constraints
                .iter()
                .map(|tc| tc.evaluate(&point))
                .collect();

            // Compute nonlinear combination
            let mut terms: Vec<FieldElement> = Vec::new();
            terms.push(randomizer[&current_index]);
            for s in 0..transition_constraints_values.len() {
                let tcv = transition_constraints_values[s];
                let quotient = tcv / transition_zerofier.evaluate(domain_current_index);
                terms.push(quotient);
                let shift = max_degree - tq_degree_bounds[s];
                terms.push(quotient * domain_current_index.pow(shift as u128));
            }
            for s in 0..self.num_registers {
                let bqv = leafs[s][&current_index];
                terms.push(bqv);
                let shift = max_degree - bq_degree_bounds[s];
                terms.push(bqv * domain_current_index.pow(shift as u128));
            }

            let combination: FieldElement = terms
                .iter()
                .zip(weights.iter())
                .fold(FieldElement::zero(), |acc, (&t, &w)| acc + t * w);

            if combination != values[i] {
                return false;
            }
        }

        if proof_stream.pull().is_some() {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::rescue_prime::RescuePrime;
    use super::*;

    #[test]
    fn test_stark_prove_verify() {
        let expansion_factor = 4;
        let num_colinearity_checks = 2;
        let security_level = 2;

        let rp = RescuePrime::new();
        let input_element = FieldElement::sample(b"0xdeadbeef");
        let output_element = rp.hash(input_element);
        let num_cycles = rp.n + 1;
        let state_width = rp.m;

        let stark = Stark::new(
            expansion_factor,
            num_colinearity_checks,
            security_level,
            state_width,
            num_cycles,
            2,
        );

        // Prove
        let trace = rp.trace(input_element);
        let air = rp.transition_constraints(stark.omicron);
        let boundary = rp.boundary_constraints(output_element);
        let proof = stark.prove(&trace, &air, &boundary);

        // Verify
        let verdict = stark.verify(&proof, &air, &boundary);
        assert!(verdict, "valid stark proof fails to verify");

        // Verify false claim
        let wrong_output = output_element + FieldElement::one();
        let wrong_boundary = rp.boundary_constraints(wrong_output);
        let verdict = stark.verify(&proof, &air, &wrong_boundary);
        assert!(!verdict, "invalid stark proof should not verify");
    }

    #[test]
    fn test_stark_rejects_trailing_proof_objects() {
        let expansion_factor = 4;
        let num_colinearity_checks = 2;
        let security_level = 2;

        let rp = RescuePrime::new();
        let input_element = FieldElement::sample(b"0xdeadbeef");
        let output_element = rp.hash(input_element);
        let num_cycles = rp.n + 1;
        let state_width = rp.m;

        let stark = Stark::new(
            expansion_factor,
            num_colinearity_checks,
            security_level,
            state_width,
            num_cycles,
            2,
        );

        let trace = rp.trace(input_element);
        let air = rp.transition_constraints(stark.omicron);
        let boundary = rp.boundary_constraints(output_element);
        let proof = stark.prove(&trace, &air, &boundary);

        let mut stream = ProofStream::deserialize(&proof).expect("deserialize proof");
        stream.push(ProofObject::Bytes(vec![0u8]));
        let tampered = stream.serialize();

        let verdict = stark.verify(&tampered, &air, &boundary);
        assert!(!verdict, "proof with trailing objects should not verify");
    }
}
