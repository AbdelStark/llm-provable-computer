/// FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity) low-degree test.
/// Ported from the stark-anatomy Python reference implementation.
use blake2::{Blake2b512, Digest};

use super::field::FieldElement;
use super::merkle::Merkle;
use super::polynomial::{test_colinearity, Polynomial};
use super::proof_stream::{ProofObject, ProofStream};

fn blake2b_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub struct Fri {
    pub offset: FieldElement,
    pub omega: FieldElement,
    pub domain_length: usize,
    pub expansion_factor: usize,
    pub num_colinearity_tests: usize,
}

impl Fri {
    pub fn new(
        offset: FieldElement,
        omega: FieldElement,
        initial_domain_length: usize,
        expansion_factor: usize,
        num_colinearity_tests: usize,
    ) -> Self {
        let fri = Fri {
            offset,
            omega,
            domain_length: initial_domain_length,
            expansion_factor,
            num_colinearity_tests,
        };
        assert!(
            fri.num_rounds() >= 1,
            "cannot do FRI with less than one round"
        );
        fri
    }

    pub fn num_rounds(&self) -> usize {
        let mut codeword_length = self.domain_length;
        let mut num_rounds = 0;
        while codeword_length > self.expansion_factor
            && 4 * self.num_colinearity_tests < codeword_length
        {
            codeword_length /= 2;
            num_rounds += 1;
        }
        num_rounds
    }

    fn sample_index(byte_array: &[u8], size: usize) -> usize {
        let mut acc: u128 = 0;
        for &b in byte_array {
            acc = (acc << 8) ^ (b as u128);
        }
        (acc % (size as u128)) as usize
    }

    fn sample_indices(
        &self,
        seed: &[u8],
        size: usize,
        reduced_size: usize,
        number: usize,
    ) -> Vec<usize> {
        assert!(
            number <= reduced_size,
            "cannot sample more indices than available in last codeword"
        );
        assert!(
            number <= 2 * reduced_size,
            "not enough entropy in indices wrt last codeword"
        );

        let mut indices = Vec::new();
        let mut reduced_indices = Vec::new();
        let mut counter: usize = 0;

        while indices.len() < number {
            // blake2b(seed + bytes(counter)): append counter zero bytes
            let mut input = seed.to_vec();
            input.extend(vec![0u8; counter]);
            let digest = blake2b_hash(&input);

            let index = Self::sample_index(&digest, size);
            let reduced_index = index % reduced_size;
            counter += 1;

            if !reduced_indices.contains(&reduced_index) {
                indices.push(index);
                reduced_indices.push(reduced_index);
            }
        }
        indices
    }

    pub fn eval_domain(&self) -> Vec<FieldElement> {
        (0..self.domain_length)
            .map(|i| self.offset * self.omega.pow(i as u128))
            .collect()
    }

    /// FRI commit phase: split-and-fold the codeword.
    pub fn commit(
        &self,
        codeword: &[FieldElement],
        proof_stream: &mut ProofStream,
    ) -> Vec<Vec<FieldElement>> {
        let one = FieldElement::one();
        let two_inv = FieldElement::new(2).inverse();
        let mut omega = self.omega;
        let mut offset = self.offset;
        let mut codeword = codeword.to_vec();
        let mut codewords: Vec<Vec<FieldElement>> = Vec::new();
        let num_rounds = self.num_rounds();

        for r in 0..num_rounds {
            let n = codeword.len();

            // Verify omega order
            assert_eq!(
                omega.pow((n - 1) as u128),
                omega.inverse(),
                "error in commit: omega does not have the right order"
            );

            // Compute and send Merkle root
            let codeword_bytes: Vec<Vec<u8>> = codeword.iter().map(|e| e.to_bytes_str()).collect();
            let root = Merkle::commit(&codeword_bytes);
            proof_stream.push(ProofObject::Bytes(root));

            if r == num_rounds - 1 {
                break;
            }

            // Get challenge
            let alpha = FieldElement::sample(&proof_stream.prover_fiat_shamir());

            // Collect codeword
            codewords.push(codeword.clone());

            // Split and fold
            let half = n / 2;
            let new_codeword: Vec<FieldElement> = (0..half)
                .map(|i| {
                    two_inv
                        * ((one + alpha / (offset * omega.pow(i as u128))) * codeword[i]
                            + (one - alpha / (offset * omega.pow(i as u128))) * codeword[half + i])
                })
                .collect();

            codeword = new_codeword;
            omega = omega.pow(2);
            offset = offset.pow(2);
        }

        // Send last codeword
        proof_stream.push(ProofObject::Codeword(codeword.clone()));

        // Collect last codeword too
        codewords.push(codeword);
        codewords
    }

    /// FRI query phase: reveal leaves and authentication paths.
    pub fn query(
        &self,
        current_codeword: &[FieldElement],
        next_codeword: &[FieldElement],
        c_indices: &[usize],
        proof_stream: &mut ProofStream,
    ) -> Vec<usize> {
        let half = current_codeword.len() / 2;
        let a_indices: Vec<usize> = c_indices.to_vec();
        let b_indices: Vec<usize> = c_indices.iter().map(|&i| i + half).collect();

        // Reveal leafs
        for s in 0..self.num_colinearity_tests {
            proof_stream.push(ProofObject::Triple(
                current_codeword[a_indices[s]],
                current_codeword[b_indices[s]],
                next_codeword[c_indices[s]],
            ));
        }

        // Reveal authentication paths
        let current_bytes: Vec<Vec<u8>> =
            current_codeword.iter().map(|e| e.to_bytes_str()).collect();
        let next_bytes: Vec<Vec<u8>> = next_codeword.iter().map(|e| e.to_bytes_str()).collect();

        for s in 0..self.num_colinearity_tests {
            proof_stream.push(ProofObject::Path(Merkle::open(
                a_indices[s],
                &current_bytes,
            )));
            proof_stream.push(ProofObject::Path(Merkle::open(
                b_indices[s],
                &current_bytes,
            )));
            proof_stream.push(ProofObject::Path(Merkle::open(c_indices[s], &next_bytes)));
        }

        [a_indices, b_indices].concat()
    }

    /// FRI prove: commit + query.
    pub fn prove(&self, codeword: &[FieldElement], proof_stream: &mut ProofStream) -> Vec<usize> {
        assert_eq!(
            self.domain_length,
            codeword.len(),
            "codeword length mismatch"
        );

        // Commit phase
        let codewords = self.commit(codeword, proof_stream);

        // Get indices
        let top_level_indices = self.sample_indices(
            &proof_stream.prover_fiat_shamir(),
            codewords[0].len() / 2,
            codewords.last().unwrap().len(),
            self.num_colinearity_tests,
        );
        let mut indices = top_level_indices.clone();

        // Query phase
        for i in 0..codewords.len() - 1 {
            let half = codewords[i].len() / 2;
            indices = indices.iter().map(|&idx| idx % half).collect();
            self.query(&codewords[i], &codewords[i + 1], &indices, proof_stream);
        }

        top_level_indices
    }

    /// FRI verify: check Merkle openings and colinearity.
    pub fn verify(
        &self,
        proof_stream: &mut ProofStream,
        polynomial_values: &mut Vec<(usize, FieldElement)>,
    ) -> bool {
        let mut omega = self.omega;
        let mut offset = self.offset;
        let num_rounds = self.num_rounds();

        // Extract all roots and alphas
        let mut roots = Vec::new();
        let mut alphas = Vec::new();
        for _ in 0..num_rounds {
            if let Some(ProofObject::Bytes(root)) = proof_stream.pull() {
                roots.push(root);
            } else {
                return false;
            }
            alphas.push(FieldElement::sample(&proof_stream.verifier_fiat_shamir()));
        }

        // Extract last codeword
        let last_codeword = if let Some(ProofObject::Codeword(cw)) = proof_stream.pull() {
            cw
        } else {
            return false;
        };

        // Check if it matches the given root
        let last_codeword_bytes: Vec<Vec<u8>> =
            last_codeword.iter().map(|e| e.to_bytes_str()).collect();
        if roots.last().unwrap().as_slice() != Merkle::commit(&last_codeword_bytes).as_slice() {
            return false;
        }

        // Check if it is low degree
        let degree = (last_codeword.len() / self.expansion_factor) - 1;
        let mut last_omega = omega;
        let mut last_offset = offset;
        for _ in 0..num_rounds - 1 {
            last_omega = last_omega.pow(2);
            last_offset = last_offset.pow(2);
        }

        // Compute interpolant
        let last_domain: Vec<FieldElement> = (0..last_codeword.len())
            .map(|i| last_offset * last_omega.pow(i as u128))
            .collect();
        let poly = Polynomial::interpolate_domain(&last_domain, &last_codeword);

        if poly.degree() > degree as isize {
            return false;
        }

        // Get indices
        let top_level_indices = self.sample_indices(
            &proof_stream.verifier_fiat_shamir(),
            self.domain_length >> 1,
            self.domain_length >> (num_rounds - 1),
            self.num_colinearity_tests,
        );

        // For every round, check consistency of subsequent layers
        for r in 0..num_rounds - 1 {
            let c_indices: Vec<usize> = top_level_indices
                .iter()
                .map(|&idx| idx % (self.domain_length >> (r + 1)))
                .collect();
            let a_indices = c_indices.clone();
            let b_indices: Vec<usize> = c_indices
                .iter()
                .map(|&idx| idx + (self.domain_length >> (r + 1)))
                .collect();

            // Read values and check colinearity
            let mut aa = Vec::new();
            let mut bb = Vec::new();
            let mut cc = Vec::new();
            for s in 0..self.num_colinearity_tests {
                let (ay, by, cy) = if let Some(ProofObject::Triple(a, b, c)) = proof_stream.pull() {
                    (a, b, c)
                } else {
                    return false;
                };
                aa.push(ay);
                bb.push(by);
                cc.push(cy);

                // Record top-layer values for later verification
                if r == 0 {
                    polynomial_values.push((a_indices[s], ay));
                    polynomial_values.push((b_indices[s], by));
                }

                // Colinearity check
                let ax = offset * omega.pow(a_indices[s] as u128);
                let bx = offset * omega.pow(b_indices[s] as u128);
                let cx = alphas[r];
                if !test_colinearity(&[(ax, ay), (bx, by), (cx, cy)]) {
                    return false;
                }
            }

            // Verify authentication paths
            for i in 0..self.num_colinearity_tests {
                let path_a = if let Some(ProofObject::Path(p)) = proof_stream.pull() {
                    p
                } else {
                    return false;
                };
                if !Merkle::verify(&roots[r], a_indices[i], &path_a, &aa[i].to_bytes_str()) {
                    return false;
                }
                let path_b = if let Some(ProofObject::Path(p)) = proof_stream.pull() {
                    p
                } else {
                    return false;
                };
                if !Merkle::verify(&roots[r], b_indices[i], &path_b, &bb[i].to_bytes_str()) {
                    return false;
                }
                let path_c = if let Some(ProofObject::Path(p)) = proof_stream.pull() {
                    p
                } else {
                    return false;
                };
                if !Merkle::verify(&roots[r + 1], c_indices[i], &path_c, &cc[i].to_bytes_str()) {
                    return false;
                }
            }

            // Square omega and offset for next round
            omega = omega.pow(2);
            offset = offset.pow(2);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_prove_verify() {
        let degree = 63;
        let expansion_factor = 4;
        let num_colinearity_tests = 17;

        let initial_codeword_length = (degree + 1) * expansion_factor;
        let omega = FieldElement::primitive_nth_root(initial_codeword_length as u128);
        let generator = FieldElement::generator();

        let fri = Fri::new(
            generator,
            omega,
            initial_codeword_length,
            expansion_factor,
            num_colinearity_tests,
        );

        let polynomial =
            Polynomial::new((0..=degree).map(|i| FieldElement::new(i as u128)).collect());
        let domain: Vec<FieldElement> = (0..initial_codeword_length)
            .map(|i| omega.pow(i as u128))
            .collect();
        let codeword = polynomial.evaluate_domain(&domain);

        // Test valid codeword
        let mut proof_stream = ProofStream::new();
        fri.prove(&codeword, &mut proof_stream);

        let mut verify_stream = proof_stream.clone();
        verify_stream.read_index = 0;
        let mut points = Vec::new();
        let verdict = fri.verify(&mut verify_stream, &mut points);
        assert!(verdict, "valid FRI proof should verify");

        for &(x, y) in &points {
            assert_eq!(
                polynomial.evaluate(omega.pow(x as u128)),
                y,
                "polynomial evaluates to wrong value"
            );
        }
    }
}
