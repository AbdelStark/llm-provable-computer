# Proof-Carrying Decode Surfaces with Carried-State Validity and Pre-Recursive Aggregation Boundaries

**Abdelhamid Bakhta**<br>
StarkWare

**Omar Espejel**<br>
Starknet Foundation

*April 2026 draft*

## Abstract

This paper studies a narrower systems question than end-to-end zkML deployment:
what cryptographically meaningful public statement can already be supported by a
repository-backed proof artifact before recursive compression closure exists. We
answer that question for `provable-transformer-vm` by isolating a
proof-carrying decode relation over explicit carried-state boundaries and by
formalizing the statement-preserving packaging layers that the repository
already realizes.

The artifact surface is bounded but nontrivial. Verified step artifacts compose
into chains, segments, interval bundles, rollups, matrices, and a
pre-recursive aggregation boundary while preserving the same start-state to
end-state decode semantics. We formalize carried-state boundary tuples,
packaging-layer validity, and a preservation proposition for these ordered
artifacts. We also separate two adjacent but distinct engineering surfaces:
bounded multi-runtime semantic-agreement artifacts and release-provenance
manifests. Both matter operationally, but neither is part of the proof
relation.

The result is not recursive proof-carrying data, incrementally verifiable
computation, or compressed recursive verification in the sense of HyperNova,
NeutronNova, ProtoStar, or related folding systems. The contribution is a
statement-stable bridge: a decode relation with explicit public boundary
semantics that future recursive work could consume without redefining the
underlying claim. Appendix A states the claim boundary directly, Appendix B
positions the artifact against IVC and folding systems, Appendix C records the
remaining engineering gaps, and Appendix D maps the paper’s language onto the
concrete repository surfaces.

______________________________________________________________________

## 1. Introduction

There is a persistent failure mode in zkML systems writing: artifacts are often
described in language that sounds stronger than the actual verified statement.
This is especially easy once a repository accumulates chains, bundles, rollups,
aggregation objects, semantic-agreement artifacts, and provenance manifests.
Without a precise statement boundary, those objects can be mistaken for
recursive proof-carrying data, compressed recursive verification, or even
general implementation-equivalence proofs.

This paper takes the opposite approach. It asks for the strongest honest claim
that the current repository can defend to a cryptography audience. The answer
is a bounded one:

- there is a stable proof-carrying decode relation over explicit carried-state
  boundaries,
- the repository already realizes statement-preserving packaging layers over
  that relation,
- those layers stop at a pre-recursive aggregation boundary,
- adjacent semantic-agreement and provenance artifacts strengthen engineering
  trust but do not enlarge the proof statement.

That claim is narrower than full recursive accumulation, but it is also more
useful than a vague “artifact supports future recursion” sentence. It specifies
what later recursive machinery would need to preserve, namely the same public
decode boundary semantics already exposed by the current implementation.

The paper makes four contributions.

1. It isolates a repository-backed public statement surface for proof-carrying
   decode artifacts.
2. It formalizes carried-state boundary tuples and packaging-layer validity.
3. It states a preservation proposition for ordered packaging layers over
   verified step artifacts.
4. It separates proof semantics from semantic-agreement and provenance
   guardrails, making the negative claim surface explicit.

For this paper, “proof-carrying” means only that each artifact carries enough
public boundary data, nested commitments, and proof references for the
repository verifier to replay continuity checks across the declared relation. It
does not mean recursive proof-carrying data or compressed verifier recursion.

______________________________________________________________________

## 2. Public Statement Surface

The starting point is not a benchmark row. It is a public statement boundary.

The repository already exposes:

- deterministic transformer-shaped execution with statement-versioned proof
  claims,
- reusable step and block proof artifacts,
- carried-state decode chains with explicit continuity fields,
- higher-order packaging objects that preserve member ordering and public
  boundaries,
- bounded multi-runtime semantic-agreement artifacts,
- release-provenance manifests for model and artifact identity.

The cryptographically relevant question is which of those surfaces belong to the
same proof statement.

Our answer is:

- the decode relation and its packaging layers are inside the proof-facing
  statement surface,
- semantic-agreement artifacts are adjacent evidence about runtime consistency,
- provenance manifests are release guardrails,
- neither semantic-agreement nor provenance artifacts enlarge the proof
  relation.

This yields a clean separation between proof semantics and operational
trust-hardening.

### 2.1 Step statement

Let `statement-v1` denote the repository’s public execution-claim surface for a
single proof-bearing step or fixed execution unit. A valid step artifact binds:

- the public execution boundary,
- the applicable backend and statement profile,
- the carried commitments required by the decode layer,
- the nested proof or proof reference checked by the verifier.

The decode line then lifts those per-step statements into an ordered relation
over carried-state boundaries.

### 2.2 Stable statement structure

The main systems fact is stable statement structure: richer artifact layers do
not change the underlying public decode semantics. They only package,
re-index, and commitment-bind already verified members.

That is the right center of gravity for a crypto audience. The interesting point
is not that the repository has many JSON artifacts. It is that the same public
boundary semantics survive across those artifacts without being redefined at
each layer.

______________________________________________________________________

## 3. Carried-State Decode Relation

We now isolate the proof-facing object.

**Definition 1 (Carried-state boundary).** At decode step `t`, the public
boundary is the tuple

```text
Σ_t = (ℓ_t, p_t, h_t^KV, f_t^KV, h_t^L, f_t^L, c_t^in, c_t^out)
```

where:

- `ℓ_t` is the layout or template identifier,
- `p_t` is the public step-position metadata,
- `h_t^KV` and `f_t^KV` are the cumulative and frontier KV commitments,
- `h_t^L` and `f_t^L` are the cumulative and frontier lookup commitments,
- `c_t^in` and `c_t^out` are the execution-boundary commitments.

**Definition 2 (Proof-carrying decode relation).** Let

```text
R_decode(Σ_t, w_t, Σ_{t+1})
```

denote the repository’s parameterized decode relation, where `w_t` is the
step-level witness and proof-bearing artifact material checked by the verifier.

The relation is parameterized because the repository admits multiple templates
and packaging layouts, but the public boundary vocabulary remains fixed. This is
exactly the structure later recursive work would need: one relation whose
statement semantics do not drift as artifact packaging grows richer.

### 3.1 Continuity conditions

The decode relation is carried by explicit continuity conditions, not by prose.
At minimum, adjacent members must agree on:

- output-to-input execution continuity,
- KV frontier continuity,
- lookup frontier continuity,
- declared member order and layout compatibility.

This is why the repository’s chain, segment, interval, rollup, matrix, and
pre-recursive aggregation objects are interesting. They are not arbitrary
bundles; they are ordered packaging layers over the same continuity-checked
relation.

### 3.2 Why this is not yet recursive PCD or IVC

Nothing in the current artifact line compresses verification into a new proof
whose verifier asymptotically replaces the nested proofs. The packaging objects
carry commitments, ordering data, and continuity metadata, but they do not
realize a recursive verifier or folding theorem. The current contribution is
therefore semantic stabilization, not recursive compression.

______________________________________________________________________

## 4. Packaging-Layer Validity

The packaging layers matter only if their validity condition is explicit.

**Definition 3 (Packaging-layer validity).** A chain, segment, interval bundle,
rollup, matrix, or pre-recursive aggregation object is valid if:

1. its member order is declared,
2. each nested member verifies under the stated backend and statement profile,
3. each adjacent pair satisfies the continuity constraints required by
   `R_decode`,
4. the package-level commitments recompute from the declared ordered members,
5. the package start and end boundaries agree with the first and last member
   boundaries.

This definition matches the actual repository discipline more closely than a
generic “aggregate of proofs” phrase. The important fact is not just that there
are nested proofs; it is that the package verifier recomputes the public
structure from those ordered members and rejects drift.

### 4.1 Preservation proposition

**Proposition 1.** Suppose each member of an ordered step chain verifies under
the same public statement surface and every adjacent member satisfies the decode
continuity checks. Then any valid chain, segment, interval bundle, rollup,
matrix, or pre-recursive aggregation package over those ordered members
preserves the same start-state to end-state decode relation as the underlying
verified member sequence.

**Proof sketch.** The base case is the verified member sequence itself. Each
packaging layer records no stronger semantics than:

- the ordered member list,
- the first and last carried-state boundaries,
- recomputable package commitments derived from members,
- verifier checks that replay nested verification and continuity constraints.

Since each packaging layer rejects order drift, continuity drift, boundary-pair
drift, and package-commitment drift, induction over the ordered members yields
the same start-to-end relation as the underlying verified sequence. The result
is statement preservation, not recursive proof compression.

### 4.2 Architectural view

The repository’s carried-state ladder is therefore best read as an artifact
graph over one relation.

![Carried-state packaging ladder](../figures/section5-carried-state-ladder.svg)

The figure remains useful for this paper, but the caption emphasis changes for a
crypto audience: it is a map of statement-preserving packaging objects, not a
claim about recursive accumulation.

______________________________________________________________________

## 5. Artifact Realization in the Repository

The current repository realizes this picture in two connected but distinct
surfaces.

### 5.1 Proof-carrying decode and carried-state packaging

The strongest paper-2 surface is the phase line that now reaches:

- step and chain artifacts,
- state-relation accumulation,
- honest intervalization,
- folded interval accumulation,
- chained fold-of-folds packaging,
- proof-carrying outer aggregation,
- a recursive-compression input contract,
- a step-proof envelope manifest.

In publication-facing prose, those layers are best described as chain, segment,
interval bundle, rollup, matrix, and pre-recursive aggregation boundary. The
repository still retains phase-numbered artifact names for checksum stability,
but the semantics are those packaging layers over a fixed decode relation.
Appendix D gives the exact artifact-to-claim mapping.

### 5.2 Semantic-agreement artifacts

The repository also contains a bounded multi-runtime semantic-agreement line.
It lockstep-executes a fixed program across transformer, native, Burn, and ONNX
surfaces, records canonical events and traces, and binds them through runtime-
specific hashes plus a canonical relation hash.

This matters because proof artifacts should not lean on an informal assumption
that different runtime frontends are “obviously the same.” The artifact provides
deterministic bounded evidence against that risk. But it is still not a general
equivalence theorem over compilers, exporter graphs, or arbitrary model graphs.

### 5.3 Release-provenance manifests

The Hugging Face provenance line binds model, tokenizer, ONNX, transcript, and
safetensors identities to explicit local-file hashes and pinned release
coordinates. In the ONNX-facing path, that boundary now includes the exported
graph, its metadata companion, declared external-data side files, and
attestation-friendly SHA-256 subject digests alongside the repository's local
BLAKE2b-256 commitments. This is operationally valuable, especially for frozen
artifact bundles and release-verification workflows that already key on
SHA-256. It should not be confused with a proof relation or a verified
attestation pipeline. It is a release boundary, not a theorem that exporter or
supply-chain semantics are preserved.

______________________________________________________________________

## 6. Negative Results and Non-Claims

This section is the most important one to keep honest.

The repository does not yet support the following stronger claims:

1. recursive cryptographic accumulation or verifier-closed recursive
   compression,
2. incrementally verifiable computation in the formal sense of systems such as
   HyperNova, NeutronNova, ProtoStar, SnarkFold, or related folding lines,
3. general implementation-equivalence proofs over runtime/compiler frontends,
4. full standard-softmax transformer proving on the `stwo` path,
5. supply-chain attestation theorems comparable to a complete in-toto or SLSA
   provenance story.

These are not cosmetic disclaimers. They define the boundary that protects the
paper from overclaiming.

### 6.1 Why the pre-recursive claim is still worthwhile

A crypto audience may reasonably ask whether stopping before recursion is too
weak to merit a paper. The answer is no, provided the statement is precise.

Recursive systems need a stable public statement to recurse over. The current
artifact contributes exactly that:

- one decode relation,
- explicit carried-state boundaries,
- verifier-recomputed packaging commitments,
- stable semantics across richer artifact layers.

That is a meaningful intermediate result because it constrains what later
recursive work must preserve instead of leaving the statement surface implicit.

______________________________________________________________________

## 7. Threat Model and Verifier Discipline

The engineering contribution is most defensible when phrased as verifier
discipline over trusted-core boundaries.

The repository’s hardening strategy already treats the following as primary
threat classes:

- verifier acceptance of malformed or semantically drifted artifacts,
- parser or decoder unsoundness on adversarial structured input,
- runtime-semantics drift across transformer/native/Burn/ONNX lanes,
- statement drift between implementation and public artifact semantics,
- overclaiming induced by review tooling rather than evidence.

For paper 2, the relevant point is that the hardening line is aligned with the
paper’s statement surface. The step-envelope manifests, recursive-compression
input contracts, semantic-agreement artifacts, and provenance manifests are all
being tested at the exact boundaries the paper names.

That alignment matters. A crypto paper should not point to “engineering
hardening” in the abstract. It should point to the same artifact boundaries that
carry the public claim.

______________________________________________________________________

## 8. Positioning Relative to Folding and PCD

This artifact line sits adjacent to, but outside, the current recursive
literature.

Relative to folding and IVC systems, the repository contributes:

- statement stabilization over a concrete decode relation,
- explicit carried-state boundary semantics,
- packaging-layer validity conditions,
- proof-carrying pre-recursive aggregation objects,
- bounded runtime-consistency and release-provenance guardrails.

It does not contribute:

- a folding scheme,
- a recursive verifier,
- a compressed accumulator theorem,
- a knowledge-soundness theorem for recursive composition.

That distinction is not a weakness in exposition; it is the core honesty
condition of the draft.

______________________________________________________________________

## 9. Engineering Status and Next Milestones

The repository is now strong enough for this bounded paper, but not for a
stronger one.

### 9.1 Good enough now

For the bounded claim of this paper, the repository is in publishable shape
provided the prose stays disciplined:

- proof-carrying decode surfaces are real,
- carried-state packaging validity is real,
- the pre-recursive aggregation boundary is real,
- semantic-agreement artifacts are real as bounded evidence,
- provenance manifests are real as release guardrails.

### 9.2 Still missing

For a stronger follow-on paper, the missing milestones are clear:

- recursive cryptographic compression over the same decode statement,
- recursive shared-table accumulation as a compressed proof object,
- stronger exporter/provenance binding for ONNX-facing release artifacts,
- broader signed supply-chain attestations with verified builder identity,
- broader `stwo` transformer coverage beyond the current narrow experimental
  boundary.

These gaps do not invalidate the current paper. They define the next engineering
program.

______________________________________________________________________

## 10. Conclusion

The correct current claim is not “the repository already has recursive zkML
inference.” The correct claim is more disciplined and, for that reason, more
useful:

the repository already exposes a stable proof-carrying decode relation with
explicit carried-state boundaries and statement-preserving pre-recursive
packaging layers.

That is enough for a real crypto-systems paper because it gives later recursive
work a fixed public statement to preserve. The artifact is therefore not the end
state. It is the first honest recursive-adjacent boundary that does not need to
pretend recursion already exists.

______________________________________________________________________

## Selected References

- HyperNova: [https://eprint.iacr.org/2023/573](https://eprint.iacr.org/2023/573)
- ProtoStar: [https://eprint.iacr.org/2023/620](https://eprint.iacr.org/2023/620)
- NeutronNova: [https://eprint.iacr.org/2024/1606](https://eprint.iacr.org/2024/1606)
- SnarkFold: [https://eprint.iacr.org/2023/1946](https://eprint.iacr.org/2023/1946)
- SLSA provenance overview: [https://slsa.dev/provenance](https://slsa.dev/provenance)
- SLSA build provenance: [https://slsa.dev/spec/v1.2-rc2/build-provenance](https://slsa.dev/spec/v1.2-rc2/build-provenance)
- in-toto attestation framework: [https://github.com/in-toto/attestation](https://github.com/in-toto/attestation)
- GitHub artifact attestations: [https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations](https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations)
- GitHub build provenance workflow: [https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds](https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- ONNX external-data documentation: [https://onnx.ai/onnx/repo-docs/ExternalData.html](https://onnx.ai/onnx/repo-docs/ExternalData.html)
- PyTorch export IR specification: [https://docs.pytorch.org/docs/main/user_guide/torch_compiler/export/ir_spec.html](https://docs.pytorch.org/docs/main/user_guide/torch_compiler/export/ir_spec.html)
