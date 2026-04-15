# Appendix D. Artifact-To-Claim Map

This appendix maps the main paper’s language to concrete repository artifact
surfaces.

## D1. Carried-state and packaging line

| Repository surface | Publication-facing description | Claim status |
| --- | --- | --- |
| Phase 24 state-relation accumulator | carried-state relation accumulator over cumulative prefixes | inside proof-carrying decode surface |
| Phase 25 intervalized state relation | honest interval bundle over rebased carried-state prefixes | inside proof-carrying decode surface |
| Phase 26 folded intervalized state relation | bounded folded packaging over interval artifacts | inside proof-carrying decode surface; still pre-recursive |
| Phase 27 chained folded intervalized state relation | chained fold-of-folds packaging over real intervals | inside proof-carrying decode surface; still pre-recursive |
| Phase 28 aggregated chained folded intervalized state relation | proof-carrying pre-recursive aggregation boundary | inside proof-carrying decode surface; still pre-recursive |
| Phase 29 recursive-compression input contract | recursive-adjacent input boundary derived from a verified Phase 28 aggregate | boundary artifact only; not recursive proof closure |
| Phase 30 decoding step proof envelope manifest | ordered manifest binding step proofs, boundaries, and package commitments | statement-preserving manifest layer; not recursive proof closure |

## D2. Adjacent evidence surfaces

| Repository surface | Publication-facing description | Claim status |
| --- | --- | --- |
| `research-v3-equivalence` | bounded multi-runtime semantic-agreement artifact | operational evidence; not part of the proof relation |
| HF provenance manifest | release-provenance manifest for model and artifact identity | reproducibility guardrail; not part of the proof relation |
| `stwo-experimental-v1` frozen bundle | narrow experimental S-two evidence tier | evidence tier, not a broad production claim |
| vanilla `production-v1` bundle | frozen reproducibility baseline | primary reproducibility tier |

## D3. Why this map matters

The paper becomes much clearer once each artifact family is assigned one of only
three roles:

- inside the proof-carrying decode relation,
- adjacent operational evidence,
- release/reproducibility provenance.

That separation prevents accidental escalation from “artifact exists” to “the
artifact proves more than it actually proves.”
