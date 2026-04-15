# Appendix B. Positioning Against IVC, Folding, and PCD

This appendix is written for readers who want the recursive-systems distinction
stated plainly.

## B1. What the repository does

The repository currently provides:

- proof-bearing step and chain artifacts,
- explicit carried-state boundary tuples,
- verifier-recomputed package commitments,
- ordered packaging layers over verified members,
- a pre-recursive aggregation boundary,
- a recursive-compression input contract that remains an input-boundary artifact,
  not a recursive proof system.

## B2. What recursive systems additionally provide

Recursive proof-carrying data, IVC, and folding systems aim to provide one or
more of the following:

- a verifier whose output becomes the next proof input,
- asymptotic or practical proof-size compression across many steps,
- recursive soundness over composed instances,
- formal accumulation or folding theorems over committed instances.

Those properties are outside the present repository claim.

## B3. Correct comparison language

The right comparison language is:

- “recursive-adjacent artifact boundary”
- “pre-recursive aggregation”
- “statement-preserving packaging over a fixed decode relation”
- “future recursive consumer of the same public statement”

The wrong comparison language is:

- “already an IVC system”
- “already recursive proof-carrying data”
- “already a folding construction”
- “already compressed recursive verification”

## B4. Why this distinction matters

For a crypto audience, overclaiming here would be fatal. The paper becomes
stronger, not weaker, by separating:

- what the artifact already proves,
- what it only packages,
- what later recursive systems could consume,
- what remains unimplemented.
