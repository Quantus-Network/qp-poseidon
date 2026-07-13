/-
  CI axiom-footprint gate for the two capstone theorems that together cover
  the package's full assurance surface: `goldilocks_tier1` (functional
  congruence + closure) and `goldilocks_tier1_safety` (no-UB/no-wrap).

  The shell step in `.github/workflows/ci.yml` runs this file and parses each
  `#print axioms` line, asserting for BOTH theorems the complete allow-list of
  standard Lean axioms: `{propext, Classical.choice, Quot.sound}` — in
  particular no placeholder axiom, no `Lean.ofReduceBool`, and no custom
  `axiom` declaration smuggled into any lemma either capstone depends on.
  Import-only; not part of `defaultTargets`.
-/
import GoldilocksSpec

#print axioms GoldilocksSpec.goldilocks_tier1
#print axioms GoldilocksSpec.goldilocks_tier1_safety
