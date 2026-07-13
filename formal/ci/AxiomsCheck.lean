/-
  CI axiom-footprint gate for the capstone `goldilocks_tier1` theorem.

  The shell step in `.github/workflows/ci.yml` runs this file and parses
  `#print axioms` output, asserting the complete allow-list of standard Lean
  axioms: `{propext, Classical.choice, Quot.sound}` — in particular no
  placeholder axiom and no `Lean.ofReduceBool`. Import-only; not part of
  `defaultTargets`.
-/
import GoldilocksSpec

#print axioms GoldilocksSpec.goldilocks_tier1
