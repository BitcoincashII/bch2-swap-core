// brand-compile-tests.ts — compile-time (`tsc --noEmit`) proofs that the fund-safety GATES are STRUCTURALLY required.
//
// These functions are NEVER executed; the `@ts-expect-error` directives are the whole point. They live in a NON-test
// `.ts` file (NOT `*.test.ts`) on purpose: `tsconfig.json` EXCLUDES `**/*.test.ts` from `tsc --noEmit`, so if these
// checks lived only in swap-controller.test.ts an accidental brand regression — a method dropping its required
// FundProof / RevealAuthorization, or accepting the WRONG brand — would compile silently, leaving the fix #1
// non-interchangeable-brands guarantee UNGUARDED. Here `tsc --noEmit` DOES compile them, so:
//   • an UNUSED `@ts-expect-error` (the call unexpectedly type-checks, i.e. a required proof became optional / a brand
//     became interchangeable) FAILS the typecheck, and
//   • a real brand regression (the wrong-brand call newly type-checks) FAILS the typecheck.
// The smoke `it(...)` assertions in swap-controller.test.ts import these to keep them referenced (and prove they load).
//
// `import type` for SwapController keeps this a purely type-level check with NO runtime import (the functions never
// run), which also avoids a runtime circular import with swap-controller.ts.

import type { SwapController } from './swap-controller';
import type { FundProof, RevealAuthorization } from './gates';

/** fundLegY STRUCTURALLY requires a FundProof (no-arg / wrong-brand must NOT compile). */
export async function _fundLegYCompileCheck(ctrl: SwapController, ra: RevealAuthorization): Promise<void> {
  // @ts-expect-error fundLegY requires a FundProof — a no-arg call must NOT compile (safe-by-default, design §4).
  await ctrl.fundLegY();
  // @ts-expect-error a RevealAuthorization is NOT a FundProof — the two brands are non-interchangeable (fix #1).
  await ctrl.fundLegY(ra);
}

/** revealAndClaim STRUCTURALLY requires a RevealAuthorization (no-arg / wrong-brand must NOT compile). */
export async function _revealAndClaimCompileCheck(ctrl: SwapController, fp: FundProof): Promise<void> {
  // @ts-expect-error revealAndClaim requires a RevealAuthorization — a no-arg call must NOT compile (fix #3 / §4).
  await ctrl.revealAndClaim();
  // @ts-expect-error a FundProof is NOT a RevealAuthorization — the two brands are non-interchangeable (fix #1).
  await ctrl.revealAndClaim(fp);
}

/** lockEvm STRUCTURALLY requires a FundProof (no-arg / wrong-brand must NOT compile). */
export async function _lockEvmCompileCheck(ctrl: SwapController, ra: RevealAuthorization): Promise<void> {
  // @ts-expect-error lockEvm requires a FundProof — a no-arg call must NOT compile (safe-by-default, design §4).
  await ctrl.lockEvm();
  // @ts-expect-error a RevealAuthorization is NOT a FundProof — the two brands are non-interchangeable (fix #1).
  await ctrl.lockEvm(ra);
}

/** revealAndClaimEvm STRUCTURALLY requires a RevealAuthorization (no-arg / wrong-brand must NOT compile). */
export async function _revealAndClaimEvmCompileCheck(ctrl: SwapController, fp: FundProof): Promise<void> {
  // @ts-expect-error revealAndClaimEvm requires a RevealAuthorization — a no-arg call must NOT compile (fix #3 / §4).
  await ctrl.revealAndClaimEvm();
  // @ts-expect-error a FundProof is NOT a RevealAuthorization — the two brands are non-interchangeable (fix #1).
  await ctrl.revealAndClaimEvm(fp);
}
