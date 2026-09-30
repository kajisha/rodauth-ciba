# Missing-client-authentication fix: Jev reassessment

Evaluated commit: [3791a53caae7ab6fbe6793fdb1646d7e5074c951](https://github.com/kajisha/rodauth-ciba/commit/3791a53caae7ab6fbe6793fdb1646d7e5074c951).
Model: `jev-1.13.0`. Evidence was supplied inline from this committed source;
the model was not assumed to browse GitHub. No prior numerical scores were supplied.

## Results

| Question | Result | Confidence |
| --- | --- | --- |
| Absent client authentication at Backchannel and CIBA poll endpoints | supported | 0.97 |
| Evidence strength for the correction (0–4) | 3.95 | 0.96 |
| Complete CIBA-147 coverage across all optional authentication paths | partial | 0.98 |

The first result has a supported selection probability of0.99. Confidence and
selection probability are distinct model outputs; neither is proof of correctness.
The score concerns this correction, not overall gem conformance or certification.
Jev returned typed judgments only; the interpretation below is the maintainer's.

## Evidence and interpretation

CIBA Core section13 classifies absent client authentication as401 invalid_client.
The fix replaces the old400 invalid_request branch with upstream
`authorization_required`, while retaining the CIBA-only boundary. Regression tests
verify both endpoints, the authentication challenge, preservation of approved
requests, absence of unauthorized grants, and successful authenticated retry.

- Before the fix:2 regression tests failed with expected401 versus actual400.
- Focused final run:8 tests /171 assertions, no failures/errors/skips.
- Full final run:410 tests /10,844 assertions, no failures/errors, two existing
  SQLite row-lock skips.

The concrete defect is addressed. Full coverage of every enabled optional
client-authentication error path remains outside this narrow reassessment; the
partial result does not itself identify an additional defect.

## Reproducible evidence

- [Exact submitted evidence and questions](request.json)
- [Raw Jev response](response.json)
- [Failing regression before the fix](../../validation/missing-client-auth-red.txt)
- [Passing targeted regressions](../../validation/missing-client-auth-targeted.txt)
- [Final full test run](../../validation/missing-client-auth-final.txt)
- [CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)

The retained `missing-client-auth-full.txt` log is an intermediate failing run
before two obsolete400 expectations were updated. It is superseded by the final
full run above.
