# Alignment alternatives: second Jev review

2026-09-30. The user accepted atomic rollback and the original initial-release scope as the baseline, then explicitly requested reconsidering non-recommended alternatives with Jev. This is a new comparison requested by the user, not a rerun to manufacture a higher score.

Status: **response received through the user's successful terminal execution**, then inspected from disk. Model jev-1.13.0; usage 6889 input / 540 output tokens. [Request](jev-alignment-alternatives-request.json), [response](jev-alignment-alternatives-response.json), [earlier failed assistant attempt](jev-alignment-alternatives-attempt.json). The first-round artifacts remain unchanged.

## Results

| Question | Probabilities | Confidence |
|---|---|---|
| Transaction, actual facts | atomic rollback .75; durable consumption .12; terminal failure .10; need evidence .03; configurable .00 | .68 |
| Strongest atomicity objection | retry semantics .62; external effects .36; future API .02; none .00; unknown .00 | .53 |
| If crash-durable no-retry is explicitly required | durable consumption .97; need evidence .02; terminal failure .01; atomic .00; configurable .00 | .96 |
| If two adopters require incompatible policies | configurable .89; terminal failure .10; need evidence .01; atomic .00; durable .00 | .86 |
| Scope, actual facts | staged parity .83; initial-only .16; broader before release .01; need evidence .00 | .77 |
| Strongest initial-only objection | alignment meaning .48; public API evolution .44; interoperability reach .04; none .04; unknown .00 | .34 |
| If first customer needs ping only | targeted ping 1.00; full parity .00; poll unchanged .00; defer .00; need evidence .00 | 1.00 |
| Most valuable next evidence | concrete deployment contract .78; real failure tests .22; optional features .00; repeat scores .00; none .00 | .72 |

The actual-fact transaction and scope choices meet the predeclared top-probability/lead heuristic. The strongest-objection questions do not: in particular the two scope objections are nearly tied. Hypothetical results are not findings that those deployments exist. Reported 1.00 is a rounded model judgment, not certainty of correctness.

## Assistant's revised recommendation

Maintain atomic rollback for the initial release. Change the previous initial-only/no-roadmap recommendation to **staged alignment with a broader compatibility roadmap**. The initial release still targets poll/login_hint; it is a milestone, not the final definition of the user's alignment objective. This is a recommendation resulting from the requested reconsideration, not a claim that the user already approved every future feature or that the overall goal is achieved.

The reason for revising the scope recommendation is the broader stated alignment goal and the risk of fixing a public request/consent API that obstructs later claims, resources or hints. The .83 preference supports that tradeoff; it is not a factual proof or a textual rationale authored by Jev. The old and new probabilities are not directly comparable because candidate sets and question framing changed.

Concrete proposed contract:

- A failed issuance before DB commit rolls back participating token/request changes and permits retry while the request remains valid. It does not roll back external side effects.
- Successful committed issuance is one-time. Losing the HTTP response does not permit reissuance; an unexpired replay triggers the existing Grant/token revocation behavior.
- Transactional hooks own same-DB work; external actions require an application contract for idempotency or an outbox. This gem does not silently supply delivery guarantees.
- Initial release keeps the agreed subset and lists every unimplemented capability. Before freezing the public API, review how the saved request and consent representations can evolve. The roadmap tracks each additional node capability and its verification requirements without claiming parity before it is implemented.

Conditional alternatives remain valid: adopt durable consumption if crash-durable no-retry becomes an explicit deployment requirement; consider configuration when actual adopters require both incompatible policies; add ping specifically when an initial client needs it rather than bundling unrelated features. Do not implement these speculative branches now.

The user subsequently accepted this recommendation. [ADR 0004](../adr/0004-retain-atomic-issuance-and-stage-alignment.md), the [failure contract](../failure-contract.md) and [staged roadmap](../alignment-roadmap.md) record that decision. This does not establish the initial application's actual retry or external-effect behavior: verify those against the contract under faults. DB and complete-OP tests remain necessary; the .78 next-step result does not waive them. No further identical model queries are needed, and no runtime behavior has been changed by this review.

Run:

```sh
python3 bin/ask-jev-alignment.py --review alternatives
```

## Strongest cases considered by the assistant before the response

| Alternative | Credible benefit | Cost / boundary |
|---|---|---|
| Independently durable consumption | Matches a deliberately strict one-attempt contract, including post-consumption crashes | A technical failure may require another customer approval; concurrent revocation and hook boundaries need new tests |
| Outer consumption transaction plus inner issuance savepoint | A caught issuance exception can roll back token/hook DB writes while committing terminal consumption | Process death or rollback of an application-owned outer transaction still restores consumption; this is not equivalent crash durability |
| Configurable transaction policy | Can serve real deployments with incompatible retry contracts | More public API and verification paths; two such adopters have not been identified |
| Committed staged parity | Keeps the initial release small while explicitly designing for broader compatibility | Future roadmap commitment and cost without a named consumer |
| Broader parity before publication | Broader interoperability and an opportunity to avoid early breaking API changes | Larger implementation/security test surface before release; current consumer does not require the extra features |

These are assistant-authored tradeoffs, not Jev explanations. The meaningful objection to initial-only scope is not simply feature count: a request/consent model that cannot grow may impose later breaking changes. The meaningful objection to atomic rollback is whether the intended client contract requires strict no-retry behavior after a failed issuance attempt. Neither concern is automatically resolved by a high model score.

## Eight independent numeric judgments

1. Transaction choice on actual facts, including the new terminal-failure alternative.
2. Strongest objection to atomic rollback (a concern, not a decision to reject it).
3. Transaction choice if a named deployment requires crash-durable no-retry behavior.
4. Transaction choice if two committed adopters require incompatible retry policies.
5. Release-scope choice on actual facts.
6. Strongest objection to initial-only scope.
7. Scope choice if the initial customer specifically requires ping but no other added features.
8. Next evidence most likely to change the transaction recommendation.

Counterfactual questions are explicitly marked; their premises are not current requirements. Prior Jev numbers and the assistant's favored policy are withheld from this request. Earlier user scope and actual technical constraints remain in the state.

## Interpretation

Use the previously declared clear-preference heuristic (top >= .70 and lead >= .20) only as a review aid, not a correctness guarantee. Retain all probabilities and confidence. Do not compare changes in first/second-round percentages as measured improvement: the candidate set and questions differ. A strongest-objection winner is not itself a rejection of the baseline. A hypothetical winner is a conditional switch rule, not permission to change today's implementation.

After receiving results, report actual-fact choices, strongest objections, and explicit switch conditions separately. Change a recommendation only if the evidence/premise that warrants the change is stated. No runtime policy was changed for this review.
