# v9.1 Preview slices ported onto upstream Pulpo1.0 main (f084863)

Branch `v91-port-f084863` in this clone. Base: upstream main
`f084863` ("fix: serialize in-memory issue_permit check-and-record;
ceremony single-use concurrency regression (#342)"). Pushed to `spikediegel-prog/Pulpo1.0-v91-port`; merged as PR #1
(`c44ca6c`), PR #2 (`4fd03d5`), and PR #3 (`cf753a9`). No PR against
Ironnember/Pulpo1.0.

Validation (Linux VM, `python3 -W error -m unittest discover -s tests`):

- pristine f084863: 453 tests OK, skipped=1
- + slice 1: 459 OK, skipped=1
- + slice 2: 466 OK, skipped=1
- + slices 1-3: 483 OK, skipped=1
- custody-service suite (`PYTHONPATH=custody-service/src:. python3 -W error
  -m unittest discover -s custody-service/tests`): 33 OK
- `proofs/pulpo-node/virtual_lamp_proof.py`: PASS (14 checks)
- `proofs/incident-response/synthetic_incident_response_proof.py`: PASS
  (14 checks)
- merged main (PRs #1-#3, `cf753a9`): 491 OK, skipped=1
- Gladiator (`scripts/run_gladiator_tournament.py`): `FINAL
  PASS_WITH_BOUNDARIES 138 10600` on this tree vs `160 10600` on Preview
  main. The runner is byte-identical to upstream and the 10600 scheduled
  operations are identical; the 22-execution gap is entirely in the
  qualification phases (state +21, evidence +3, consequence -2 on Preview)
  because the Preview test corpus is larger (1308 tests vs 486 here) — not
  a coverage loss. The proof passes; the count is not an assertion.

## Slice 1 — live purchase: pre-purchase revalidation + durable unknown outcome

Ported, adapted. `GovernanceKernel.revalidate_consumed_permit` and the
`KernelState` backends re-read existence, intent binding, spent flag, and
the directive binding for an already-spent permit; `DomainCommerceExecutor`
refuses before the provider call on a failed revalidation and records a
durable `purchase_consequence_unknown` event in the canonical audit when
the provider call raises. 6 ported tests.

Not portable upstream, omitted (see the test file's PORT NOTE):

- the expired-permit test (upstream has no permit TTL; permits never expire),
- the policy-hash-change test (upstream `consume_permit` records no
  permit<->policy/issuer binding, so there is no stored binding to re-check),
- the NULL-expiry test (upstream `issue_permit` has no `expires_at_ns`).

Coordinator route wired as a follow-on (PR #2, branch
`port/coordinator-wiring`, on top of merged PR #1): `DomainCommerceExecutor`
takes `coordinator=` and routes purchase attempts through
`GovernedDomainAttemptCoordinator` (locked-target resolution, canonical
consume, audit-tip check, custody attempt) before the provider call; the
orchestrator passes it through. The three coordinator-route tests are
ported with it (happy path, unknown outcome carrying the custody attempt
id, target/budget mismatch refusals); core suite 486 OK, skipped=1.
Correction to the original port instructions: the custody stack DOES exist
upstream — `pulpo/custody_domain.py` has
`GovernedDomainAttemptCoordinator` with the same `authorize()` /
`reserve()` / `.budget` API, and `pulpo/custody.py` has `CustodyViolation`.
The "no custody stack upstream" premise was wrong.

Still NOT there (honest limits of this follow-on): no reconciliation state
machine — an attempt whose outcome is unknown stays recorded as
`attempt_authorized`; the canonical `purchase_consequence_unknown` audit
event is the reconciliation-required record. No evidence vocabulary —
`pulpo/evidence_observation.py` and `pulpo/evidence_export.py` do not
exist upstream.

## Slice 2 — clock TOCTOU fix in kernel state

Ported, adapted. `issue_permit` / `consume_permit` (in-memory + SQLite)
accept an optional `clock=` and re-sample it after acquiring the lock /
`BEGIN IMMEDIATE`, failing closed (`StateClockError`) on a broken or
regressed clock; the regression check compares adjacent samples from the
same clock, not the audit tip. 7 ported tests.

Adapted, not carried verbatim:

- No expiry re-anchoring: upstream `issue_permit` has no `expires_at_ns`.
  The expiry-anchoring tests are omitted; the permit-expiry scenario is
  rewritten as a directive-binding-window scenario (the validity window
  that can close between sample and lock upstream).
- Upstream in-memory `consume_permit` held no lock; the fix takes the
  `_audit_lock` there, so the post-lock sample is actually post-lock.
- The recovery pin is NOT ported: upstream has no `recover` /
  `recovery_checkpoint` machinery, so `capture_recovery_pin`,
  `docs/RECOVERY_PIN_OPERATOR_STEP.md`, and the pin tests stay fork-only.

## Slice 3 — signed versioned policy envelope at kernel construction

Ported, adapted. `Policy` gains `version` / `previous_policy_hash`;
`PolicyEnvelope` (in `pulpo/authority.py`) is verified at kernel
construction against the pinned issuer trust; the accepted head is
recorded as `policy_head_accepted` in the canonical audit, and a stale or
forked head is refused. Policies with no `authority_trust` are accepted
unsigned (open issuer-enrollment decision) — that boundary is carried
over unchanged. 17 ported tests in `tests/test_policy_envelope.py`.

Adapted, not carried verbatim:

- `policy_hash_for` uses upstream f084863's `policy_hash` payload verbatim
  (including its ceremony branch, which differs from the fork's), adding
  only the version/previous-hash binding for version != 1. Verified:
  v1 hashes are bit-identical to pristine f084863, plain and
  ceremony-opted-in policies alike; a v2 hash differs from the v1 hash.
- The custody-service runtime takes the envelope from
  `PULPO_POLICY_ENVELOPE_JSON` and requires it; it does NOT gain the
  fork's audit-performance-profile machinery (upstream kernels take no
  `audit_verification_engine`).
- 15 files from the Preview slice do not exist upstream (fork-only proofs
  and tests) and were skipped.
- Beyond the slice, the envelope had to be added to call sites the slice
  did not touch: `custody-service/tests/test_api.py`,
  `test_approval_challenge.py`, `test_domain_proposal.py` (9 errors before
  the fix), `tests/test_ceremony_key_derivation.py`, the slice-1 test
  file's revoked-directive test, and two audit-count assertions in
  `tests/test_persistence.py` (the head record is now the first audit
  event). The `test_ceremony_key_derivation.py` verifiers are
  verification-only, so their envelopes are signed via the test signer
  (`sign=self.approval_signer.sign`).

## Slice 4 — evidence vocabulary (AUTHORIZED / ATTEMPTED / CONSEQUENCE UNKNOWN)

NOT ported as code. The slice patches `pulpo/evidence_observation.py`
and `pulpo/evidence_export.py`, which do not exist upstream, so there is
no file to patch and the diff cannot cherry-pick. Nothing was forced.

What transfers as design: the `STATE_OUTCOMES` mapping terms are
identical upstream — `pulpo/custody.py` has the same lifecycle constants
(`attempt_authorized`, `attempt_claimed`, `request_transmitted`,
`reconciliation_required`, `reconciled_success`, `reconciled_failure`,
`unresolved`) and `pulpo/effect_reconcile.py` has the same `"uncertain"`
status — so the mapping itself needs no adaptation.

What upstream would need for this slice to port as code: the evidence
modules themselves (`evidence_observation.py` /
`evidence_export.py`, i.e. the `EvidenceEvent` / `EvidenceObservation`
contract, the `OUTCOMES` / `EVENT_NAMES` enums, and the
`freeze_evidence_observation` / `export_evidence_observation`
projection), plus `tests/test_evidence_vocabulary.py`. That is a
port of the Preview evidence-export surface, not a change to the
vocabulary mapping. Until then, the unknown-outcome evidence from slice 1
(`purchase_consequence_unknown` in the canonical audit) exists upstream
without the unified evidence projection.
