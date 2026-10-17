# Release Control

A minimal repository for approval-gated operational workflows.

## Purpose

This repository exists only to provide a controlled approval point for sensitive infrastructure actions.

## Security boundaries

- No application source code.
- No Terraform state.
- No secret values.
- No private repository contents.
- No customer data.
- No long-lived cloud credentials.
- Privileged actions must require explicit human approval.
- Cloud access, when added, must use short-lived OIDC credentials and least-privilege permissions.

## Open approval window

`.github/workflows/open-window.yml` is the only privileged workflow. It never runs infrastructure changes itself.

1. **Dispatch** it manually on `main` with two inputs:
   - `digest`: the sha256 of a plan that was reviewed elsewhere;
   - `minutes`: how long the window stays open, from 5 to 60.
2. **Validation.** A first job checks the inputs. It has no cloud credentials.
3. **Approval.** The second job runs in the `staging-infra` environment. It waits for the required reviewer, and only after approval does it receive a GitHub OIDC token.
4. **Exchange.** It exchanges that token through Workload Identity Federation for a five-minute token as a narrow gate service account.
5. **Open and record.** With that token it does two things, in this order:
   - **opens the window.** It adds one `roles/iam.workloadIdentityUser` binding for a single configured principal on a single target service account, with the condition `request.time < <expiry>`. Earlier window bindings for that principal are removed. Every other binding is left untouched.
   - **records the approval.** It writes `approvals/<digest>.json` (digest, expiry, run id) to a bucket. This is create-only: an existing record is never overwritten, so each digest can be approved at most once. A failed run that never wrote the record can be retried for the same digest; once a record exists, a new approval needs a new plan.

The system that holds the plan is expected to apply only when:
- the plan's digest matches an unexpired approval record;
- the target account's policy contains nothing beyond the gate binding and live windows.

Configuration lives in the protected environment's **secrets**, not variables: `WIF_PROVIDER`, `GATE_SA`, `TARGET_SA`, `MEMBER` and `APPROVAL_BUCKET`. GitHub therefore masks them everywhere, including step headers, and releases them only to the approved job. Logs show only the digest and the expiry time. Errors show only the failing step and its HTTP status, never a response body.

The cloud side is expected to trust only this repository, `main`, the `staging-infra` environment, `workflow_dispatch`, this workflow file and a pinned workflow commit. Any change to this repository therefore needs the trust to be re-pinned before it can run with privilege.

`checks.yml` runs the unit tests in `tests/` with no credentials.

## Scope

Keep this repository small, generic, and independent from any private application repository.
