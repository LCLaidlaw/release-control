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

## Scope

Keep this repository small, generic, and independent from any private application repository.
