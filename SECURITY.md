# Security Policy

## Reporting a vulnerability

Report a suspected vulnerability in provii-crypto to **security@provii.app**. Do not open a public issue for a security-affecting finding before it has been triaged.

Where you can, include the crate name, the function or constant involved, a reproduction case, and your assessment of impact. Cryptographic findings (proof soundness, side-channel leaks, commitment binding failures) receive expedited triage.

We acknowledge a report within five business days and keep you updated as we investigate.

## Scope

This repository contains the cryptographic core of the Provii protocol: zero knowledge proof circuits, commitment schemes, signature primitives, and protocol helpers. Findings of interest include errors in domain separation tags, circuit constraint soundness, non-constant-time handling of secret material, and any path that leaks witness data.

Vulnerabilities in a deployed Provii service belong in that service's own repository.

## Disclosure

We follow coordinated disclosure. Once a fix is merged and released, we credit reporters who want it.
