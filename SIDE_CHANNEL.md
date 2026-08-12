# Side-Channel Considerations

herringfish is a mathematical analysis toolkit, not a production cryptographic implementation.

## Scope

- This project analyzes algebraic and differential properties of hash functions in an idealized model.
- It does not implement constant-time primitives or side-channel hardened code paths.

## Recommendations for real use

- Do not deploy analysis code in production.
- If implementing primitives for evaluation, use constant-time operations, avoid secret-dependent branches, and validate with side-channel tests.
- For Keccak-f and SHA-256, use audited libraries e.g., rust-crypto, ring, or openssl.

## Research notes

- Differential and linear trails are computed on reduced-round models. Actual probability estimates may differ due to implementation artifacts.
- Message schedule propagation is modeled symbolically; timing characteristics are not evaluated.

## Disclaimer

This document does not constitute security assurance for any implementation.
