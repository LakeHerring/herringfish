# Herringfish Compliance Statement

**Status:** Experimental research project – not compliant for production use.

## Scope
Herringfish is an experimental symmetric-key cryptography research project. It is not a standardized or approved cryptographic primitive.

## Standards
* Herringfish Feistel ARX v0.2 is not NIST-approved, not FIPS validated, and not included in any formal standards body.
* The construction uses SHAKE256 from the SHA-3 family, which is standardized in NIST FIPS 202. SHAKE256 is used only for key schedule and S-box derivation, not as a hash for data integrity.
* No claims of compliance with common cryptographic certification regimes such as Common Criteria, ISO/IEC 15408, or PCI DSS are made.

## Intended Use
* Research, experimentation, education, and cryptanalysis only.
* Must not be used to protect real-world secrets, production systems, passwords, financial information, or other sensitive data.

## Limitations
* Has not undergone independent public cryptanalysis.
* No formal security proof.
* Reference implementation is not constant-time by default.
* No AEAD construction, no formal security model, no production hardening.

## Reporting
Any compliance or certification claim regarding Herringfish must be supported by independent review and documented evidence. The project maintainers do not assert compliance with any production cryptographic standard.

**Design it. Implement it. Test it. Break it. Improve it.**
