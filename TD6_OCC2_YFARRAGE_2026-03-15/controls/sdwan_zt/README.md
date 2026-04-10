# SD-WAN / Zero Trust — Out of Scope (TD1–TD6)

This directory is reserved for future Zero Trust Network Access (ZTNA) controls,
as specified in the TD6 repository standard.

It was not implemented during TD1–TD6 due to scope constraints:
- SD-WAN overlay was not required for the two-site cloud-hybrid lab
- ZT pilot is planned in the 60-day roadmap (see report/30_60_90_Plan.md)

Planned next steps:
- 60 days: Vault SSH CA for short-lived certificate issuance (replaces raw SSH)
- 90 days: Migrate IPsec auth to X.509 (strongSwan PKI)
