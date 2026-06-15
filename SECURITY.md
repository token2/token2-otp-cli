# Security Policy

## Reporting a vulnerability

If you discover a security issue — including but not limited to:

- a flaw in the ECDH/AES seed-encryption implementation,
- a way to extract OTP seeds without authorization,
- a command sequence that can brick or lock out a device,
- or any other issue with security impact,

please **do not open a public GitHub issue**. Instead, report it privately
to the maintainers (see repository contact details) or to Token2 support at
`support@token2.com`.

Please include:

- A description of the issue and its impact
- Steps to reproduce (with any sensitive seed values redacted/replaced)
- Affected device model(s) and transport (USB/NFC)

## Scope notes

- This tool implements the **OTP management protocol** described in
  [docs/Token2-OTP-SDK-Protocol.md](docs/Token2-OTP-SDK-Protocol.md), not the
  device's FIDO2/CTAP2 interface.
- TOTP/HOTP are shared-secret schemes by design; loss of a seed compromises
  future codes for that account. This is an inherent property of OTP, not a
  bug in this tool — but please report any way this tool itself could leak
  seeds (e.g. via logs, error messages, or insecure storage).
- The protocol document's "Hardware-safety warning" section describes
  device-configuration commands that can disable all communication
  interfaces if misused. Reports related to this are welcome.
