# Changelog

## [Unreleased]

### Added
- Repository restructured for open-source publication: README rewrite,
  CONTRIBUTING, SECURITY, .gitignore, pyproject.toml, CI lint workflow.
- Full protocol/SDK reference document (`docs/Token2-OTP-SDK-Protocol.md`).
- Project relicensed under the MIT License by the copyright holder
  (Token2 Sarl). Updated headers in `app.py`, `gui/ui.py`, and
  `gui/README.GUI.html` accordingly.

### Fixed
- `transports/pcsc.py`: removed a duplicated APDU transmission in
  `PCSCTransport.send_command()` that sent every command to the device
  twice.

### Changed
- Minor docstring/comment improvements in `token2/__init__.py` and
  `transports/__init__.py`. No functional behavior changes beyond the
  PC/SC fix above.

## [0.2] - prior release

- Token2 OTP CLI Tool v0.2 (read/write/delete OTP entries, button-press HOTP
  configuration, JSON output, USB and PC/SC transports, Tkinter GUI).
