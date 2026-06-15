# Contributing to Token2 OTP CLI Tool

Thanks for your interest in improving this project! Contributions of all
kinds are welcome — bug reports, documentation fixes, new features, and
protocol/transport improvements.

This project is licensed under the [MIT License](LICENSE); by contributing,
you agree that your contributions will be licensed under the same terms.

## Getting started

1. **Fork** the repository and clone your fork:

   ```bash
   git clone https://github.com/<your-username>/token2-otp-cli.git
   cd token2-otp-cli
   ```

2. **Set up a virtual environment** and install dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Create a branch** for your change:

   ```bash
   git checkout -b feature/my-improvement
   ```

## Hardware requirements

Most of this project's functionality requires a physical Token2 T2F2 / PIN+
security key connected via USB or a PC/SC (NFC) reader. If you don't have
hardware available, you can still contribute to:

- Documentation (`README.md`, `docs/Token2-OTP-SDK-Protocol.md`)
- Argument parsing / validation logic (`cli_args/`)
- Data structure serialization (`token2/data_structures.py`)
- GUI code review (`gui/`)

When submitting hardware-dependent changes, please describe how you tested
them (device model, transport used — USB or NFC).

## Code style

- Follow existing code conventions (PEP 8 where practical).
- Keep functions small and focused; prefer clear names over abbreviations.
- Add docstrings/comments for non-obvious protocol or transport details —
  cross-reference [docs/Token2-OTP-SDK-Protocol.md](docs/Token2-OTP-SDK-Protocol.md)
  where relevant.
- Avoid introducing new third-party dependencies unless necessary; if you
  do, update `requirements.txt` and explain why in your PR description.

## Reporting bugs

When filing an issue, please include:

- Your OS and Python version
- The exact command you ran (redact any secret/seed values!)
- The transport used (USB or NFC/PC-SC) and reader/device model if relevant
- Full error output (run with `DEBUG_COMMS=1` for protocol-level traces)

```bash
DEBUG_COMMS=1 python3 app.py get_all
```

## Security issues

**Do not open a public issue for security vulnerabilities.** Seed material
and device-bricking risks (see the "Hardware-safety warning" in
[docs/Token2-OTP-SDK-Protocol.md](docs/Token2-OTP-SDK-Protocol.md)) should be
reported privately — see [SECURITY.md](SECURITY.md).

## Submitting a pull request

1. Make sure your branch is up to date with `main`.
2. Test your changes against real hardware where applicable.
3. Update documentation (`README.md`, protocol doc) if behavior changes.
4. Open a PR with a clear description of the change and motivation.
5. Be responsive to review feedback — small, focused PRs are easiest to
   review and merge.

## Code of conduct

Be respectful and constructive. We want this to be a welcoming project for
contributors of all experience levels.
