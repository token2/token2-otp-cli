# Token2 OTP — Protocol & SDK Reference
 
A **language-agnostic** specification for talking to Token2 T2F2 / PIN+ hardware security keys to manage their on-device TOTP/HOTP entries. The wire protocol is cross-referenced against the vendor's *OTP on FIDO Command Manual* (sections 1.1–1.11). The SDK shape, validation rules, transport framing, and worked examples are drawn from the official Python `Token2 OTP CLI Tool v0.2`. Together they are sufficient to re-implement a compatible client in any language with HID and/or PC/SC bindings, an EC-DH primitive (NIST P-256), an AES-CBC primitive, and SHA-256.

> **Scope.** This is the **management protocol** — provisioning seeds, listing entries, reading codes, configuring the button-press HOTP, and reading device configuration. It is *not* CTAP/FIDO2. The same hardware also speaks FIDO2 on its standard interface; that is documented separately by the FIDO Alliance specs.
>
> **⚠️ Security posture — prefer FIDO2 over OTP wherever possible.** TOTP and HOTP are **shared-secret** schemes and are **not phishing-resistant**: a code typed into a lookalike site is replayable by the attacker within its validity window, and a seed that leaks (from the provisioning channel, from a backup, from a screenshot of a QR code) compromises every future code. Native FIDO protocols (WebAuthn / CTAP2) bind the credential to the origin and use challenge-response over the authenticator's secure element, defeating phishing and replay by construction. **Use FIDO2 for any account that supports it.** This document exists so OTP can still be supported on legacy services that don't accept WebAuthn — not as an endorsement of OTP for new deployments.
>
> **⚠️ Hardware-safety warning — APDU is a foot-gun.** The companion app and other officially released Token2 tools include guardrails on top of this protocol. Speaking APDU directly **bypasses those guardrails**, and several commands documented here can put the device in an unusable state if used carelessly. The most important example: `SET_DEVICE_TYPE` (§6.8) takes a bitmask of interfaces to *disable*. The firmware does **not** refuse a mask that disables every interface — if you send a value that turns off HID-FIDO, the keyboard channel, **and** CCID at once, the device has no way to be talked to and is effectively bricked. The companion app validates that at least one channel remains active before sending; **a direct APDU client must implement the same check itself.** The same caution applies to any future commands added to the device-config family. Treat this protocol as you would a firmware-update tool: do not use it on a production device until you have rehearsed the call on a test unit, and always read the device state via `READ_CONFIG` (§6.9) before sending a write that changes interface availability.
>
> **Provenance per command.** Every command in §6 is documented in the vendor manual *except* §6.10 (Read Serial Number / `80 33 00 00`), which is not in the manual but is implemented by the reference client against the FIDO applet. Treat §6.10 as observed-behavior-from-the-reference; everything else is vendor-authoritative.

---

## 1. High-level model

The device stores a list of OTP *entries*. Each entry is uniquely keyed by the tuple `(app_name, account_name)`. The host issues **APDU**-framed commands over one of two transports (USB-HID or PC/SC), and the device replies with a payload plus a 2-byte ISO-7816 status word.

There are four classes of operation:

| Class | Examples | Encryption |
|---|---|---|
| Read | enumerate, read-one, read-config, read-serial | plain |
| Seed write / delete | write-entry, delete-entry, erase-all, set-btn-seed, delete-btn-seed | ECDH+AES for the payload |
| Device / TOTP / HOTP-keystroke config | enable-TOTP, set-device-type, cfg-HOTP-enter, cfg-HOTP-touch, cfg-HOTP-kbd | plain (single config byte) |
| Get pubkey | obtain device's ECDH pubkey | n/a (pubkey is the response) |

All multi-byte integers on the wire are **big-endian**. All length-prefixed strings are **one-byte length followed by raw bytes**, ASCII unless noted.

---

## 2. Identifying the device

### 2.1 USB-HID

Pick the first HID device matching either:

* `vendor_id == 0x349E` (decimal 13470), **or**
* `manufacturer_string == "TOKEN2"` AND `product_string == "FIDO2 Security Key"`.

Open it as a feature-report HID device. No interface claiming beyond what your HID library already does.

The reference Linux udev rule:

```
SUBSYSTEM=="usb", ATTR{idVendor}=="349e", ATTR{idProduct}=="0022",
  MODE="0660", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl"
```

### 2.2 PC/SC (NFC or contact reader)

Enumerate readers, connect to each in turn, and try to `SELECT` the management applet. The first reader that accepts the SELECT is the device.

```
SELECT AID  = F0 00 00 01 4F 74 70 01      (8 bytes, "Otp\x01" prefixed)
APDU header = 00 A4 04 00                  (ISO SELECT by name)
Lc form     = short (single byte)
```

So the raw command is: `00 A4 04 00 08 F0 00 00 01 4F 74 70 01` and a success status `90 00` confirms.

> **Note on serial number over NFC.** Reading the serial number requires switching the active applet to FIDO first (see §6.7). Some readers/models will refuse this without administrator privileges; this is expected.

---

## 3. APDU framing

The on-the-wire APDU has the conventional ISO-7816 form:

```
[CLA] [INS] [P1] [P2] [Lc...] [Data...]
```

* **CLA/INS/P1/P2** — one byte each. The command table in §6 gives them.
* **Lc** — length of `Data`. Two forms:
  * **Short** (used for PC/SC SELECT only): one byte, `Lc = len(Data)`. Allowed only when `len(Data) ≤ 255` and `len(Data) > 0`.
  * **Extended** (used for everything else): three bytes, `00 || Lc_hi || Lc_lo` (big-endian 16-bit).
* **Le** — not used. The device returns whatever it has.

The response is `[Data...] [SW1] [SW2]`. The last two bytes are the status word; everything before them is the response data (which may be empty).

### 3.1 Status words

| SW (hex) | Meaning | How to surface |
|---|---|---|
| `90 00` | Success | normal return |
| `6A 80` | Entry not found | `EntryNotFound` |
| `6A 83` | Entry not found (alt) | `EntryNotFound` |
| `6A 84` | Not enough space on device | `NotEnoughSpace` |
| `6A 86` | HOTP-over-HID not supported on this model | `HIDNotSupported` |
| `6F F9` | Timed out waiting for button press | `ButtonPressRequired` |
| any other ≠ `90 00` | Unexpected | `BadStatusCode` |

`EntryNotFound` is also raised on a clean `enum_codes` against an empty token — the caller should treat it as "zero entries", not an error.

---

## 4. USB-HID transport

USB-HID does not natively carry APDUs, so they are chunked across **64-byte feature reports**. Each report on the wire is 65 bytes total — a leading **HID report ID byte of `0x00`** plus 64 bytes of payload — but only the 64 payload bytes are "the frame".

### 4.1 Frame layout (64 bytes of payload)

```
offset 0 : 0x00                            (HID report ID, prepended by host stack)
offset 1 : 0x21                            (magic / channel)
offset 2 : flags<<4 | msg_id&0x0F          (sequence + flags byte)
offset 3 : chunk length (≤ 61)
offset 4..4+len : chunk data
remainder       : zero padding to 65 bytes total
```

The two-byte prefix `00 21` is fixed.

### 4.2 Flags byte (byte at offset 2 of the 64-byte payload)

The low 4 bits are a wrap-around message counter starting at 0. The high nibble carries flags:

| Flag (high nibble) | Direction | Meaning |
|---|---|---|
| `0x20` | host → device, device → host | more chunks follow |
| `0xC0` | device → host only | command still in progress; host should poll again |
| `0x00` | both | last/only chunk |

### 4.3 Sending a command (host → device)

1. Serialize the APDU (extended-length form).
2. Split into chunks of **at most 61 bytes**.
3. For each chunk *i* (zero-based):
   * `flags = 0x20 if not_last else 0x00`
   * `seq = i mod 16`
   * `byte_2 = flags | seq`
4. Build the 64-byte payload: `21 || byte_2 || len(chunk) || chunk || 00…00`.
5. Prepend HID report ID `00`, send as feature report. (Most HID libraries take the report ID as the first byte of the buffer.)

### 4.4 Receiving a response (device → host)

Loop, reading 65-byte feature reports (report ID `0x00` + 64 payload bytes):

1. Verify the first two payload bytes are `00 21`. (Hosts that drop the leading report ID will see the magic at offsets 0..1; check accordingly.)
2. `flags = payload[2] & 0xF0`, `seq = payload[2] & 0x0F`.
3. **If `flags == 0xC0`**: device says "still working". Do **not** advance the counter, do **not** append to the buffer — just poll again. After ~3 such retries, if `detect_btn_wait` was set, invoke the "please press the button" callback once.
4. Otherwise: verify `seq == received_count mod 16`, increment `received_count`.
5. `more = (flags & 0x20) != 0`. Read `len = payload[3]` bytes from `payload[4..4+len]` and append to the response buffer.
6. Stop when `more` is false.

The accumulated buffer is `[APDU response data] || [SW1] [SW2]`. Strip and check the trailing status word per §3.1.

---

## 5. PC/SC transport

PC/SC handles framing natively. After SELECT (§2.2), every APDU is sent as-is via `Transmit`. The card returns `(data_bytes, SW1, SW2)`; treat `SW1||SW2` as the status word.

There is **no** button-press polling on PC/SC — the device responds when it responds. (HOTP entries are still bound by the user touching the field, but PC/SC is exclusively used over NFC where a touch is implicit, and the firmware adapts.)

> **Idiosyncrasy in the reference implementation.** When reading the serial number over PC/SC the host sends a `SELECT` to the FIDO applet AID `A0 00 00 06 47 2F 00 01` first, then issues the GET_INFO command. Re-implementations that target PC/SC must include this dance.

---

## 6. Command set

All commands are `CLA INS P1 P2`. Read the table top-to-bottom:

| Name | CLA INS P1 P2 | Direction of payload | Encryption | Manual ref |
|---|---|---|---|---|
| `ISO_SELECT` | `00 A4 04 00` | host→dev: AID | none | (transport-layer) |
| `WRITE_HOTP_SEED` | `80 C5 00 00` | host→dev: ECDH blob | yes (IV-2) | §1.7 |
| `GET_ECDH_PUBKEY` | `80 C5 01 00` | dev→host: raw 64-byte pubkey | n/a | §1.1 |
| `READ_CONFIG` | `80 C5 02 00` | host→dev: 1 byte (read length); dev→host: device info | none | §1.11 |
| `SET_DEVICE_TYPE` | `80 C5 02 01` | host→dev: 1 byte (enable mask) | none | §1.6 |
| `CFG_HOTP_ENTER` | `80 C5 02 02` | host→dev: 1 byte | none | §1.8 |
| `CFG_HOTP_TOUCH` | `80 C5 02 04` | host→dev: 1 byte | none | §1.9 |
| `ENABLE_TOTP` | `80 C5 02 05` | host→dev: 1 byte (00/01) | none | §1.2 |
| `CFG_HOTP_KBD_TYPE` | `80 C5 02 06` | host→dev: 1 byte | none | §1.10 |
| `ENUM_CODES` | `80 C5 05 00` | host→dev: subcommand + args | none | §1.4 |
| `ENUM_CODES_CONTINUE` | `80 C5 05 01` | host→dev: 8-byte timestamp | none | §1.5 |
| `WRITE_SEED` | `80 C5 05 02` | host→dev: ECDH blob, or empty for erase-all | yes (IV-1) | §1.3 |
| `READ_OTP_PIN_FLAG` | `80 C5 05 04` | host→dev: Lc (04/09/29); dev→host: PIN status | none / IV+EncRand | §1.12 |
| `SET_OTP_PIN` | `80 C5 05 05` | host→dev: IV+NewPinEnc+NewPinAuth | yes (session) | §1.13 |
| `VERIFY_OTP_PIN` | `80 C5 05 06` | host→dev: IV+PinHashEnc | yes (session) | §1.14 |
| `CHANGE_OTP_PIN` | `80 C5 05 08` | host→dev: IV+NewPinEnc+NewPinAuth+PinHashEnc | yes (session) | §1.15 |
| `READ_AGREEMENT_PUBKEY` | `80 C5 05 09` | host→dev: host P-256 pubkey; dev→host: dev pubkey+ECC521 sig | none | §1.16 |
| `GET_INFO` *(FIDO applet)* | `80 33 00 00` | host→dev: 18-byte info request | none | (reference client only) |

The subcommand byte for `ENUM_CODES`:

| Subcommand | Byte | Used by reference client? |
|---|---|---|
| `READ_ONE` | `0x01` | yes — `read_entry` |
| `GET_METADATA` | `0x02` | no — returns only the OTP code without the metadata fields |
| `READ_ALL` | `0x03` | yes — `get_all`; this is the only mode that paginates |

### 6.1 Enumerate all entries (`get_all`)

**Request data** = `0x03 || u64_be(timestamp_seconds)`. Send as `ENUM_CODES`.

The response is a **partial-marker byte** followed by a packed list of entries:

```
[partial_byte] [entry_1] [entry_2] ... [entry_n]
```

Where:

* `partial_byte & 0x80` ≠ 0 → more pages follow; issue `ENUM_CODES_CONTINUE` (data = `u64_be(timestamp)`) repeatedly until a response comes back with the high bit cleared.
* The byte to feed into the entry parser is `partial_byte & 0x7F` concatenated with the rest of the response. (In other words: the first entry's leading byte and the partial flag share the same byte, with bit 7 as the flag and bits 0–6 as the entry's `type` field.)

**Entry record layout** (parsed left-to-right):

```
type            : 1 byte   (00 = HOTP, 01 = TOTP)
algorithm       : 1 byte   (C1 = SHA1, C2 = SHA256)
timestep        : u16_be
code_length     : 1 byte   (4..10)
btn_flag        : 1 byte   (00 = not required, 01 = required)
app_name_len    : 1 byte   (0..64)
app_name        : ASCII bytes, app_name_len long
account_name_len: 1 byte   (1..64)
account_name    : ASCII bytes, account_name_len long
otp_code_len    : 1 byte    \  present ONLY when type == TOTP
otp_code        : ASCII digits, otp_code_len long  / AND btn_flag == not_required
```

**Critical rule for parsing:** the `otp_code_len`+`otp_code` tail is *omitted* on the wire for any entry that is HOTP or has the button-required flag set. Parsers must branch on those fields, or they will desynchronize across the rest of the page.

When the same entry is returned by `READ_ONE` (see §6.2), the OTP code **is** always included — the host requested it specifically and pressed the button if needed.

### 6.2 Read one entry (`read_entry`)

**Request data** = `0x01 || u64_be(timestamp) || u8(app_name_len) || app_name || u8(account_name_len) || account_name`.

Send as `ENUM_CODES`. The host should also set the transport's "detect button wait" flag — over USB-HID the device may respond with `0xC0` polling frames while waiting for a press, and the user-facing prompt is shown after a few retries.

Response is a **single** entry record with the layout in §6.1, **always including the OTP code** (i.e. parse as if `full_decode = true`).

### 6.3 Write or update an entry (`write_entry`)

This is the first encrypted command. The flow:

1. Send `GET_ECDH_PUBKEY` (empty data). Response is **64 bytes** = the device's NIST P-256 public key as `X || Y`, uncompressed but without the leading `0x04` byte.
2. Construct the cleartext payload (see below).
3. Perform ECDH+AES (see §7) using **IV-1**.
4. Send `WRITE_SEED` with the ECDH blob as data.

**Cleartext payload** (same shape as the parsed entry minus the code field):

```
type            : 1 byte
algorithm       : 1 byte
timestep        : u16_be
code_length     : 1 byte
btn_flag        : 1 byte
app_name_len    : 1 byte
app_name        : ASCII bytes
account_name_len: 1 byte
account_name    : ASCII bytes
seed_len        : 1 byte
seed            : raw bytes (the Base32-decoded shared secret)
```

**Validation, before sending:**

* `1 ≤ timestep ≤ 0xFFFF`
* `4 ≤ code_length ≤ 10`
* `len(app_name) ≤ 64` (zero is OK)
* `1 ≤ len(account_name) ≤ 64`
* `1 ≤ len(seed) ≤ 64` (this is the *decoded* length, not the Base32 string length)

If `(app_name, account_name)` matches an existing entry, the device overwrites it.

### 6.4 Delete an entry (`delete_entry`)

Uses the same encrypted-write path as `write_entry`. The cleartext is the same shape as a write payload but with all the configurable fields zeroed and the seed empty:

```
type             = 0x00
algorithm        = 0x00
timestep         = 0x0000
code_length      = 0x00
btn_flag         = 0x00
app_name_len     = u8
app_name         = ASCII
account_name_len = u8
account_name     = ASCII
seed_len         = 0x00      (no seed bytes follow)
```

ECDH-encrypt with **IV-1** and send as `WRITE_SEED`. The device interprets a write with an empty seed and a known `(app, account)` pair as a delete.

### 6.5 Erase all entries (`erase_all`)

Send `WRITE_SEED` with **empty data** (no payload, not even an ECDH blob). On USB-HID, set the "detect button wait" flag — the device requires a confirming button press.

### 6.6 Configure HOTP-on-button-press

The device can store a single extra HOTP secret that is emitted **as keystrokes** when the user touches the button outside any active session. Setting it takes four commands in sequence:

1. **Seed.** Get the ECDH pubkey, then encrypt this cleartext with **IV-2** and send as `WRITE_HOTP_SEED`:

   ```
   code_length : 1 byte   (must be 6 or 8)
   seed_len    : 1 byte
   seed        : raw bytes (1..64)
   ```

2. **Send-Enter config.** Send `CFG_HOTP_ENTER` with one byte: `0x01` to suppress the trailing Enter key, `0x00` to send it.

3. **Long-touch config.** Send `CFG_HOTP_TOUCH` with one byte: `0x01` to require a 2-second hold, `0x00` for a short tap.

4. **Numeric-keypad config.** Send `CFG_HOTP_KBD_TYPE` with one byte: `0x01` to type using the numpad scancodes, `0x00` for the regular number-row.

**Deletion** is one call: encrypt the two-byte cleartext `0x00 0x00` with **IV-2** and send as `WRITE_HOTP_SEED`.

> **Compatibility.** On devices that don't support HOTP-via-HID at all, any of these commands may return `6A 86` (`HIDNotSupported`). Treat this as an expected error.

### 6.7 Enable / disable the TOTP function (`ENABLE_TOTP`)

Some models ship with TOTP disabled by default and accept only HOTP entries until this is turned on. Send `ENABLE_TOTP` with a one-byte payload:

* `0x01` — enable TOTP support
* `0x00` — disable TOTP support

Response data is empty; check the status word. The reference Python client does not invoke this command — its callers either know TOTP is already enabled on their tokens or they call it themselves before provisioning.

### 6.8 Set composite device type (`SET_DEVICE_TYPE`)

Selectively enables or disables the USB interfaces the token exposes. The payload is a one-byte **bitmask of devices to *disable***:

| Bit (1 = lowest) | Device |
|---|---|
| 1 | FIDO device — set to disable FIDO |
| 2 | Keyboard device — set to disable HOTP-via-keystroke (the channel §6.6 uses) |
| 3 | CCID device, if present — set to disable smart-card interface |

At least one interface must remain enabled. Example: payload `0x02` disables the keyboard interface and leaves FIDO and CCID enabled. After this command the token typically re-enumerates over USB, so the host should be ready for the existing handle to go invalid.

> **⚠️ Bricking risk — read before calling.** The firmware does **not** refuse a payload that disables every interface. A mask with all three bits set leaves the device with no way to receive further APDUs, no FIDO interface to authenticate over, and no keyboard channel to type codes — i.e. effectively bricked. The Token2 companion app validates the mask client-side and refuses any value that would leave zero channels active. **A direct APDU client must perform the same check before sending this command.** A conservative pattern: call `READ_CONFIG` (§6.9) first, compute which channels are currently enabled, refuse to send a mask whose effect would zero them all out, and confirm the change with the user before sending.

### 6.9 Read configuration information (`READ_CONFIG`)

Returns a fixed-format device-info blob describing what the firmware supports and how it's currently configured.

**Request data** is a single byte: the number of response bytes the host wants back, `1..64`. Currently the firmware only fills the first **10 bytes** with meaningful content; ask for at least that many.

**Response layout** (offsets in bytes):

```
0      : Transfer type        (1 byte)
1      : Device configuration (1 byte)
2..5   : Appearance bytes     (4 bytes; e.g. 86 01 00 00 = "ZK1" first-gen fingerprint key)
6..8   : FIDO version         (3 bytes; e.g. 02 00 01 = 2.0.1)
9      : Device extension     (1 byte)
```

**Transfer-type bits** (byte 0). Bit 1 is the lowest bit:

| Bit | Meaning when set |
|---|---|
| 1 | FIDO disabled |
| 2 | HOTP-via-keystroke disabled |

**Device-configuration bits** (byte 1):

| Bit | Meaning when set |
|---|---|
| 1 | HOTP will *not* send Enter after the code |
| 2 | FIDO has a PIN registered |
| 3 | HOTP is supported |
| 4 | Fingerprint sensor present |
| 5 | NFC supported |
| 6 | HOTP is triggered by *long* press (else short tap) |
| 7 | PIN is locked |
| 8 | HOTP-on-button seed is configured |

**Device-extension bits** (byte 9):

| Bit | Meaning when set |
|---|---|
| 1 | TOTP function supported |
| 2 | FIDO 2.1 supported |
| 3 | Fingerprint registration supported |
| 4 | HOTP keystrokes use the numeric keypad layout (else main row) |
| 5 | CCID device supported |
| 6 | HOTP-on-button is **not** supported on this hardware |
| 7 | Current OTP generation *requires* fingerprint verification |
| 8 | Mandatory-fingerprint verification feature is supported |

> **Bit ordering reminder, straight from the manual.** Within each byte the bits are ordered `bit8, bit7, bit6, bit5, bit4, bit3, bit2, bit1`, with **bit 1 being the lowest bit**. In other words, "bit 1" in the manual is `value & 0x01`, "bit 2" is `value & 0x02`, and so on.

This is the right command to call at startup to feature-detect — for example, to decide whether to even offer the user a "TOTP" option (extension bit 1), whether HOTP-on-button is supported at all (extension bit 6 inverted), or whether the device already has a button-HOTP slot occupied (config bit 8).

### 6.10 Read serial number

> **Not documented in the vendor manual.** This command lives on the FIDO applet, not the OTP applet, and is implemented by the reference Python client only.

Send `GET_INFO` with the fixed 18-byte payload:

```
D1 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Response layout:

```
0x00 : 0xD1 (response type tag — must be verified)
0x01 : sn_len   (length of hex-encoded SN field that follows)
0x02..0x02+sn_len : ASCII hex characters representing the serial number bytes
```

So the host reads `sn_len` ASCII bytes and hex-decodes them. (Yes, the SN is double-encoded on the wire: ASCII-hex characters, that the host then unhexes into raw bytes.)

**PC/SC quirk:** as noted in §5, send a `SELECT` to AID `A0 00 00 06 47 2F 00 01` before this command. Some models / readers will fail this step — surface that as "model does not support serial number over NFC."

---


### 6.11 OTP PIN (privacy protection) — R3.4 / manual V1.2

The OTP PIN gates read access to stored codes. When set, enumeration returns
encrypted data and the host must run a **session handshake** and **verify** the
PIN to open a read window. All PIN commands use short-form Lc and run over an
authenticated ECDH session established per connection.

**Session handshake (`READ_AGREEMENT_PUBKEY`, `80 C5 05 09`).**
Host sends its ephemeral P-256 public key (64 bytes, X‖Y). Device returns its
own agreement public key (64 bytes) followed by an ECC-P521 signature (132
bytes, `r‖s`) over `hostPub ‖ devPub`. The host should verify this signature
against the device's known ECC521 key.

**Session key derivation** (all HMAC-SHA256):

```
shared      = ECDH-P256(hostPriv, devPub).X            # 32 bytes
pu1Key      = shared
pu1PRKey    = HMAC(key = 0x00*32,  data = pu1Key)
SessionMacKey = HMAC(key = pu1PRKey, data = "TOTP HMAC key" || 0x01)
SessionEncKey = HMAC(key = pu1PRKey, data = "TOTP AES key"  || 0x01)
```

**PIN flag (`READ_OTP_PIN_FLAG`, `80 C5 05 04`).** The device returns as many
bytes as the request's Lc:

| Lc | Returns |
|---|---|
| `04` | `PinAlgId, PinRetry, OtpPinLen, PinMaxRetry` |
| `09` | above + `PubVer(2)`, `PubCrc(2)` |
| `29` | above + `IV(16)`, `EncRand(16)` (the verify challenge) |

`OtpPinLen == 0` means **no PIN set**. On a device that has never had a PIN,
`PinAlgId` and `PinRetry` are also `00`.

**Set PIN (`SET_OTP_PIN`, `80 C5 05 05`)** — only from the unprotected state
(`OtpPinLen == 0`); returns `6A81` if a PIN already exists.

```
NewPin      = 0x07 || PinRetry(0x64) || OtpPinLen || OtpPin      # AlgId=07 = AES256
NewPin      = PKCS#5/7 pad to 16
IV          = random(16)
NewPinEnc   = AES-256-CBC(SessionEncKey, IV, NewPin)
NewPinAuth  = HMAC(SessionMacKey, NewPinEnc)[0:16]
data field  = IV || NewPinEnc || NewPinAuth
```

**Verify PIN (`VERIFY_OTP_PIN`, `80 C5 05 06`).** Read the `Lc=29` flag to get
`IV` + `EncRand`; decrypt `Rand = AES-256-CBC-dec(SessionEncKey, IV, EncRand)`;
send `IV' || PinHashEnc` where `PinHashEnc` binds the PIN to `Rand`. `9000`
opens the read window (default 5 minutes); afterwards `ENUM_CODES` returns
plaintext until the window closes or `lock` is sent.

**Change / remove PIN (`CHANGE_OTP_PIN`, `80 C5 05 08`).** Same as Set but the
data field also carries the current-PIN proof (`PinHashEnc`). Removing a PIN is
a change to `OtpPinLen == 0`. Unlike Set, Change works from the protected state.

**Once a PIN is set**, `ENUM_CODES` (`READ_ALL`) returns `IV || EncData ||
EncDataAuth`; the host decrypts `EncData` under `SessionEncKey` after a
successful verify.

**Reset.** There is no PIN-only firmware reset. `WRITE_SEED` with an empty body
(`erase_all`) wipes all OTP data and returns PIN state to `OtpPinLen == 0`,
`PinAlgId == 0`. Use this to recover a locked PIN (§9).


## 7. ECDH + AES payload encryption

A handful of commands (`WRITE_SEED`, `WRITE_HOTP_SEED`) carry secrets and are wrapped in an ECDH-derived AES-CBC blob.

### 7.1 Algorithm

* Curve: **NIST P-256** (a.k.a. `secp256r1` / `prime256v1`).
* The device's pubkey returned by `GET_ECDH_PUBKEY` is the raw concatenation `X || Y` (64 bytes). Prepend a `0x04` byte to get the standard "uncompressed point" form before feeding it to most crypto libraries.
* Generate a fresh ephemeral P-256 keypair per command.
* `shared = ECDH(host_priv, device_pub)` — take the 32-byte X-coordinate of the shared point.
* `session_key = SHA256(shared)` — 32 bytes.
* Pad the cleartext with **PKCS#7** to a 16-byte boundary.
* Encrypt with **AES-256-CBC**, key = `session_key`, IV = one of the two constants below.
* The on-wire blob is `host_pub_xy || ciphertext`, where `host_pub_xy` is the host's ephemeral pubkey in the same 64-byte `X || Y` form (no leading `0x04`).

### 7.2 The two IVs

```
IV-1 (write OTP entries / delete OTP entry)
  9D D8 91 8E 34 F3 CC AB 08 CB 75 18 F7 19 38 F1

IV-2 (HOTP-on-button seed write / delete)
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Both are **constants**, not nonces — the freshness comes from the per-command ephemeral keypair. A re-implementation that uses random IVs will fail to decrypt on the device side.

### 7.3 Pseudocode

```
device_pub = send(GET_ECDH_PUBKEY, empty)       # 64 bytes, X || Y
(host_priv, host_pub) = p256_keygen()           # host_pub.uncompressed[1:] is 64 bytes
shared = ecdh(host_priv, 0x04 || device_pub)    # 32 bytes (X coord)
key    = sha256(shared)                         # 32 bytes
ct     = aes_256_cbc_encrypt(key, IV_x, pkcs7_pad(cleartext, 16))
blob   = host_pub.uncompressed[1:] || ct
send(target_command, blob)
```

---

## 8. Suggested SDK surface

A re-implementation can mirror the reference's three-layer structure. Names are illustrative.

### 8.1 Transport layer

```
interface Transport {
    open();                                       // discover + connect
    close();
    sendCommand(apdu, detectButtonWait=false) -> bytes;   // returns response data with SW stripped
    setButtonPressCallback(fn);                   // for UX prompts during HID polling
}

class UsbHidTransport implements Transport
class PcScTransport  implements Transport

function detectToken(...) -> Transport  // try USB first, fall back to PC/SC, else throw
```

The `sendCommand` contract is: serialize the APDU, do whatever framing the transport requires, read until the device returns a terminal frame, strip the trailing SW, raise the corresponding exception for non-`9000` status words, and return the data on success.

### 8.2 Codec layer

Pure functions, no I/O:

* `serializeApdu(cmd, data, extendedLength=true) -> bytes`
* `serializeWriteEntry(entry) -> bytes` and `serializeDeleteEntry(app, acct) -> bytes`
* `serializeReadEntry(ts, app, acct) -> bytes`
* `parseEnumEntries(bytes, fullDecode=false) -> [Entry]` — iterator-friendly; the spec's variable-length tail makes a stateful parser the natural fit.
* `encryptPayloadEcdh(devicePubKey, cleartext, iv) -> bytes`

### 8.3 Client layer

```
class Token2Client {
    Token2Client(transport)

    // OTP entries
    enumerate(timestamp)           -> Iterator<Entry>
    readEntry(ts, app, acct)       -> Entry
    writeEntry(entry)
    deleteEntry(app, acct)
    eraseAll()

    // Button-HOTP (keystroke channel)
    setButtonHotp(spec)
    deleteButtonHotp()

    // Device-wide configuration (vendor manual §1.2, §1.6, §1.11)
    enableTotp(enabled: bool)                  // §1.2
    setDeviceType(disableMask: byte)           // §1.6 — bitmask of devices to DISABLE
    readConfig(numBytes: int = 10) -> DeviceInfo  // §1.11

    // FIDO-applet command, not in the vendor OTP manual
    readSerial()                   -> bytes
}

struct DeviceInfo {
    transferType:        byte    // §6.9 byte 0
    deviceConfig:        byte    // §6.9 byte 1
    appearance:          bytes   // 4 bytes
    fidoVersion:         bytes   // 3 bytes (e.g. 02 00 01)
    deviceExtension:     byte    // §6.9 byte 9
    raw:                 bytes   // anything beyond byte 9, for forward-compat
}
```

`enumerate` is naturally a generator/iterator because of the paging via `ENUM_CODES_CONTINUE`. `readConfig` should be the first call at startup if the client cares about feature detection: it tells you whether TOTP is supported at all, whether the HOTP-on-button slot is configured, whether NFC/CCID/fingerprint are present, and the current keystroke-layout choice. The convention is to expose each bit as a named boolean property on `DeviceInfo` rather than asking callers to mask bytes themselves.

### 8.4 Error types

Mirror the reference: a base "expected, surface to the user" exception and:

* `EntryNotFound` (`6A 80` / `6A 83`)
* `NotEnoughSpace` (`6A 84`)
* `ButtonPressRequired` (`6F F9`)
* `HIDNotSupported` (`6A 86`)
* `BadStatusCode(sw)` (catch-all)
* `TokenNotDetected` (no transport opened)
* `TransportUnavailable` (one specific transport failed; caller may try the next)

---

## 9. Validation rules to enforce client-side

**OTP PIN policy** (the firmware rejects violations with `6A80`; enforce
client-side for a clear error):

*Numeric PINs* — minimum 6 digits (configurable upward, 6 is the floor):
- no ascending or descending sequences (`123456`, `654321`)
- no all-identical digits (`111111`)
- no palindrome / mirror numbers (`321123`, `69233296`)
- no single digit repeating more than 3 times (`111123`, `990000`)

*Alphanumeric PINs* — minimum 10 characters; must include at least two of:
uppercase `A-Z`, lowercase `a-z`, digits `0-9`, special characters.


Doing these before hitting the wire saves a round-trip and gives better error messages:

| Field | Rule |
|---|---|
| `timestep` | integer, `1..0xFFFF`; only meaningful for TOTP |
| `code_length` (entry) | integer, `4..10` |
| `code_length` (button HOTP) | integer, **either 6 or 8** — no other values |
| `app_name` | ASCII, `0..64` bytes |
| `account_name` | ASCII, `1..64` bytes |
| `seed` (raw, after Base32 decode) | `1..64` bytes |
| `timestamp` | non-negative integer seconds since UNIX epoch |

Seeds are accepted from the user as Base32 strings (RFC 4648). Re-pad to a multiple of 8 with `=` before decoding to be forgiving of stripped padding.

---

## 10. End-to-end traces (worked examples)

Below are three runs reduced to the minimum useful bytes. CLA/INS/P1/P2 are shown spaced; data is contiguous.

### 10.1 List all entries (TOTP only, 1 entry, "Test"/"alice", SHA1, 30s, 6 digits, code 123456) at t=0

Host → device APDU:

```
80 C5 05 00     00 00 09        03  00 00 00 00 00 00 00 00
^^ ENUM_CODES   ^^ extended Lc  ^^  ^^ timestamp_be64 = 0
                   = 9          READ_ALL
```

Device → host payload:

```
00 C1 00 1E 06 00 04 54 65 73 74 05 61 6C 69 63 65 06 31 32 33 34 35 36
^^ partial flag clear, type byte = 01 → TOTP
   ^^ SHA1
      ^^ timestep_be16 = 30
            ^^ code_length = 6
               ^^ btn not required
                  ^^ app_name_len = 4
                     ^^ "Test"
                                 ^^ account_name_len = 5
                                    ^^ "alice"
                                                ^^ code_len = 6
                                                   ^^ "123456"
```

Status word `90 00` follows on the wire; transport layer strips it.

### 10.2 Write a new TOTP entry — host work before the encrypted send

Cleartext for `("Test", "alice", seed=0x48 65 6c 6c 6f, SHA1, TOTP, 30, 6, no button)`:

```
01 C1 00 1E 06 00 04 54 65 73 74 05 61 6C 69 63 65 05 48 65 6C 6C 6F
```

The host then:

1. Issues `GET_ECDH_PUBKEY` (`80 C5 01 00 00 00 00`) → 64-byte device public key.
2. Builds the ECDH blob per §7 with **IV-1**.
3. Sends `WRITE_SEED` (`80 C5 05 02 00 LL LL …`) where the data is `host_pubkey_xy || aes_ct`.

`aes_ct` is one or two 16-byte blocks (cleartext is 23 bytes → pad to 32 → two AES blocks).

### 10.3 Read serial number over USB

```
80 33 00 00     00 00 12        D1 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
^^ GET_INFO     ^^ Lc = 18      ^^ tag       ^^ 16 zero bytes
```

Response data (before SW):

```
D1 0A 31 32 33 34 35 36 37 38 39 30
^^ response tag, must equal 0xD1
   ^^ sn_len = 10 ASCII hex chars
      ^^ "1234567890" — host then hex-decodes to bytes  12 34 56 78 90
```

---

## 11. Implementation gotchas

* **Don't confuse the two USB byte counts.** The HID feature report is 65 bytes (1 report ID + 64 payload). The inner chunk-length byte at offset 3 is the *useful* APDU bytes only and never exceeds 61. Bugs creep in here easily.
* **Honor the `0xC0` polling flag** — do not increment your message counter on these. Treat them strictly as "try again in a moment". The reference uses a `num_retries` counter to throttle and to drive the "press the button" prompt at retry 3.
* **The partial-bit lives inside the type field.** When parsing an `ENUM_CODES` response, mask the very first byte: `is_partial = byte & 0x80; first_entry_type = byte & 0x7F`. Don't consume the byte twice.
* **Variable-tail enumeration.** Entries do **not** carry their own length prefix — the parser knows when one ends only by walking the fields. Get the conditional OTP-code tail wrong and you'll mis-frame everything that follows in the page.
* **AES IVs are constants by design.** Resist the urge to randomize them. Freshness comes from the ephemeral host keypair.
* **Pubkey representation.** Different ECC libraries default to different encodings. The wire form is the raw 64-byte `X || Y`; the most common library expectation is `04 || X || Y`. Convert at the boundary.
* **PC/SC SELECT uses *short* Lc.** The only command that uses short-form Lc in this protocol; everything else uses extended-form.
* **`erase_all` is a write with empty data**, not its own command code. Easy to miss.
* **Treat `EntryNotFound` from `enum_codes` as "empty token"**, not as an error to bubble up.
* **`HIDNotSupported` (`6A 86`) is model-specific.** Older PIN+ revisions don't expose HOTP-via-HID at all. Detect and feature-gate.

---

## 12. References

* **Vendor manual:** *OTP on FIDO Command Manual*, §§1.1–1.11. Authoritative for the OTP-applet command set and the encryption parameters.
* **Reference implementation:** `Token2 OTP CLI Tool v0.2`, modules `token2/`, `transports/`, `cli_args/` (Python; ~25 KB of source). Authoritative for transport framing (USB-HID chunking, PC/SC AID, error mapping), client-side validation, and the FIDO-applet serial-number command.
* Curve and AES primitives: NIST FIPS 186-4 (P-256), NIST FIPS 197 (AES), RFC 5652 §6.3 (PKCS#7 padding; the vendor manual refers to it as "PKCS5" — for a 16-byte AES block the two are identical), RFC 7748 (ECDH).
* APDU framing: ISO/IEC 7816-4.
* USB-HID feature reports: USB HID 1.11 §7.2.

---

*The vendor manual is authoritative for the OTP-applet commands described in §§6.1–6.9. §6.10 (read serial number) is from the reference implementation only.  