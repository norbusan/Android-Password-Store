# Android Password Store Notes

This repository is an Android frontend for ZX3CR4's `password-store` workflow. It stores password entries as OpenPGP-encrypted `.gpg` files in a Git repository, using `.gpg-id` files to determine the OpenPGP recipients for each directory. The app contains its own PGP key manager and crypto backend instead of delegating key operations to OpenKeychain.

## Project Structure

- `app/`: Android application module. Contains activities, settings, Git integration, password browsing, decryption, password creation/editing, autofill, and the PGP key manager UI.
- `crypto/common/`: Generic crypto interfaces such as `CryptoHandler`, `CryptoOptions`, and `KeyManager`.
- `crypto/pgpainless/`: OpenPGP backend implemented with PGPainless and Bouncy Castle. This module owns PGP key parsing, key storage, encryption, decryption, key generation, and key capability checks.
- `format/common/`: Password-entry parsing and formatting, including OTP/TOTP helpers.
- `passgen/`: Password generators.
- `ui/compose/`: Shared Compose UI/theme pieces.
- `build-logic/`: Gradle convention plugins used by the multi-module build.

The main runtime crypto path is:

1. UI activity (`DecryptActivity`, `PasswordCreationActivity`, autofill decrypt activity) asks `CryptoRepository` to encrypt/decrypt.
2. `CryptoRepository` resolves key ids through `PGPKeyManager`.
3. `PGPainlessCryptoHandler` performs normal PGPainless/Bouncy Castle encryption and decryption for local software keys.
4. Smartcard-backed decryption now branches through the NFC/OpenPGP-card helper described below.

## OpenPGP Smartcard/NFC Work

The goal was to support YubiKey/OpenPGP smartcards over NFC for:

- discovering/importing a smartcard-backed public key,
- associating an imported public key with a physical OpenPGP card,
- treating that association as decryption-capable instead of "public only",
- decrypting password entries through the OpenPGP card over NFC.

Android's `android.permission.NFC` was added to `app/src/main/AndroidManifest.xml` together with an optional `android.hardware.nfc` feature. NFC is a normal install-time Android permission, not a runtime permission, so it does not appear as a user-toggleable permission in Android app settings.

### New NFC/Card Helpers

New files under `app/src/main/java/app/passwordstore/util/crypto/`:

- `OpenPgpNfcCard.kt`
  - Owns Android `NfcAdapter` reader mode and `IsoDep` communication.
  - Selects the OpenPGP applet using AID `D27600012401`.
  - Reads card data:
    - application related data `GET DATA 00 6E`,
    - fingerprints from TLV tag `C5`,
    - card URL from `GET DATA 5F 50`.
  - Verifies user PIN with `VERIFY PW1 other` (`00 20 00 82`).
  - Performs `PSO:DECIPHER` (`00 2A 80 86`) for RSA session-key decryption.
  - Keeps reader mode active for full operations to suppress Android/Google Services handling of the irrelevant YubiKey NDEF URL (`https://my.yubico.com/yk/#...`).
  - Uses reader flags:
    - `FLAG_READER_NFC_A`,
    - `FLAG_READER_NFC_B`,
    - `FLAG_READER_SKIP_NDEF_CHECK`,
    - `FLAG_READER_NO_PLATFORM_SOUNDS`.

- `OpenPgpSmartcardDecryptor.kt`
  - Implements a Bouncy Castle `PublicKeyDataDecryptorFactory` path for smartcard-backed RSA keys.
  - Parses the OpenPGP encrypted message, finds a `PGPPublicKeyEncryptedData` packet matching the available key, asks the card to recover the session key, then lets Bouncy Castle decrypt the payload.
  - Current implemented card private-key operation is RSA `PSO:DECIPHER`.
  - ECC/X25519 smartcard decryption is not implemented in this pass.

- `OpenPgpSmartcardStore.kt`
  - Stores a verified association between a primary PGP key id and smartcard fingerprints/URL in app settings.
  - This is the local metadata that makes `public key + verified card fingerprints` behave as a card-backed key.

### Key Import/Association Flow

OpenKeychain's current implementation was used as the reference model. Its smartcard setup reads card fingerprints and URL, retrieves a public key from the URL and/or keyserver, verifies fingerprint match, then promotes/associates the public key as token-backed.

This app now follows the same shape at a simpler level:

1. User selects `Set up NFC smartcard` from the PGP key manager add-key sheet.
2. `PGPKeyImportActivity` waits for an NFC OpenPGP card.
3. The app reads card fingerprints and URL.
4. It first checks existing imported keys for matching fingerprints.
5. If no local key matches and the card has a URL, the app downloads the public key from that URL.
6. If URL fetch fails or no URL exists, the app opens the existing file import flow and verifies the selected key against the card fingerprints.
7. Only matching keys are imported/associated.
8. A verified association is stored through `OpenPgpSmartcardStore`.

Relevant changed files:

- `app/src/main/java/app/passwordstore/ui/dialogs/AddPgpKeyBottomSheet.kt`
- `app/src/main/res/layout/add_pgp_key_sheet.xml`
- `app/src/main/java/app/passwordstore/ui/pgp/PGPKeyListActivity.kt`
- `app/src/main/java/app/passwordstore/ui/pgp/PGPKeyImportActivity.kt`
- `app/src/main/res/values/strings.xml`

### Decryption Flow

Before this work, a downloaded/imported public key was treated as public-only, so decryption showed:

`No decryption keys found ... public only`

This was wrong for a verified smartcard-backed public key. The fix is in `CryptoRepository`:

- `hasDecKey(id)` now returns true if the key has local secret decryption material or if it has a verified smartcard association.
- `isSmartcardBacked(id)` checks the association metadata.
- `decryptWithSmartcard(...)` routes card-backed decrypt operations through `OpenPgpSmartcardDecryptor`.

`BasePGPActivity` and `DecryptActivity` were changed so card-backed decryption:

- asks for an `OpenPGP card PIN`, not a generic PGP passphrase,
- does not cache the card PIN in the PGP passphrase cache,
- shows a modal `Decrypt with OpenPGP card` prompt before waiting for NFC,
- keeps NFC reader mode active across the prompt and error dialog to avoid Android dispatching the YubiKey URL to Google Services.

Relevant changed files:

- `app/src/main/java/app/passwordstore/data/crypto/CryptoRepository.kt`
- `app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt`
- `app/src/main/java/app/passwordstore/ui/crypto/DecryptActivity.kt`
- `app/src/main/java/app/passwordstore/ui/dialogs/PasswordDialog.kt`

### PGP Key Capability Changes

`crypto/pgpainless/src/main/kotlin/app/passwordstore/crypto/KeyUtils.kt` was changed to support smartcard-related detection:

- Secret-key detection now treats OpenPGP secret-key stubs as secret keys, even when private key material is stripped.
- Decryption-key detection treats encryption-capable secret subkeys, including stripped stubs, as decryption-capable.
- Added helpers to list fingerprints and test whether a key contains any card-reported fingerprint.

This lets the app distinguish:

- normal public-only key,
- local software secret key,
- GnuPG/OpenPGP stub key,
- public key associated with a verified smartcard.

## APDU/Transport Notes

OpenKeychain references inspected:

- `OpenPgpCommandApduFactory`
- `SecurityTokenConnection`
- `NfcTransport`
- `PsoDecryptTokenOp`
- `PublicKeyRetriever`

Important behavior copied or approximated:

- OpenKeychain uses 254-byte command-chaining chunks instead of 255 for compatibility with non-compliant tokens.
- Long PSO:DECIPHER inputs are sent as chained short APDUs instead of one large extended APDU.
- Final chained APDU includes an expected response length (`Le`) based on the RSA MPI length, capped according to short APDU behavior.
- Reader mode stays active during app-owned NFC operations.

Current issue still under investigation:

- On some YubiKey/phone combinations, raw Android `IsoDep.transceive(...)` still throws `Transceive failed` during PSO:DECIPHER. OpenKeychain uses the Nordpol `AndroidCard` wrapper rather than raw `IsoDep`, which may handle additional ISO-DEP quirks. If this persists, the next likely step is to replace or wrap raw `IsoDep` with Nordpol-like transport behavior or port more of OpenKeychain's transport layer.

## Current Limitations

- RSA OpenPGP card decryption is the only implemented card private-key operation.
- ECC/X25519 smartcard decryption is not implemented.
- Encryption itself does not need NFC for normal password-store operation; OpenPGP encryption uses public certificates.
- The key import flow supports URL fetch from the card and manual file import with fingerprint verification. It does not yet implement HKP keyserver fallback by fingerprint.
- Smartcard PIN retry counters are not surfaced in the UI.
- NFC handling depends on user flow: open the APS smartcard/decrypt prompt first, then present the YubiKey. If the key is presented before APS enables reader mode, Android may still dispatch the YubiKey NDEF URL.

## Verification Performed

Targeted build verification was run repeatedly after the changes:

```bash
./gradlew :app:compileDebugKotlin
```

The command passed after the latest changes.

## Working Tree Note

The file `gradle/gradle-daemon-jvm.properties` was already untracked during this work and was intentionally left untouched.
