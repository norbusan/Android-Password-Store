# Password Store

[![GitHub workflow](https://github.com/valasiadis/Android-Password-Store/workflows/Deploy%20snapshot%20builds/badge.svg)](https://github.com/valasiadis/Android-Password-Store/actions)


> [!WARNING]  
> This repository is a fork of
> [agrahn/Android-Password-Store](https://github.com/valasiadis/Android-Password-Store) that
> implements hardware security support, commit signing and some UX improvements. The features were
> implemented with heavy assistance from generative AI (Claude Opus 4.8 and some OpenAI GPT-5.5). As
> soon as I can spare some time, I will more thoroughly review the code with the goal of eventually
> merging it upstream. I changed the app ID to `app.passwordstore.valasiadis` for compatibility
> reasons and the app icon color so that the app isn't confused with agrahn's. I will also
> keep this repo up-to-date with agrahn's version until the code is merged. If you use this version
> of the app in the meantime, reproducible bug reports and other suggestions would be incredibly
> helpful.

## Download

- Latest [snapshot build (APK)](https://github.com/valasiadis/Android-Password-Store/releases/tag/latest) of this fork
- [GitHub Releases](https://github.com/valasiadis/Android-Password-Store/releases)

You can install this app via [Obtainium](https://obtainium.imranr.dev/) too. You just need to check `Include prereleases`
under the `Additional options for GitHub` section.

## Documentation

The original documentation can be found [here](https://docs.passwordstore.app) and [there](https://github.com/android-password-store/Android-Password-Store/wiki/).

## How-To: Transfer a PGP key to Password Store securely

### From an OpenPGP smartcard

1. Go to `Settings > PGP settings > Key manager > +` and select `Set up NFC smartcard`
2. Present your smartcard behind the phone on the NFC sensor and hold it there

### From GPG keyring
````bash
gpg --armor --gen-random 1 24 # generate a strong random password; use it in the next step
gpg --armor --export-secret-keys <ID of key used for pass> | gpg --armor --symmetric --output myKeyForPass.sec.asc
````
File `myKeyForPass.sec.asc` can be directly imported into Password Store via Settings → PGP Settings → Key Manager → <kbd>+</kbd>; enter the password from the first step when asked for the backup code.

### From OpenKeychain
1. In the main app window, select the key that you use for `pass`/Password Store from the "My Keys" list.
2. In the window that appears, tap the three-dot menu in the top right corner and select "Backup key".
3. Write down the backup code, then save the backup file to your phone.
4. Import this backup file into Password Store by navigating to Settings → PGP Settings → Key Manager → <kbd>+</kbd>, and enter the backup code when prompted.

## Contributing

This fork of the original repository just tries to keep pace with automatic dependency updates made by [Renovate](https://github.com/apps/renovate). New features will most likely not be implemented, only fixes. See [ChangeLog](https://github.com/agrahn/Android-Password-Store/blob/develop/CHANGELOG.md).

## Donations

If you wish to sponsor the original author, financial contributions can be made through the following platforms

- [GitHub Sponsors](https://github.com/sponsors/android-password-store)
- [OpenCollective](https://opencollective.com/android-password-store)
