# Releasing Security Groupie

Releases are cut by pushing a `vX.Y.Z` tag. `.github/workflows/release.yml`
runs the unit tests, then builds, signs, notarizes, staples, packages, and
publishes a DMG, a zip, and a signed Sparkle `appcast.xml` to the GitHub
Release for that tag. Before the first release, complete the one-time setup
below.

> The repository is assumed to be `inxilpro/security-groupie`. The workflow
> does not hard-code it (it publishes to whatever repository it runs in), but
> `SUFeedURL` in `Security Groupie/Info.plist` does, and it is the one place
> the app learns where updates live. If the repository lives elsewhere, change
> it. The release workflow refuses to publish when `SUFeedURL` doesn't point at
> the repository it runs in.

Security Groupie is distributed outside the Mac App Store with Developer ID
signing and notarization. It is sandboxed with the hardened runtime on.

## Runner image and Xcode

The workflow runs on GitHub's `xcode-27` image with
`/Applications/Xcode_27.0.app`, the toolchain the project is developed with.
`xcode-27` is a **preview** image: expect GitHub to rename or retire it. When a
GA `macos-27` image ships, change `runs-on` and `XCODE_APP` together.
Current images: <https://github.com/actions/runner-images#available-images>.

## One-time setup

### 1. Developer ID Application certificate

1. In Xcode → Settings → Accounts → your team (657AK7D2D9) → Manage
   Certificates, create a **Developer ID Application** certificate if one does
   not exist (or create it at developer.apple.com → Certificates). The one
   Chronicle and Short Circuit use works here too; it belongs to the team, not
   the app.
2. In Keychain Access, find the certificate (with its private key), select
   both, and export as a `.p12`, choosing an export password.
3. Base64-encode it for the secret:

   ```sh
   base64 -i DeveloperID.p12 | pbcopy
   ```

   The clipboard contents become `MACOS_CERTIFICATE_P12`; the export password
   becomes `MACOS_CERTIFICATE_PASSWORD`.

### 2. App Store Connect API key (for notarization)

1. In App Store Connect → Users and Access → Integrations → App Store Connect
   API → Team Keys, generate a key with the **Developer** role (or reuse
   Chronicle's key; it isn't tied to an app).
2. Download the `.p8` file (only possible once).
3. Record:
   - the **Key ID** → `ASC_KEY_ID`
   - the **Issuer ID** (top of the keys page) → `ASC_ISSUER_ID`
   - the file contents (`cat AuthKey_XXXX.p8`) → `ASC_PRIVATE_KEY`

No App Store Connect app record is needed for Developer ID notarization.

### 3. Sparkle EdDSA key

Sparkle signs each update archive with an EdDSA key, and the app verifies it
with the public key in `Security Groupie/Info.plist` (`SUPublicEDKey`).

**Current choice: Security Groupie reuses Chronicle's key**, as Short Circuit
does. `SUPublicEDKey` is Chronicle's public key, so the `SPARKLE_PRIVATE_KEY`
secret already set on Chronicle's repository works here unchanged: set the same
value on this repository. Nothing needs generating.

The trade-off is that one leaked private key could sign updates for all three
apps. If you'd rather give Security Groupie its own key, do it **before the
first release**; once copies are installed, they expect updates signed with the
key they shipped with.

1. Download the Sparkle distribution matching the resolved version (currently
   2.10.0; see `SPARKLE_VERSION` in `release.yml`):

   ```sh
   curl -fsSLO https://github.com/sparkle-project/Sparkle/releases/download/2.10.0/Sparkle-2.10.0.tar.xz
   mkdir Sparkle-2.10.0 && tar -xJf Sparkle-2.10.0.tar.xz -C Sparkle-2.10.0
   cd Sparkle-2.10.0
   ```

2. Generate a keypair under its own keychain account, so it doesn't collide
   with Chronicle's (which lives under the default account, `ed25519`):

   ```sh
   ./bin/generate_keys --account security-groupie
   ```

   It prints the **public** key (base64). Replace the `SUPublicEDKey` value in
   `Security Groupie/Info.plist` with it and commit.

3. Export the **private** key for CI:

   ```sh
   ./bin/generate_keys --account security-groupie -x security-groupie-sparkle-key.txt
   ```

   Set the file's contents as this repository's `SPARKLE_PRIVATE_KEY` secret
   (`gh secret set SPARKLE_PRIVATE_KEY < security-groupie-sparkle-key.txt`),
   keep a secure backup (a password manager), and delete the file. Losing the
   private key strands every installed copy on its current version.

To change keys after releases have shipped, publish one transition release
that contains the new `SUPublicEDKey` but is still signed with the old private
key; installed copies accept it, and every release after it is signed with the
new key.

### 4. GitHub secrets

The names match Chronicle's and Short Circuit's, so the same values can be set
on this repository. Set each secret (Settings → Secrets and variables →
Actions, or with `gh`):

```sh
gh secret set MACOS_CERTIFICATE_P12       # base64 of the Developer ID .p12
gh secret set MACOS_CERTIFICATE_PASSWORD  # the .p12 export password
gh secret set KEYCHAIN_PASSWORD           # any random string, e.g. `uuidgen`
gh secret set APPLE_TEAM_ID               # 657AK7D2D9
gh secret set ASC_KEY_ID                  # App Store Connect API key ID
gh secret set ASC_ISSUER_ID               # App Store Connect API issuer ID
gh secret set ASC_PRIVATE_KEY             # contents of the .p8 file
gh secret set SPARKLE_PRIVATE_KEY         # Sparkle EdDSA private key (same as Chronicle's; see step 3)
```

`KEYCHAIN_PASSWORD` protects only the throwaway keychain created for a single
CI run; any random value is fine. `GITHUB_TOKEN` is provided automatically;
the workflow's `permissions: contents: write` lets it create the release.
No repository variables are needed.

## How updates are served

`Security Groupie/Info.plist` sets:

```
SUFeedURL = https://github.com/inxilpro/security-groupie/releases/latest/download/appcast.xml
```

GitHub's `releases/latest/download/<asset>` URL always redirects to that asset
on the **latest** release, so each release's `appcast.xml` only describes the
newest version. The release workflow generates it from just the zip it built,
with the enclosure URL pointing at that tag's zip, and signs it with
`SPARKLE_PRIVATE_KEY`. There is no cumulative feed to maintain. Consequences:

- Marking an older release as "latest" in the GitHub UI would serve its older
  appcast; don't.
- Pre-releases are never "latest", so a pre-release tag is not offered to
  users.

The updater runs only in Release builds. Debug builds (and so unit tests)
create it without starting it, which leaves **Check for Updates…** disabled in
the menu bar menu and in Settings. `SUEnableAutomaticChecks` is `true`, as in
Chronicle, and Settings → Updates has the toggle to turn it off.

### Sandboxing

Because the app is sandboxed, Sparkle installs updates through its
`Installer.xpc` service rather than launching the installer directly. That
needs two things, both already in place:

- `SUEnableInstallerLauncherService = true` in `Security Groupie/Info.plist`;
- `com.apple.security.temporary-exception.mach-lookup.global-name` with
  `$(PRODUCT_BUNDLE_IDENTIFIER)-spks` and `$(PRODUCT_BUNDLE_IDENTIFIER)-spki`
  in `Security_Groupie.entitlements`.

The app has `com.apple.security.network.client`, so it downloads updates itself
and doesn't need Sparkle's `Downloader.xpc` (`SUEnableDownloaderService` stays
unset).

`Sparkle.framework` arrives with ad-hoc signatures on its nested helpers; the
workflow's "Re-sign Sparkle nested components" step re-signs them with the
Developer ID and a timestamp before notarization, and the verify step checks
each one and that the signed app still carries both mach-lookup exceptions.

### Updating Sparkle

`SPARKLE_VERSION` in `release.yml` downloads the matching `generate_appcast`,
and must equal the version pinned in
`Security Groupie.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`;
the workflow's first check fails the release if they differ. After updating the
package in Xcode (File → Packages → Update to Latest Package Versions), bump
`SPARKLE_VERSION` in the same commit.

## Cutting a release

1. Make sure the unit tests pass on `main`.
2. Choose the next version. The tag is the single source of truth: the
   workflow strips the `v` and overrides both `MARKETING_VERSION` and
   `CURRENT_PROJECT_VERSION` with it, so the `1.0` in the project file is only
   what local builds report. Use strictly increasing `X.Y.Z` versions;
   Sparkle compares `CFBundleVersion` to decide what's newer.
3. Tag and push:

   ```sh
   git tag v1.0.0
   git push origin v1.0.0
   ```

4. Watch the Release workflow. On success the GitHub Release for the tag
   contains `Security-Groupie-X.Y.Z.dmg`, `Security-Groupie-X.Y.Z.zip`, and
   `appcast.xml` (asset names use a hyphen because GitHub rewrites spaces),
   and the log prints the SHA-256 sums for a future Homebrew cask.

A tag that isn't `vX.Y.Z` fails in the first step. A failed run leaves no
release behind; fix the problem, delete the tag locally and remotely
(`git push origin :refs/tags/v1.0.0`), and push it again.

## Verifying a release

Do this after the first release and any time signing changes:

1. Download the DMG from the release, drag the app to `/Applications`, and
   launch it. Gatekeeper should show no warnings (notarized and stapled).
2. Spot-check locally:

   ```sh
   codesign --verify --deep --strict --verbose=2 "/Applications/Security Groupie.app"
   codesign --display --verbose=2 "/Applications/Security Groupie.app"   # Developer ID, Timestamp, flags=…(runtime)
   codesign --display --entitlements - "/Applications/Security Groupie.app"  # sandbox, network.client, -spks/-spki
   spctl -a -t exec -vv "/Applications/Security Groupie.app"               # source=Notarized Developer ID
   xcrun stapler validate "/Applications/Security Groupie.app"
   ```

3. Confirm Settings → Updates reports the tagged version.
4. Sign in to AWS and let the app update a security group rule. Keychain
   access and outbound network calls are where a sandboxed, notarized build
   could differ from a Debug build.

### The update path, end to end

Do this once with the first two releases, and again whenever the key, the
Sparkle version, or the entitlements change:

1. Install the older release from its DMG and launch it.
2. Cut a release with a higher version (a throwaway `v1.0.1` is fine).
3. In the installed app, choose **Check for Updates…** from the menu bar menu.
   Sparkle should offer the new version, download the zip, verify its EdDSA
   signature against `SUPublicEDKey`, install, and relaunch.
4. Confirm Settings → Updates reports the new version.

A signature error means the `SUPublicEDKey` in the installed app doesn't match
the `SPARKLE_PRIVATE_KEY` that signed the appcast; see "Sparkle EdDSA key"
above. An install that fails after the download completes usually means the
sandbox blocked the installer; see "Sandboxing" above.
