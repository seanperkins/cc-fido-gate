# cc-presence-gate SP2 (A+B) — Touch ID / Secure Enclave backend + install port

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Touch ID / Secure Enclave presence gate (`cc-touch-id`) as a product fully parallel to `cc-fido`, reusing the SP1 `CCGateCore` engine with only one additive seam.

**Architecture:** Add a client-side `GateCeremony` seam to core (moving FIDO's `osascript` ceremony into `CCFidoBackend`), then a new `CCTouchIDBackend` target implementing the four SP1 seams + the new one with Secure Enclave crypto (client-side biometric `SecKeyCreateSignature`; off-session `SecKeyVerifySignature`; `LAContext.invalidate()` cancel). A second thin `cc-touch-id` executable composes the Touch ID `GateContext`; a `plugins/cc-touch-id/` plugin + install skill deliver it via the marketplace.

**Tech Stack:** Swift 5.9, SwiftPM, macOS 13+, XCTest, Security.framework, LocalAuthentication, CryptoKit. No third-party dependencies.

**Source spec:** `docs/superpowers/specs/2026-07-18-cc-presence-gate-sp2-touch-id-design.md`.
**Feasibility spike:** `docs/superpowers/spikes/2026-07-18-secure-enclave-touch-id-feasibility.md` (8/8 green, ad-hoc signing sufficient, no Developer ID).

## Global Constraints

- **Swift tools 5.9, macOS 13+** — do not change `Package.swift` platform/tools floor.
- **No runtime behavior change to the FIDO gate.** SP1's FIDO tests keep their expected *values*; only call-site signatures change (the `signer`→`ceremony` `GateContext` field, the `runEnroll` signature). The `confirmAndSign` move into `FidoCeremony` is **verbatim** (do not "tidy" the body).
- **`CCGateCore` gains only `GateCeremony` + the `ceremony` field.** No FIDO or Touch ID identity literal may enter core — the `GrepGateTests` token list still applies (`_ccfido`, `.ccfido`, `gate_sk`, `gate-principal`, `cc-fido`, `ccfido`, `/var/ccfido`, `cc-fido-gate@`, `com.cc-fido-gate`, `brokerd`), and Touch ID literals (`_cctouchid`, `cc-touch-id`, `cctouchid`, `com.cc-touch-id`) must never appear in `Sources/CCGateCore/` either.
- **After Task 5, `Enroll.swift` is FIDO-free** — the `GrepGateTests` `Enroll.swift` exclusion is REMOVED (the SP1 carve-out is retired; the whole SP2 residual it named is closed here).
- **Ad-hoc signing only** — no Developer ID / notarization. `swift build`'s automatic ad-hoc linker signature is the target (spike-proven). Do not add codesign identities.
- **Fail-closed everywhere** — unreadable allowed-signers, empty/garbage pubkey line, verify error, SE lookup failure, cancelled/timed-out sheet → deny. Preserve on every decision path.
- **Secure Enclave keys are P-256** (`kSecAttrKeyTypeECSECPrimeRandom`, 256-bit), algorithm `.ecdsaSignatureMessageX962SHA256`, access `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, biometric flag `.biometryCurrentSet`.
- **Touch ID allowed-signers format** = base64 of the 65-byte raw public key (`04‖X‖Y`), one per line. Blank lines and undecodable lines are ignored (fail-closed, never a parse crash).
- **`cc-touch-id` binary/product name is fixed** — install scripts and the plist depend on it.

---

### Task 1: Persistent Secure-Enclave key persistence probe (investigation — gates Tasks 6-7)

**Why first:** the spike proved a *transient* SE key. Enrollment needs a *persistent* keychain-resident biometric SE key that a *second process* (the client at a later gate) can look up and sign with. Persistent keys can require a keychain-access-group / signing entitlement that ad-hoc transient keys do not. This task settles that before `TouchIdEnroller`/`TouchIdCeremony` are built. **Investigation task — the written finding is the deliverable, not TDD.**

**Files:**
- Create: `docs/superpowers/spikes/2026-07-18-se-persistent-key-persistence.md`
- (throwaway probe in scratchpad, not committed)

- [ ] **Step 1: Write a throwaway persistent-key probe**

In a scratchpad dir, write `sepx2.swift` with two subcommands sharing one keychain **tag** (`com.cc-touch-id.gate.key` as `kSecAttrApplicationTag`, UTF-8 Data):
- `enroll`: `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, access control `[.privateKeyUsage, .biometryCurrentSet]`, and `kSecPrivateKeyAttrs = [kSecAttrIsPermanent: true, kSecAttrApplicationTag: tag, kSecAttrAccessControl: access]`. Export + print the base64 pubkey.
- `sign`: look the key up in a **fresh process** via `SecItemCopyMatching([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag, kSecAttrKeyType: EC, kSecReturnRef: true])`, then `SecKeyCreateSignature` (this prompts Touch ID). Print the base64 signature.
- `delete`: `SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag])`.

Compile with `swiftc -O sepx2.swift -o sepx2` (ad-hoc linker signature only) and inspect `codesign -dvvv sepx2`.

- [ ] **Step 2: Run the cross-process persistence test [USER-RUN — needs a touch]**

The human runs (un-sandboxed):
```bash
./sepx2 enroll            # prints pubkey; note it
./sepx2 sign              # SEPARATE process: looks up by tag, Touch ID sheet -> touch -> prints sig
./sepx2 delete
```
Record: does `enroll` succeed ad-hoc (or return `errSecMissingEntitlement`)? Does the second-process `sign` find the key and produce a signature? Any keychain-access-group requirement?

- [ ] **Step 3: Record the finding + decide the enroll persistence approach**

Write to the spike doc, with observed output as evidence, ONE of:
- **(A) ad-hoc persistent works** → `TouchIdEnroller` creates a persistent tagged SE key directly; `TouchIdCeremony` looks it up by tag. (Expected.)
- **(B) needs a keychain-access-group / entitlement** → record the exact entitlement; the fallback is to store only the public key broker-side and require the install to sign the binary with that entitlement. Adjust Tasks 6-7 to match.

- [ ] **Step 4: Commit the finding**

```bash
git add docs/superpowers/spikes/2026-07-18-se-persistent-key-persistence.md
git commit -m "docs(spike): persistent Secure Enclave key persistence finding (SP2 Task 1)"
```

---

### Task 2: Add the `GateCeremony` seam; move `confirmAndSign` into `FidoCeremony`; thread `ceremony` through `GateContext`

**Files:**
- Create: `Sources/CCGateCore/Signing/GateCeremony.swift`
- Modify: `Sources/CCGateCore/GateContext.swift` (replace `signer` field with `ceremony`)
- Modify: `Sources/CCGateCore/Client.swift` (delete the free `confirmAndSign`; call `ctx.ceremony.confirmAndSign`)
- Create: `Sources/CCFidoBackend/FidoCeremony.swift` (the moved ceremony)
- Modify: `Sources/CCFidoBackend/FidoProfile.swift:21-28` (`makeFidoContext` passes `ceremony:` not `signer:`)
- Create: `Tests/CCGateCoreTests/GateCeremonySeamTests.swift`

**Interfaces:**
- Produces: `protocol GateCeremony { func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? }`; `GateContext(profile:ceremony:verifier:enroller:)`; `struct FidoCeremony: GateCeremony` init `(signer: Signer)`.
- Consumes: `Signer`, `scrubbedEnv()` (both existing/public).

- [ ] **Step 1: Write the failing seam test**

`Tests/CCGateCoreTests/GateCeremonySeamTests.swift`:
```swift
import XCTest
@testable import CCGateCore

final class GateCeremonySeamTests: XCTestCase {
    struct FakeCeremony: GateCeremony {
        let out: Data?
        var lastRendering = ""
        func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? { out }
    }
    func testGateContextHoldsACeremony() {
        // Compiles only if GateContext exposes `ceremony` (and no longer requires `signer`).
        let ctx = GateContext(profile: dummyProfile(), ceremony: FakeCeremony(out: Data([1,2,3])),
                              verifier: AlwaysVerifier(ok: true), enroller: NoopEnroller())
        XCTAssertEqual(ctx.ceremony.confirmAndSign(rendering: "r", challenge: Data(), displayName: "d"), Data([1,2,3]))
    }
    func testCeremonyDenyIsNil() {
        let c: GateCeremony = FakeCeremony(out: nil)
        XCTAssertNil(c.confirmAndSign(rendering: "r", challenge: Data(), displayName: "d"))
    }
}

// Minimal fakes for the other three seam fields (verify/enroll are not under test here).
struct AlwaysVerifier: Verifier { let ok: Bool; func verify(challenge: Data, signature: Data) -> Bool { ok } }
struct NoopEnroller: Enroller {
    func enroll(home: String, keys: Int, profile: GateProfile) throws {}
    func positiveControl(home: String, profile: GateProfile) -> Bool { true }
    func isEnrolled(home: String) -> Bool { false }
    func removeKeyMaterial(home: String) {}
}
```
> NOTE: `NoopEnroller` already targets the **expanded** `Enroller` protocol (Task 5). If Task 5 has not landed yet, temporarily give `NoopEnroller` the *old* members (`enrollPlan`/`isEnrolled`/`removeKeyMaterial`) and switch it when Task 5 lands. `dummyProfile()` = the helper in `Tests/CCGateCoreTests/TestProfile.swift` (reuse it; if it is named differently there, use that name).

- [ ] **Step 2: Run it — verify it fails to compile**

Run: `swift test --filter CCGateCoreTests.GateCeremonySeamTests`
Expected: FAIL — `GateContext` has no `ceremony:` initializer / `GateCeremony` undefined.

- [ ] **Step 3: Add the `GateCeremony` protocol**

`Sources/CCGateCore/Signing/GateCeremony.swift`:
```swift
import Foundation
/// Client-side presence ceremony: shows what is being signed (method-specific UI) and returns a
/// challenge-bound signature on approval, nil on deny/cancel/timeout. FIDO = osascript dialog +
/// armed hardware key; Touch ID = native biometric sheet. Lives in core; impls live in backends.
public protocol GateCeremony {
    func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data?
}
```

- [ ] **Step 4: Swap `GateContext.signer` → `ceremony`**

`Sources/CCGateCore/GateContext.swift`:
```swift
import Foundation
public struct GateContext {
    public let profile: GateProfile
    public let ceremony: GateCeremony
    public let verifier: Verifier
    public let enroller: Enroller
    public init(profile: GateProfile, ceremony: GateCeremony, verifier: Verifier, enroller: Enroller) {
        self.profile = profile; self.ceremony = ceremony; self.verifier = verifier; self.enroller = enroller
    }
}
```

- [ ] **Step 5: Move `confirmAndSign` out of `Client.swift` into `FidoCeremony`**

Delete the free `func confirmAndSign(...)` (lines 4-54) from `Sources/CCGateCore/Client.swift`. In `runWrite`/`runApprove`, change both call sites:
```swift
// was: confirmAndSign(human, challenge: challenge, signer: ctx.signer, displayName: ctx.profile.displayName)
guard let sig = ctx.ceremony.confirmAndSign(rendering: human, challenge: challenge, displayName: ctx.profile.displayName) else {
```
Create `Sources/CCFidoBackend/FidoCeremony.swift` — paste the deleted body **verbatim** as the method, wrapping `Signer`:
```swift
import Foundation
import Darwin
import CCGateCore

public struct FidoCeremony: GateCeremony {
    let signer: Signer
    public init(signer: Signer) { self.signer = signer }

    public func confirmAndSign(rendering humanRendering: String, challenge: Data, displayName: String) -> Data? {
        // ---- paste the exact body of the old free confirmAndSign here, unchanged ----
        // (osascript dialog + concurrent signer.makeCanceller()/signer.sign + dialog/backstop cancel;
        //  it uses scrubbedEnv() which is public in CCGateCore)
    }
}
```
> The parameter label is `rendering` (external) / `humanRendering` (internal) so the pasted body — which refers to `humanRendering` — compiles without edits.

- [ ] **Step 6: Update `makeFidoContext` to pass `ceremony:`**

`Sources/CCFidoBackend/FidoProfile.swift`, in `makeFidoContext`:
```swift
public func makeFidoContext(home: String) -> GateContext {
    let signer = FidoSigner(keygen: fidoSignKeygen, handlePath: fidoKeyHandle(home: home), namespace: fidoProfile.namespace)
    return GateContext(
        profile: fidoProfile,
        ceremony: FidoCeremony(signer: signer),
        verifier: FidoVerifier(keygen: fidoVerifyKeygen, allowedSigners: fidoProfile.allowedSigners,
                               principal: "gate-principal", namespace: fidoProfile.namespace, keydir: fidoProfile.keydir),
        enroller: FidoEnroller())
}
```

- [ ] **Step 7: Run the seam test + full suite**

Run: `swift build && swift test`
Expected: PASS. `GateCeremonySeamTests` green; all SP1 tests green (only the two `Client.swift` call sites and `makeFidoContext` changed). `GrepGateTests` still green (moving `confirmAndSign`/osascript *out* of core only helps).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(core): GateCeremony seam; move confirmAndSign into FidoCeremony; GateContext.ceremony"
```

---

### Task 3: `CCTouchIDBackend` target + `TouchIdVerifier` (off-session, software-key [SW] roundtrip)

**Files:**
- Modify: `Package.swift` (add `CCTouchIDBackend` target + `CCTouchIDBackendTests` test target)
- Create: `Sources/CCTouchIDBackend/TouchIdVerifier.swift`
- Create: `Tests/CCTouchIDBackendTests/TouchIdVerifierTests.swift`

**Interfaces:**
- Consumes: `Verifier` (core).
- Produces: `struct TouchIdVerifier: Verifier` init `(allowedSigners: String)`; free helper `func parseAllowedP256(_ text: String) -> [SecKey]`.

- [ ] **Step 1: Add the target to `Package.swift`**

```swift
// swift-tools-version:5.9
import PackageDescription
let package = Package(
  name: "cc-presence-gate",
  platforms: [.macOS(.v13)],
  targets: [
    .target(name: "CCGateCore"),
    .target(name: "CCFidoBackend", dependencies: ["CCGateCore"]),
    .target(name: "CCTouchIDBackend", dependencies: ["CCGateCore"]),
    .executableTarget(name: "cc-fido", dependencies: ["CCGateCore", "CCFidoBackend"]),
    .testTarget(name: "CCGateCoreTests", dependencies: ["CCGateCore"]),
    .testTarget(name: "CCFidoBackendTests", dependencies: ["CCFidoBackend", "CCGateCore"]),
    .testTarget(name: "CCTouchIDBackendTests", dependencies: ["CCTouchIDBackend", "CCGateCore"]),
  ]
)
```

- [ ] **Step 2: Write the failing verifier test (software P-256 key — no SE, no touch)**

`Tests/CCTouchIDBackendTests/TouchIdVerifierTests.swift`:
```swift
import XCTest
import Security
@testable import CCTouchIDBackend

final class TouchIdVerifierTests: XCTestCase {
    // A software (non-SE) P-256 key: signs headlessly, exports the same 65-byte raw pub an SE key would.
    private func softwareKey() -> (SecKey, Data) {
        var err: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256] as CFDictionary, &err)!
        let pub = SecKeyCopyPublicKey(priv)!
        let raw = SecKeyCopyExternalRepresentation(pub, &err)! as Data
        return (priv, raw)
    }
    private func sign(_ priv: SecKey, _ msg: Data) -> Data {
        var err: Unmanaged<CFError>?
        return SecKeyCreateSignature(priv, .ecdsaSignatureMessageX962SHA256, msg as CFData, &err)! as Data
    }
    private func writeAllowed(_ pubs: [Data]) -> String {
        let path = NSTemporaryDirectory() + "allowed-\(getpid())-\(pubs.count)"
        try! pubs.map { $0.base64EncodedString() }.joined(separator: "\n").write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    func testEnrolledKeyVerifies() {
        let (priv, raw) = softwareKey()
        let chal = Data("hello".utf8); let sig = sign(priv, chal)
        let v = TouchIdVerifier(allowedSigners: writeAllowed([raw]))
        XCTAssertTrue(v.verify(challenge: chal, signature: sig))
    }
    func testWrongKeyRejected() {
        let (priv, _) = softwareKey(); let (_, otherRaw) = softwareKey()
        let chal = Data("hello".utf8); let sig = sign(priv, chal)
        let v = TouchIdVerifier(allowedSigners: writeAllowed([otherRaw]))
        XCTAssertFalse(v.verify(challenge: chal, signature: sig))
    }
    func testTamperedChallengeRejected() {
        let (priv, raw) = softwareKey()
        let sig = sign(priv, Data("hello".utf8))
        let v = TouchIdVerifier(allowedSigners: writeAllowed([raw]))
        XCTAssertFalse(v.verify(challenge: Data("hellp".utf8), signature: sig))
    }
    func testMultiKeyAnyMatchAndGarbageIgnored() {
        let (priv, raw) = softwareKey(); let (_, otherRaw) = softwareKey()
        let path = NSTemporaryDirectory() + "allowed-multi-\(getpid())"
        try! ("\n" + otherRaw.base64EncodedString() + "\nnot-base64!!!\n" + raw.base64EncodedString() + "\n")
            .write(toFile: path, atomically: true, encoding: .utf8)
        let chal = Data("x".utf8); let sig = sign(priv, chal)
        XCTAssertTrue(TouchIdVerifier(allowedSigners: path).verify(challenge: chal, signature: sig))
    }
    func testMissingFileRejects() {
        XCTAssertFalse(TouchIdVerifier(allowedSigners: "/no/such/file").verify(challenge: Data("x".utf8), signature: Data([0])))
    }
}
```

- [ ] **Step 3: Run it — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdVerifierTests`
Expected: FAIL — `TouchIdVerifier` undefined.

- [ ] **Step 4: Implement `TouchIdVerifier`**

`Sources/CCTouchIDBackend/TouchIdVerifier.swift`:
```swift
import Foundation
import Security
import CCGateCore

/// Reconstructs enrolled P-256 public keys from a base64-raw-pubkey-per-line file and verifies an
/// ECDSA(SHA-256, X9.62) signature over the challenge. Pure crypto — runs off-session in the broker
/// daemon (no Secure Enclave, no biometric). Fail-closed: unreadable file / bad lines -> false.
public func parseAllowedP256(_ text: String) -> [SecKey] {
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256,
    ]
    var keys: [SecKey] = []
    for line in text.split(whereSeparator: \.isNewline) {
        let s = line.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty, let raw = Data(base64Encoded: s), raw.count == 65 else { continue }
        if let k = SecKeyCreateWithData(raw as CFData, attrs as CFDictionary, nil) { keys.append(k) }
    }
    return keys
}

public struct TouchIdVerifier: Verifier {
    let allowedSigners: String
    public init(allowedSigners: String) { self.allowedSigners = allowedSigners }

    public func verify(challenge: Data, signature: Data) -> Bool {
        if signature.isEmpty || signature.count > MAX_SIG { return false }
        guard let text = try? String(contentsOfFile: allowedSigners, encoding: .utf8) else { return false }
        for key in parseAllowedP256(text) {
            if SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256,
                                     challenge as CFData, signature as CFData, nil) { return true }
        }
        return false
    }
}
```

- [ ] **Step 5: Run tests green + build**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdVerifierTests && swift build`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(touchid): CCTouchIDBackend target + TouchIdVerifier (off-session P-256, [SW] roundtrip)"
```

---

### Task 4: `boundedReason` — the Touch ID sheet's `localizedReason` renderer

**Files:**
- Create: `Sources/CCTouchIDBackend/BoundedReason.swift`
- Create: `Tests/CCTouchIDBackendTests/BoundedReasonTests.swift`

**Interfaces:**
- Produces: `func boundedReason(_ rendering: String, displayName: String, maxLen: Int = 220) -> String`.

- [ ] **Step 1: Write the failing test**

`Tests/CCTouchIDBackendTests/BoundedReasonTests.swift`:
```swift
import XCTest
@testable import CCTouchIDBackend

final class BoundedReasonTests: XCTestCase {
    func testShortRenderingIsShownWithDigestAndSize() {
        let r = boundedReason("write ~/.zshrc", displayName: "cc-touch-id")
        XCTAssertTrue(r.hasPrefix("cc-touch-id: write ~/.zshrc"))
        XCTAssertTrue(r.contains("sha256 "))
        XCTAssertTrue(r.contains(" B]"))
    }
    func testLongRenderingIsTruncatedButBounded() {
        let long = String(repeating: "A", count: 5000)
        let r = boundedReason(long, displayName: "cc-touch-id", maxLen: 220)
        XCTAssertLessThan(r.count, 320)              // head(<=220) + fixed suffix
        XCTAssertTrue(r.contains("…"))
        XCTAssertTrue(r.contains("5000 B]"))          // size reflects the FULL rendering, not the truncation
    }
    func testDigestBindsFullRenderingNotTruncation() {
        // Two long strings sharing a 220-char prefix must yield DIFFERENT reasons (digest over full text).
        let a = String(repeating: "A", count: 300) + "X"
        let b = String(repeating: "A", count: 300) + "Y"
        XCTAssertNotEqual(boundedReason(a, displayName: "d"), boundedReason(b, displayName: "d"))
    }
    func testPreEscapedTokensArePreserved() {
        // The broker already confusable-escapes; boundedReason must not re-process the token.
        let r = boundedReason("write <U+202E> file", displayName: "d")
        XCTAssertTrue(r.contains("<U+202E>"))
    }
}
```

- [ ] **Step 2: Run it — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.BoundedReasonTests`
Expected: FAIL — `boundedReason` undefined.

- [ ] **Step 3: Implement `boundedReason`**

`Sources/CCTouchIDBackend/BoundedReason.swift`:
```swift
import Foundation
import CryptoKit

/// The native Touch ID sheet shows a short `localizedReason`, not the full signed rendering (WYSIWYS
/// is deliberately softened for Touch ID — see the SP2 spec). We show a bounded head of the rendering
/// plus a sha256 fingerprint + byte size of the FULL rendering, so a truncated display can't hide the
/// tail: two renderings sharing a prefix produce different reasons. The challenge still binds the full
/// canonical bytes; this string is advisory display only.
public func boundedReason(_ rendering: String, displayName: String, maxLen: Int = 220) -> String {
    let full = Data(rendering.utf8)
    let digest = SHA256.hash(data: full).prefix(6).map { String(format: "%02x", $0) }.joined()
    let head = rendering.count > maxLen ? String(rendering.prefix(maxLen)) + "…" : rendering
    return "\(displayName): \(head)\n[sha256 \(digest)… \(full.count) B]"
}
```

- [ ] **Step 4: Run green**

Run: `swift test --filter CCTouchIDBackendTests.BoundedReasonTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(touchid): boundedReason localizedReason renderer (digest binds full rendering)"
```

---

### Task 5: Make `runEnroll` method-agnostic — expand `Enroller`, move FIDO enroll into `FidoEnroller`, retire the grep-gate carve-out

**Files:**
- Modify: `Sources/CCGateCore/Signing/Enroller.swift` (expand protocol)
- Modify: `Sources/CCGateCore/Enroll.swift` (thin driver; FIDO-free)
- Modify: `Sources/CCFidoBackend/FidoEnroller.swift` (implement `enroll`/`positiveControl`; keep `enrollPlan` internal)
- Modify: `Sources/cc-fido/main.swift:97-106` (new `runEnroll` call)
- Modify: `Tests/CCGateCoreTests/GrepGateTests.swift` (remove the `Enroll.swift` exclusion)
- Modify: `Tests/CCFidoBackendTests/FidoEnrollerTests.swift` if it referenced protocol-level `enrollPlan` (keep it as a `FidoEnroller` method)

**Interfaces:**
- Produces (expanded `Enroller`):
  - `func enroll(home: String, keys: Int, profile: GateProfile) throws`
  - `func positiveControl(home: String, profile: GateProfile) -> Bool`
  - `func isEnrolled(home: String) -> Bool` (unchanged)
  - `func removeKeyMaterial(home: String)` (unchanged)
  - **removes** `enrollPlan` from the protocol (stays as a `FidoEnroller` method for its tests).
- Produces: `func runEnroll(home: String, keys: Int, enroller: Enroller, profile: GateProfile) throws`.

- [ ] **Step 1: Expand the `Enroller` protocol**

`Sources/CCGateCore/Signing/Enroller.swift`:
```swift
import Foundation
public protocol Enroller {
    /// Perform the full method-specific enrollment for `keys` keys, running as the LOGIN user.
    /// Prints its own ">>> TOUCH ... <<<" prompts and may escalate (runPrivileged) to register public
    /// key material into the service-account-owned allowed-signers file. Throws on any failure.
    func enroll(home: String, keys: Int, profile: GateProfile) throws
    /// Post-enroll positive control: proves the method truly requires presence / round-trips end to
    /// end (FIDO = negative blink-test; Touch ID = sign->verify self-test). false -> abort activation.
    func positiveControl(home: String, profile: GateProfile) -> Bool
    /// Is a gate key present for this user? FIDO = key file on disk; SE = keychain query.
    func isEnrolled(home: String) -> Bool
    /// Delete this method's key material (uninstall). FIDO = rm key files; SE = keychain delete.
    func removeKeyMaterial(home: String)
}
```

- [ ] **Step 2: Rewrite `Enroll.swift` as a thin, FIDO-free driver**

`Sources/CCGateCore/Enroll.swift`:
```swift
import Foundation

public enum EnrollError: Error { case failed(String) }

/// Method-agnostic enroll orchestration. All method-specific work (key creation, pubkey
/// registration, presence self-test) lives behind the `Enroller` seam. No backend identity here.
public func runEnroll(home: String, keys: Int, enroller: Enroller, profile: GateProfile) throws {
    try enroller.enroll(home: home, keys: max(1, keys), profile: profile)
    if !enroller.positiveControl(home: home, profile: profile) {
        throw EnrollError.failed("positive control failed — presence not verified")
    }
}
```

- [ ] **Step 3: Move the FIDO enroll body into `FidoEnroller`**

In `Sources/CCFidoBackend/FidoEnroller.swift`, add `enroll` (the old `runEnroll` body, minus the injected params — it now uses `fidoSignKeygen`, `home + "/.ccfido"`, `fidoProfile.namespace` directly) and `positiveControl` (wraps `fidoNegativeBlinkTest`). Keep `enrollPlan` as an internal method (its tests stay). Sketch:
```swift
public struct FidoEnroller: Enroller {
    public init() {}
    public func enrollPlan(home: String, index: Int) -> [[String]] { /* unchanged — used by enroll() + tests */ }

    public func enroll(home: String, keys: Int, profile: GateProfile) throws {
        let dir = "\(home)/.ccfido"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        _ = run("/bin/chmod", ["700", dir])
        for n in 1...max(1, keys) {
            guard let argv = enrollPlan(home: home, index: n).first else { throw EnrollError.failed("no plan #\(n)") }
            FileHandle.standardError.write(Data(">>> TOUCH to enroll key #\(n) of \(max(1,keys)) <<<\n".utf8))
            if run(fidoSignKeygen, argv).0 != 0 { throw EnrollError.failed("ssh-keygen key #\(n)") }
            _ = run("/bin/chmod", ["600", "\(dir)/gate_sk\(n)"])
            guard let pub = (try? String(contentsOfFile: "\(dir)/gate_sk\(n).pub", encoding: .utf8))?
                    .trimmingCharacters(in: .whitespacesAndNewlines), !pub.isEmpty else { throw EnrollError.failed("read pubkey #\(n)") }
            if !runPrivileged(["/bin/sh", "-c", "printf 'gate-principal %s\\n' \"$1\" >> \(profile.allowedSigners)", "sh", pub]) {
                throw EnrollError.failed("register key #\(n)")
            }
        }
        _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1", fidoKeyHandle(home: home)])
        _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1.pub", fidoKeyHandle(home: home) + ".pub"])
        _ = runPrivileged(["/usr/sbin/chown", profile.serviceAccount, profile.allowedSigners])
        _ = runPrivileged(["/bin/chmod", "600", profile.allowedSigners])
    }

    public func positiveControl(home: String, profile: GateProfile) -> Bool {
        fidoNegativeBlinkTest(handle: "\(home)/.ccfido/gate_sk1", namespace: profile.namespace)
    }
    public func isEnrolled(home: String) -> Bool { /* unchanged */ }
    public func removeKeyMaterial(home: String) { /* unchanged */ }
}
```
> `run`, `runPrivileged`, `fidoNegativeBlinkTest`, `fidoSignKeygen`, `fidoKeyHandle` are all reachable from `CCFidoBackend` (core-public or backend-local). The blink-test previously ran inside `runEnroll` *after* the symlink; here it runs as `positiveControl` *after* `enroll` returns — same order.

- [ ] **Step 4: Update `cc-fido/main.swift` enroll case**

Replace lines 97-106's `runEnroll(...)` call with:
```swift
case "enroll":
    if getuid() == 0 { FileHandle.standardError.write(Data("cc-fido enroll: run as your login user (not sudo) — it needs your key + a touch\n".utf8)); exit(1) }
    let keys = flagValue("--keys", in: args).flatMap { Int($0) } ?? 1
    let home = realLoginHome()
    do { try runEnroll(home: home, keys: keys, enroller: FidoEnroller(), profile: fidoProfile)
         print("cc-fido: enrolled. Next: sudo cc-fido activate"); exit(0) }
    catch { FileHandle.standardError.write(Data("cc-fido enroll failed: \(error)\n".utf8)); exit(1) }
```

- [ ] **Step 5: Remove the `Enroll.swift` grep-gate exclusion**

In `Tests/CCGateCoreTests/GrepGateTests.swift`, delete the `.filter { $0.lastPathComponent != "Enroll.swift" }` clause so `Enroll.swift` is now swept like every other core file.

- [ ] **Step 6: Run full suite + build**

Run: `swift build && swift test`
Expected: PASS. `GrepGateTests` now green *including* `Enroll.swift` (it is FIDO-free). `FidoEnrollerTests` green (`enrollPlan` still present). If `GateCeremonySeamTests`'s `NoopEnroller` used the old members, switch it to the new `enroll`/`positiveControl` now.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(core): method-agnostic runEnroll via Enroller.enroll/positiveControl; Enroll.swift now FIDO-free"
```

---

### Task 6: Secure-Enclave key manager + `TouchIdCeremony` (client-side biometric sign + LAContext cancel)

**Files:**
- Create: `Sources/CCTouchIDBackend/SecureEnclaveKey.swift` (tag, create/lookup/delete, export pub)
- Create: `Sources/CCTouchIDBackend/TouchIdCeremony.swift` (`GateCeremony` + `TouchIdCanceller`)
- Create: `Tests/CCTouchIDBackendTests/SecureEnclaveKeyTests.swift`

**Interfaces:**
- Consumes: `GateCeremony`, `CeremonyCanceller` (core), `boundedReason`, `TouchIdVerifier`.
- Produces:
  - `enum SecureEnclaveKey { static let tag: Data; static func load() -> SecKey?; static func create() throws -> SecKey; static func delete(); static func exportRaw(_ pub: SecKey) -> Data? }` (persistence per Task 1 finding).
  - `final class TouchIdCanceller: CeremonyCanceller` wrapping an `LAContext` (`cancel()` → `invalidate()`).
  - `final class TouchIdCeremony: GateCeremony` init `()`.

- [ ] **Step 1: Write the [SW]-testable pieces' tests**

Only the *pure* pieces are headless — key tag, raw-pub export shape, and that a fresh `TouchIdCanceller.cancel()` invalidates its context. Real persistent-SE create/lookup/sign is USER-RUN (Task 11).
`Tests/CCTouchIDBackendTests/SecureEnclaveKeyTests.swift`:
```swift
import XCTest
import Security
import LocalAuthentication
@testable import CCTouchIDBackend

final class SecureEnclaveKeyTests: XCTestCase {
    func testTagIsStableAndNamespaced() {
        XCTAssertEqual(SecureEnclaveKey.tag, Data("com.cc-touch-id.gate.key".utf8))
    }
    func testExportRawIs65BytesForP256() {
        // software P-256 key stands in for shape (an SE pubkey exports identically: 65-byte 04||X||Y)
        var err: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey([kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                          kSecAttrKeySizeInBits as String: 256] as CFDictionary, &err)!
        let raw = SecureEnclaveKey.exportRaw(SecKeyCopyPublicKey(priv)!)
        XCTAssertEqual(raw?.count, 65)
        XCTAssertEqual(raw?.first, 0x04)
    }
    func testCancellerInvalidatesContext() {
        let ctx = LAContext()
        let c = TouchIdCanceller(context: ctx)
        c.cancel()   // must not crash; ctx is invalidated (idempotent)
        c.cancel()
    }
}
```

- [ ] **Step 2: Run it — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.SecureEnclaveKeyTests`
Expected: FAIL — `SecureEnclaveKey`/`TouchIdCanceller` undefined.

- [ ] **Step 3: Implement `SecureEnclaveKey`** (adapt to Task 1's finding — (A) ad-hoc persistent shown here)

`Sources/CCTouchIDBackend/SecureEnclaveKey.swift`:
```swift
import Foundation
import Security
import LocalAuthentication

/// Owns the persistent, biometric-gated Secure Enclave P-256 key for this user. Identified by a
/// stable keychain tag so the client can look it up at gate time (a different process from enroll).
public enum SecureEnclaveKey {
    public static let tag = Data("com.cc-touch-id.gate.key".utf8)

    /// Create + persist the enrolled key. Runs at enroll time in the login session.
    public static func create() throws -> SecKey {
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err) else {
            throw EnrollError.failed("access control: \(String(describing: err?.takeRetainedValue()))")
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            throw EnrollError.failed("SE key create: \(String(describing: err?.takeRetainedValue()))")
        }
        return priv
    }

    /// Look up the persistent key. `ctx` (optional) binds an LAContext so a canceller can invalidate it.
    public static func load(ctx: LAContext? = nil) -> SecKey? {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let ctx = ctx { q[kSecUseAuthenticationContext as String] = ctx }
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? (out as! SecKey) : nil
    }

    public static func delete() {
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag] as CFDictionary)
    }

    public static func exportRaw(_ pub: SecKey) -> Data? {
        SecKeyCopyExternalRepresentation(pub, nil) as Data?
    }
}
```
> `EnrollError` is public in `CCGateCore` — import it. If Task 1 chose fallback (B), add the keychain-access-group attr here exactly as the spike recorded.

- [ ] **Step 4: Implement `TouchIdCeremony` + `TouchIdCanceller`**

`Sources/CCTouchIDBackend/TouchIdCeremony.swift`:
```swift
import Foundation
import Security
import LocalAuthentication
import CCGateCore

public final class TouchIdCanceller: CeremonyCanceller {
    private let ctx: LAContext
    public init(context: LAContext) { self.ctx = context }
    public func cancel() { ctx.invalidate() }   // aborts an in-flight Touch ID prompt (LAError -9)
}

/// Client-side. The native Touch ID sheet IS the presence ceremony; no osascript. Returns the SE
/// signature on touch, nil on cancel/give-up/error (fail-closed). Runs in the login GUI session.
public final class TouchIdCeremony: GateCeremony {
    public init() {}
    public func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? {
        let ctx = LAContext()
        ctx.localizedReason = boundedReason(rendering, displayName: displayName)
        ctx.localizedCancelTitle = "Cancel"
        guard let priv = SecureEnclaveKey.load(ctx: ctx) else { return nil }  // not enrolled -> deny
        var err: Unmanaged<CFError>?
        // SecKeyCreateSignature presents the sheet (key is biometric-gated + ctx-bound).
        guard let sig = SecKeyCreateSignature(priv, .ecdsaSignatureMessageX962SHA256,
                                              challenge as CFData, &err) as Data? else { return nil }
        return sig
    }
    /// Exposed for the enroll positive-control + USER-RUN cancel test.
    public func makeCanceller(_ ctx: LAContext) -> CeremonyCanceller { TouchIdCanceller(context: ctx) }
}
```

- [ ] **Step 5: Run [SW] tests green + build**

Run: `swift test --filter CCTouchIDBackendTests.SecureEnclaveKeyTests && swift build`
Expected: PASS (the pure pieces). SE create/sign are exercised in Task 11.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(touchid): SecureEnclaveKey manager + TouchIdCeremony (biometric sheet, LAContext cancel)"
```

---

### Task 7: `TouchIdEnroller` — persistent SE key create, pubkey register, isEnrolled/removeKeyMaterial, sign→verify positive control

**Files:**
- Create: `Sources/CCTouchIDBackend/TouchIdEnroller.swift`
- Create: `Tests/CCTouchIDBackendTests/TouchIdEnrollerTests.swift`

**Interfaces:**
- Consumes: `Enroller`, `GateProfile`, `runPrivileged` (core), `SecureEnclaveKey`, `TouchIdVerifier`.
- Produces: `struct TouchIdEnroller: Enroller`.

- [ ] **Step 1: Write the [SW]-testable enroller tests**

Persistent SE create/register is USER-RUN; [SW] covers `isEnrolled` on a clean home and the registration *shape* via an injected privileged-runner. Design `TouchIdEnroller` to take an injectable `priv` runner defaulting to `runPrivileged` so the register step is testable headlessly.
`Tests/CCTouchIDBackendTests/TouchIdEnrollerTests.swift`:
```swift
import XCTest
@testable import CCTouchIDBackend
@testable import CCGateCore

final class TouchIdEnrollerTests: XCTestCase {
    private func profile() -> GateProfile {
        GateProfile(serviceAccount: "_cctouchid", accountRealName: "rn", namespace: "ns",
            keydir: "/var/cctouchid", runDir: "/var/cctouchid-run", sock: "/var/cctouchid-run/g.sock",
            daemonLogErr: "/var/cctouchid/e.err", codeDir: "/opt/cc-touch-id", policy: "/opt/cc-touch-id/p.json",
            binaryName: "cc-touch-id", displayName: "cc-touch-id", launchdLabel: "com.cc-touch-id.brokerd",
            plist: "/L/x.plist", daemonMatchPattern: "cc-touch-id daemon", claudeCodeDir: "/CC", managedSettings: "/CC/m.json")
    }
    func testIsEnrolledFalseWhenNoKey() {
        // On a clean CI keychain there is no enrolled key.
        SecureEnclaveKey.delete()
        XCTAssertFalse(TouchIdEnroller().isEnrolled(home: "/tmp/h"))
    }
    func testRegisterAppendsBase64PubkeyLine() {
        var captured: [[String]] = []
        let e = TouchIdEnroller(priv: { captured.append($0); return true })
        e.register(pubBase64: "QUJD", profile: profile())
        // must append base64 pubkey (NO principal prefix — that was FIDO) into profile.allowedSigners
        let joined = captured.last!.joined(separator: " ")
        XCTAssertTrue(joined.contains("/var/cctouchid/allowed_signers"))
        XCTAssertTrue(joined.contains("QUJD"))
        XCTAssertFalse(joined.contains("gate-principal"))
    }
}
```
> `GateProfile.allowedSigners` is the derived `keydir + "/allowed_signers"` from SP1.

- [ ] **Step 2: Run it — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdEnrollerTests`
Expected: FAIL — `TouchIdEnroller` undefined.

- [ ] **Step 3: Implement `TouchIdEnroller`**

`Sources/CCTouchIDBackend/TouchIdEnroller.swift`:
```swift
import Foundation
import LocalAuthentication
import CCGateCore

public struct TouchIdEnroller: Enroller {
    let priv: ([String]) -> Bool
    public init(priv: @escaping ([String]) -> Bool = { runPrivileged($0) }) { self.priv = priv }

    /// Append a base64 raw pubkey line into the service-account-owned allowed-signers file (one escalation).
    /// pub passed as $1 positional — never interpolated into the shell text.
    public func register(pubBase64: String, profile: GateProfile) {
        _ = priv(["/bin/sh", "-c", "printf '%s\\n' \"$1\" >> \(profile.allowedSigners)", "sh", pubBase64])
    }

    public func enroll(home: String, keys: Int, profile: GateProfile) throws {
        // Touch ID uses a single per-user SE key regardless of `keys` (no multi-key handle concept).
        SecureEnclaveKey.delete()                             // idempotent re-enroll
        FileHandle.standardError.write(Data(">>> A Touch ID key will be created for cc-touch-id <<<\n".utf8))
        let key = try SecureEnclaveKey.create()
        guard let pub = SecKeyCopyPublicKey(key), let raw = SecureEnclaveKey.exportRaw(pub) else {
            throw EnrollError.failed("export SE pubkey")
        }
        register(pubBase64: raw.base64EncodedString(), profile: profile)
        _ = priv(["/usr/sbin/chown", profile.serviceAccount, profile.allowedSigners])
        _ = priv(["/bin/chmod", "600", profile.allowedSigners])
    }

    /// Sign a nonce with the freshly enrolled key (one touch) and verify with this method's verifier.
    public func positiveControl(home: String, profile: GateProfile) -> Bool {
        let nonce = Data("cc-touch-id enroll self-test \(getpid())".utf8)
        FileHandle.standardError.write(Data(">>> TOUCH to confirm enrollment <<<\n".utf8))
        guard let sig = TouchIdCeremony().confirmAndSign(rendering: "enrollment self-test",
                                                         challenge: nonce, displayName: profile.displayName) else { return false }
        return TouchIdVerifier(allowedSigners: profile.allowedSigners).verify(challenge: nonce, signature: sig)
    }

    public func isEnrolled(home: String) -> Bool { SecureEnclaveKey.load() != nil }
    public func removeKeyMaterial(home: String) { SecureEnclaveKey.delete() }
}
```

- [ ] **Step 4: Run [SW] tests green + build**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdEnrollerTests && swift build`
Expected: PASS (`isEnrolled` false on clean home; register shape correct). Full SE enroll is Task 11.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(touchid): TouchIdEnroller (persistent SE key, base64 pubkey register, sign->verify positive control)"
```

---

### Task 8: `touchIdProfile` + `makeTouchIdContext`

**Files:**
- Create: `Sources/CCTouchIDBackend/TouchIdProfile.swift`
- Create: `Tests/CCTouchIDBackendTests/TouchIdProfileTests.swift`

**Interfaces:**
- Produces: `public let touchIdProfile: GateProfile`; `public func makeTouchIdContext(home: String) -> GateContext`.

- [ ] **Step 1: Write the profile test**

`Tests/CCTouchIDBackendTests/TouchIdProfileTests.swift`:
```swift
import XCTest
@testable import CCTouchIDBackend
@testable import CCGateCore

final class TouchIdProfileTests: XCTestCase {
    func testProfileIdentityAndDerivedControlPaths() {
        let p = touchIdProfile
        XCTAssertEqual(p.serviceAccount, "_cctouchid")
        XCTAssertEqual(p.binaryName, "cc-touch-id")
        XCTAssertEqual(p.sock, "/var/cctouchid-run/gate.sock")
        XCTAssertEqual(p.allowedSigners, "/var/cctouchid/allowed_signers")
        XCTAssertEqual(p.daemonMatchPattern, "cc-touch-id daemon")
        XCTAssertTrue(p.controlDenylist.contains("/var/cctouchid/allowed_signers"))
    }
    func testContextComposesTouchIdSeams() {
        let ctx = makeTouchIdContext(home: "/tmp/h")
        XCTAssertTrue(ctx.ceremony is TouchIdCeremony)
        XCTAssertTrue(ctx.verifier is TouchIdVerifier)
        XCTAssertTrue(ctx.enroller is TouchIdEnroller)
    }
}
```

- [ ] **Step 2: Run it — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdProfileTests`
Expected: FAIL — `touchIdProfile`/`makeTouchIdContext` undefined.

- [ ] **Step 3: Implement the profile + factory**

`Sources/CCTouchIDBackend/TouchIdProfile.swift`:
```swift
import Foundation
import CCGateCore

public let touchIdProfile = GateProfile(
    serviceAccount: "_cctouchid", accountRealName: "cc-touch-id broker",
    namespace: "cc-touch-id@example.test",
    keydir: "/var/cctouchid", runDir: "/var/cctouchid-run", sock: "/var/cctouchid-run/gate.sock",
    daemonLogErr: "/var/cctouchid/brokerd.err",
    codeDir: "/opt/cc-touch-id", policy: "/opt/cc-touch-id/policy.json",
    binaryName: "cc-touch-id", displayName: "cc-touch-id",
    launchdLabel: "com.cc-touch-id.brokerd",
    plist: "/Library/LaunchDaemons/com.cc-touch-id.brokerd.plist",
    daemonMatchPattern: "cc-touch-id daemon",
    claudeCodeDir: "/Library/Application Support/ClaudeCode",
    managedSettings: "/Library/Application Support/ClaudeCode/managed-settings.json")

public func makeTouchIdContext(home: String) -> GateContext {
    GateContext(
        profile: touchIdProfile,
        ceremony: TouchIdCeremony(),
        verifier: TouchIdVerifier(allowedSigners: touchIdProfile.allowedSigners),
        enroller: TouchIdEnroller())
}
```

- [ ] **Step 4: Run green + build**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdProfileTests && swift build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(touchid): touchIdProfile + makeTouchIdContext composition"
```

---

### Task 9: `cc-touch-id` executable target + dispatcher

**Files:**
- Modify: `Package.swift` (add `cc-touch-id` executable target)
- Create: `Sources/cc-touch-id/main.swift`

**Interfaces:**
- Consumes: `makeTouchIdContext`, `touchIdProfile` (backend); all `ctx`/`profile`-threaded core entry points (`hookMain`, `runWrite`, `runApprove`, `Broker`, `installPrereqs`, `activate`, `uninstall`, `gatherStatus`, `runEnroll`, `renderPlist`, `renderManagedSettings`, `CustodyRegistry`, `MacOSPlatform`).

- [ ] **Step 1: Add the executable target**

In `Package.swift` `targets:` add:
```swift
    .executableTarget(name: "cc-touch-id", dependencies: ["CCGateCore", "CCTouchIDBackend"]),
```

- [ ] **Step 2: Write `cc-touch-id/main.swift`**

Mirror `Sources/cc-fido/main.swift`, with these differences: import `CCTouchIDBackend` (not `CCFidoBackend`); build the context with `makeTouchIdContext`/`touchIdProfile`; all user-facing strings say `cc-touch-id`; the `enroll` case calls `runEnroll(home:keys:enroller: TouchIdEnroller(), profile: touchIdProfile)`; **drop** the FIDO-only internals (`_blink-test`); `_render-plist`/`_render-managed`/`_verify-audit`/`_registry-add`/`_validate-policy`/`_render-policy`/`_cc-version`/`status`/`enroll-file`/`enroll-dir` are reused verbatim with `touchIdProfile`. Header:
```swift
import Foundation
import CCGateCore
import CCTouchIDBackend

let touchCtx = makeTouchIdContext(home: NSHomeDirectory())
let args = Array(CommandLine.arguments.dropFirst())

func usage() -> Never {
    FileHandle.standardError.write(Data("usage: cc-touch-id {daemon|hook|write <path>|enroll|install [--policy PATH]|activate|uninstall|enroll-file <path> [mode]|enroll-dir <path>|status [--json]|_validate-policy <path>|_render-policy <src> <home>}\n".utf8))
    exit(2)
}
func realLoginHome() -> String {
    if let u = ProcessInfo.processInfo.environment["SUDO_USER"], let pw = getpwnam(u) { return String(cString: pw.pointee.pw_dir) }
    return NSHomeDirectory()
}
func installRepoPolicyDefault() -> String { touchIdProfile.codeDir + "/policy.json.template" }
// ... (ccfidoUIDOr→cctouchidUIDOr, warnAncestors, enrollSteps, rollbackFileLock: copy verbatim, swap fidoProfile→touchIdProfile and error prefixes to cc-touch-id) ...

guard let cmd = args.first else { usage() }
switch cmd {
case "daemon": try Broker(profile: touchCtx.profile, verifier: touchCtx.verifier).serve()
case "hook":   hookMain(ctx: touchCtx)
case "write":
    guard args.count >= 2 else { usage() }
    exit(runWrite(ctx: touchCtx, path: args[1], content: FileHandle.standardInput.readDataToEndOfFile()))
case "enroll":
    if getuid() == 0 { FileHandle.standardError.write(Data("cc-touch-id enroll: run as your login user (not sudo)\n".utf8)); exit(1) }
    let home = realLoginHome()
    do { try runEnroll(home: home, keys: 1, enroller: TouchIdEnroller(), profile: touchIdProfile)
         print("cc-touch-id: enrolled. Next: sudo cc-touch-id activate"); exit(0) }
    catch { FileHandle.standardError.write(Data("cc-touch-id enroll failed: \(error)\n".utf8)); exit(1) }
// install / activate / uninstall / status / enroll-file / enroll-dir / _render-* / _verify-audit /
// _registry-add / _validate-policy / _render-policy: copy the cc-fido case bodies verbatim, replacing
// makeFidoContext→makeTouchIdContext and fidoProfile→touchIdProfile. Omit `_blink-test`.
default: FileHandle.standardError.write(Data("cc-touch-id: unknown command \(cmd)\n".utf8)); exit(2)
}
```
> `_render-managed` emits the hook command `touchIdProfile.codeDir + "/" + touchIdProfile.binaryName + " hook"` — identical logic to `cc-fido`, different profile.

- [ ] **Step 3: Build both executables**

Run: `swift build && swift test`
Expected: PASS. Both `.build/debug/cc-fido` and `.build/debug/cc-touch-id` exist; suites green.

- [ ] **Step 4: Smoke-test the dispatcher headlessly**

Run: `.build/debug/cc-touch-id status --json`
Expected: JSON status (all-negative on an un-installed machine) — proves compose/dispatch works without root.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(touchid): cc-touch-id executable + dispatcher"
```

---

### Task 10: Marketplace + `plugins/cc-touch-id/` + install skill (Step-0 bootstrap, Touch ID preflight)

**Files:**
- Modify: `.claude-plugin/marketplace.json` (add `cc-touch-id`)
- Create: `plugins/cc-touch-id/.claude-plugin/plugin.json`
- Create: `plugins/cc-touch-id/skills/install/SKILL.md`
- Create: `plugins/cc-touch-id/install/policy.json` (copy of `plugins/cc-fido/install/policy.json`)
- Create: `plugins/cc-touch-id/install/POLICY.md` (copy, retitled)
- Modify: `README.md` (add the Touch ID gate + `/cc-touch-id:install`)

- [ ] **Step 1: Add the marketplace entry**

`.claude-plugin/marketplace.json`:
```json
{ "name": "cc-presence-gate", "owner": { "name": "Sean Perkins" },
  "plugins": [
    { "name": "cc-fido", "source": "./plugins/cc-fido" },
    { "name": "cc-touch-id", "source": "./plugins/cc-touch-id" }
  ] }
```

- [ ] **Step 2: `plugin.json`**

`plugins/cc-touch-id/.claude-plugin/plugin.json`:
```json
{ "name": "cc-touch-id", "description": "Require a Touch ID (Secure Enclave) presence check before high-risk Claude Code tool calls.", "version": "0.1.0" }
```

- [ ] **Step 3: Copy the install policy + doc**

```bash
mkdir -p plugins/cc-touch-id/install plugins/cc-touch-id/skills/install
cp plugins/cc-fido/install/policy.json plugins/cc-touch-id/install/policy.json
cp plugins/cc-fido/install/POLICY.md  plugins/cc-touch-id/install/POLICY.md
```
Edit `POLICY.md`'s title/paths to `cc-touch-id` / `/opt/cc-touch-id`.

- [ ] **Step 4: Write the install skill**

`plugins/cc-touch-id/skills/install/SKILL.md`: mirror `plugins/cc-fido/skills/install/SKILL.md`, driving `cc-touch-id install/enroll/activate/uninstall`, with a **Step 0**:
- preflight: `xcode-select -p` (swift present); **`bioutil -rs`** (or `bioutil -c`) to confirm Touch ID hardware + at least one enrolled fingerprint — if absent, STOP with a clear message (Touch ID gate needs a fingerprint).
- bootstrap: `swift build -c release` from the repo root located via `${CLAUDE_PLUGIN_ROOT}` (per the SP1 marketplace-clone spike); the ad-hoc linker signature is sufficient — **do not** require a Developer ID.
- `--policy plugins/cc-touch-id/install/policy.json`.
- A prominent note: **`cc-touch-id` and `cc-fido` do not coexist yet** — installing one replaces the other's managed hook (mutual-exclusion is a later SP2 cycle).

- [ ] **Step 5: Update README**

Add a short "Touch ID gate" section pointing at `/cc-touch-id:install`, noting it as an alternative presence method to the FIDO key, and the no-coexistence caveat.

- [ ] **Step 6: Validate + build**

Run: `swift build && swift test`; if available `claude plugin validate .`
Expected: build/tests PASS; plugin validates.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(packaging): cc-touch-id plugin + marketplace entry + install skill (Step-0 bootstrap, Touch ID preflight)"
```

---

### Task 11: [USER-RUN] hardware acceptance — human runs, pastes output

**Files:**
- Create: `scripts/userrun/touchid_accept.sh`
- Create: `scripts/userrun/touchid_cancel.sh`

**This task CANNOT be run by Claude** (needs sudo + a real fingerprint). Authored here; the human runs it un-sandboxed and pastes output.

- [ ] **Step 1: Author `touchid_accept.sh`**

Mirror `scripts/userrun/task7_accept.sh`, targeting `cc-touch-id`: `sudo cc-touch-id install` → `cc-touch-id enroll` (create SE key + enroll-time positive-control touch) → `sudo cc-touch-id activate` → trigger a gated write → operator **touches** → assert the write landed and `_verify-audit` shows a `write_ok`. Guard against outer sudo like the FIDO script.

- [ ] **Step 2: Author `touchid_cancel.sh`**

Mirror the FIDO cancel script: trigger a gated write; the Touch ID sheet appears; operator **clicks Cancel** (and, in a second run, waits for give-up). Assert the command exits promptly, denies, performs **no write** (compare target mtime/content before/after), and required no successful touch.

- [ ] **Step 3: [USER-RUN] Approve+Touch path**

Human runs `sudo scripts/userrun/touchid_accept.sh`; confirms enroll positive-control passes, the gate fires, and a real fingerprint approves a gated write.

- [ ] **Step 4: [USER-RUN] Cancel + give-up path**

Human runs `scripts/userrun/touchid_cancel.sh`; confirms prompt denial with no write for both explicit Cancel and give-up.

- [ ] **Step 5: [USER-RUN] Clean-machine install reaches active**

Human runs `/cc-touch-id:install` on a machine where `command -v cc-touch-id` initially fails; confirms it reaches `status: active` via the Step-0 bootstrap.

- [ ] **Step 6: Commit (after human confirms all paths pass)**

```bash
git add scripts/userrun/touchid_accept.sh scripts/userrun/touchid_cancel.sh
git commit -m "test(userrun): cc-touch-id acceptance (enroll+approve+touch; Cancel/give-up deny, no write)"
```

---

## Self-Review

**Spec coverage:**
- `GateCeremony` seam + move `confirmAndSign` + `GateContext.ceremony` → Task 2.
- SE crypto: `TouchIdVerifier` (off-session, software-key roundtrip) → Task 3; `boundedReason` → Task 4; `TouchIdCeremony`/`SecureEnclaveKey`/`LAContext` cancel → Task 6.
- Method-agnostic `runEnroll` + Enroll.swift de-FIDO + grep-gate carve-out retired → Task 5.
- `TouchIdEnroller` (persistent SE key, base64 register, `isEnrolled`/`removeKeyMaterial`, sign→verify positive control) → Task 7.
- `touchIdProfile`/`makeTouchIdContext` → Task 8; `cc-touch-id` executable/dispatcher → Task 9.
- Install port (marketplace + plugin + skill Step-0 bootstrap + Touch ID preflight + no-coexistence note) → Task 10.
- Persistent-key entitlement residual (spike-flagged) → Task 1 (gates 6-7).
- Testing: [SW] verifier/boundedReason/enroller-shape/seam + grep gate → Tasks 2-8; [USER-RUN] enroll/approve/cancel/clean-install → Task 11.
- Non-goal (Pillar C mutual-exclusion) correctly **absent**; the no-coexistence caveat is documented in Task 10.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; the one FIDO-ceremony "paste verbatim" (Task 2 Step 5) is an explicit move of existing, in-repo code, not a placeholder.

**Type consistency:** `GateCeremony.confirmAndSign(rendering:challenge:displayName:)`, `GateContext(profile:ceremony:verifier:enroller:)`, `Enroller.enroll(home:keys:profile:)`/`positiveControl(home:profile:)`/`isEnrolled(home:)`/`removeKeyMaterial(home:)`, `TouchIdVerifier(allowedSigners:)`, `boundedReason(_:displayName:maxLen:)`, `SecureEnclaveKey.{tag,create,load(ctx:),delete,exportRaw}`, `TouchIdCeremony()`, `TouchIdEnroller(priv:)`/`register(pubBase64:profile:)`, `touchIdProfile`/`makeTouchIdContext(home:)` — used consistently across tasks. `NoopEnroller` in Task 2 is flagged to track the Task 5 seam change.

**Note on strict-green execution:** Task 2's `NoopEnroller`/`AlwaysVerifier` fakes target the expanded `Enroller` (Task 5). If executing strictly in order, give them the pre-Task-5 members first and switch when Task 5 lands (called out in Task 2 Step 1 and Task 5 Step 6).
