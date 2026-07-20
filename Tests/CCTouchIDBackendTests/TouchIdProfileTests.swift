import XCTest
@testable import CCTouchIDBackend
@testable import CCGateCore

/// Minimal Platform double — CCTouchIDBackendTests can't see CCGateCoreTests' MockPlatform.
final class MockTouchIdPlatform: Platform {
    var managed: String?
    func createServiceAccount(name: String) throws {}
    func deleteServiceAccount(name: String) throws {}
    func serviceAccountExists(name: String) -> Bool { true }
    func installDaemonPlist(_ xml: String) throws {}
    func activateDaemon() throws {}
    func bootoutDaemon() throws {}
    func daemonState() -> (loaded: Bool, running: Bool, pid: Int?) { (false, false, nil) }
    func writeManagedSettings(_ json: String) throws { managed = json }
    func removeManagedSettings() throws {}
    func makeImmutable(_ path: String) throws {}
    func clearImmutable(_ path: String) throws {}
}

final class TouchIdProfileTests: XCTestCase {
    func testProfileIdentity() {
        let p = touchIdProfile
        XCTAssertEqual(p.serviceAccount, "_cctouchid")
        XCTAssertEqual(p.binaryName, "cc-touch-id")
        XCTAssertEqual(p.namespace, "cc-touch-id-gate/v1")
        XCTAssertEqual(p.sock, "/var/cctouchid-run/gate.sock")
        XCTAssertEqual(p.allowedSigners, "/var/cctouchid/allowed_signers")
        XCTAssertEqual(p.launchdLabel, "com.cc-touch-id-gate.brokerd")
    }
    func testHookBinaryIsTheEntitledApp() {
        // The hook SIGNS with the Secure Enclave key, so it must run from the provisioned .app —
        // the plain daemon binary is amfid-killed on SE access. Regression guard for the install
        // path that used to write codeDir/binaryName into managed-settings.
        XCTAssertEqual(touchIdProfile.hookBinary, touchIdAppBinary)
        XCTAssertNotEqual(touchIdProfile.hookBinary,
                          touchIdProfile.codeDir + "/" + touchIdProfile.binaryName)
    }
    func testInstallWritesTheAppHookNotThePlainBinary() throws {
        let plat = MockTouchIdPlatform()
        try installOrchestration(platform: plat, profile: touchIdProfile)
        // Parse rather than substring-match: the rendered JSON escapes "/" as "\/".
        let json = try XCTUnwrap(plat.managed)
        let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        let pre = try XCTUnwrap((obj?["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]])
        let hooks = try XCTUnwrap(pre.first?["hooks"] as? [[String: Any]])
        XCTAssertEqual(hooks.first?["command"] as? String, touchIdAppBinary + " hook")
    }
    func testContextComposesTouchIdSeams() {
        let ctx = makeTouchIdContext(home: "/tmp/h")
        XCTAssertTrue(ctx.ceremony is TouchIdCeremony)
        XCTAssertTrue(ctx.verifier is TouchIdVerifier)
        XCTAssertTrue(ctx.enroller is TouchIdEnroller)
    }
}
