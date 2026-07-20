import XCTest
@testable import CCGateCore

/// Pulls the PreToolUse hook command out of a rendered managed-settings JSON blob.
func hookCommand(inManaged json: String?) throws -> String? {
    guard let json, let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
          let pre = (obj["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]],
          let hooks = pre.first?["hooks"] as? [[String: Any]] else { return nil }
    return hooks.first?["command"] as? String
}

final class GateProfileTests: XCTestCase {
    func mk(_ tag: String) -> GateProfile {
        GateProfile(serviceAccount: "_svc\(tag)", accountRealName: "rn\(tag)", namespace: "ns\(tag)",
            keydir: "/var/k\(tag)", runDir: "/var/r\(tag)", sock: "/var/r\(tag)/g.sock",
            daemonLogErr: "/var/k\(tag)/e.err", codeDir: "/opt/c\(tag)", policy: "/opt/c\(tag)/p.json",
            binaryName: "bin\(tag)", displayName: "d\(tag)", launchdLabel: "lbl\(tag)",
            plist: "/L/lbl\(tag).plist", daemonMatchPattern: "bin\(tag) daemon",
            claudeCodeDir: "/CC", managedSettings: "/CC/m.json")
    }
    func testControlDenylistDerivesFromRoots() {
        let p = mk("A")
        XCTAssertEqual(p.controlDenylist, ["/var/kA/allowed_signers", "/var/kA/audit.log",
            "/var/kA/custody.json", "/var/kA/ceremony.lock", "/var/rA/g.sock", "/opt/cA/p.json"])
    }
    func testHookBinaryDefaultsToCodeDirBinaryName() {
        XCTAssertEqual(mk("A").hookBinary, "/opt/cA/binA")
    }
    func testHookBinaryOverrideIsUsed() {
        let p = GateProfile(serviceAccount: "_svc", accountRealName: "rn", namespace: "ns",
            keydir: "/var/k", runDir: "/var/r", sock: "/var/r/g.sock", daemonLogErr: "/var/k/e.err",
            codeDir: "/opt/c", policy: "/opt/c/p.json", binaryName: "bin", displayName: "d",
            launchdLabel: "lbl", plist: "/L/lbl.plist", daemonMatchPattern: "bin daemon",
            claudeCodeDir: "/CC", managedSettings: "/CC/m.json",
            hookBinary: "/opt/c/bin.app/Contents/MacOS/bin")
        XCTAssertEqual(p.hookBinary, "/opt/c/bin.app/Contents/MacOS/bin")
    }
    func testInstallOrchestrationWritesTheProfilesHookBinary() throws {
        // Regression: installOrchestration hardcoded codeDir/binaryName, so `install` on an .app-based
        // product wrote a managed hook pointing at a binary that can never sign.
        let p = GateProfile(serviceAccount: "_svc", accountRealName: "rn", namespace: "ns",
            keydir: "/var/k", runDir: "/var/r", sock: "/var/r/g.sock", daemonLogErr: "/var/k/e.err",
            codeDir: "/opt/c", policy: "/opt/c/p.json", binaryName: "bin", displayName: "d",
            launchdLabel: "lbl", plist: "/L/lbl.plist", daemonMatchPattern: "bin daemon",
            claudeCodeDir: "/CC", managedSettings: "/CC/m.json",
            hookBinary: "/opt/c/bin.app/Contents/MacOS/bin")
        let plat = MockPlatform()
        try installOrchestration(platform: plat, profile: p)
        // Parse rather than substring-match: the rendered JSON escapes "/" as "\/".
        XCTAssertEqual(try hookCommand(inManaged: plat.managedContents),
                       "/opt/c/bin.app/Contents/MacOS/bin hook")
    }
    func testTwoProfilesDoNotLeakAcrossEachOther() {
        let a = mk("A"), b = mk("B")
        XCTAssertNotEqual(a.serviceAccount, b.serviceAccount)
        XCTAssertTrue(Set(a.controlDenylist).isDisjoint(with: Set(b.controlDenylist)))
        XCTAssertNotEqual(a.daemonMatchPattern, b.daemonMatchPattern)
    }
}
