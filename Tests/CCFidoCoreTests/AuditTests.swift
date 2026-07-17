import XCTest
@testable import CCFidoCore

final class AuditTests: XCTestCase {
    private func tmp() -> String { NSTemporaryDirectory() + "audit-\(UUID().uuidString).log" }
    func testChainVerifiesFromFirstLine() throws {
        let p = tmp(); try auditAppend(["event": "a"], path: p); try auditAppend(["event": "b"], path: p)
        XCTAssertTrue(auditVerifyChain(path: p))   // no unchained prefix — chained from line 0
    }
    func testTamperBreaksChain() throws {
        let p = tmp(); try auditAppend(["event": "a"], path: p); try auditAppend(["event": "b"], path: p)
        var lines = try String(contentsOfFile: p, encoding: .utf8).split(separator: "\n").map(String.init)
        lines[0] = lines[0].replacingOccurrences(of: "\"a\"", with: "\"HACKED\"")
        try (lines.joined(separator: "\n") + "\n").write(toFile: p, atomically: true, encoding: .utf8)
        XCTAssertFalse(auditVerifyChain(path: p))
    }
}
