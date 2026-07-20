import XCTest
import Foundation
@testable import CCGateCore

// Shared across CCGateCoreTests (internal, not private) — e.g. BrokerAllowlistTests also needs a Broker.
struct StubVerifier: Verifier {
    func verify(challenge: Data, signature: Data) -> Bool { false }
}

final class BrokerLogicTests: XCTestCase {
    // --- M1: a durable write must never be reported as a failure ---
    enum FakeAuditError: Error { case disk }
    func testWriteResultIsOkWhenAuditSucceeded() {
        let r = Broker.writeResult(auditError: nil)
        XCTAssertEqual(r["status"] as? String, "ok")
        XCTAssertNil(r["audit_error"], "no audit failure ⇒ no audit_error key")
    }
    func testWriteResultStaysOkButFlagsAuditFailure() {
        // The write is already durable at this point: an audit-append failure must NOT downgrade the
        // status to deny (the client would think nothing happened) — but it must not be silent either.
        let r = Broker.writeResult(auditError: FakeAuditError.disk)
        XCTAssertEqual(r["status"] as? String, "ok", "durable write must still report ok")
        XCTAssertTrue((r["audit_error"] as? String)?.contains("audit append failed") == true,
                      "audit gap must be surfaced, got: \(String(describing: r["audit_error"]))")
    }

    func testDecideApproveCompilesAndBindsInput() throws {
        let b = Broker(profile: testProfile, verifier: StubVerifier())
        let d = try b.decideApprove(["op": "approve", "tool": "Bash",
                                     "input": ["command": "git push --force"], "cwd": "/tmp"], caller: 501)
        XCTAssertTrue(d.human.contains("git push --force"))
        XCTAssertFalse(d.challengeB64.isEmpty)
    }
    func testApproveChallengeIsDeterministicForSameInput() throws {
        // canonicalJSON sorts nested keys, so payload hash is stable regardless of dict order
        let a = try canonicalJSON(["tool": "Bash", "input": ["command": "x"], "cwd": "/"])
        let b = try canonicalJSON(["cwd": "/", "input": ["command": "x"], "tool": "Bash"])
        XCTAssertEqual(a, b)
    }
}
