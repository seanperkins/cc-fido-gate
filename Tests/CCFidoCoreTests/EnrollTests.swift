import XCTest
@testable import CCFidoCore

final class EnrollTests: XCTestCase {
    func testEnrollPlanGeneratesKeygenPerKey() {
        let plan = enrollPlan(home: "/Users/x", keys: 2)
        XCTAssertEqual(plan.count, 2)
        // each entry is a ssh-keygen -t ed25519-sk invocation writing gate_sk<N>
        XCTAssertTrue(plan[0].contains("ed25519-sk"))
        XCTAssertTrue(plan[0].contains("/Users/x/.ccfido/gate_sk1"))
        XCTAssertTrue(plan[1].contains("/Users/x/.ccfido/gate_sk2"))
    }
}
