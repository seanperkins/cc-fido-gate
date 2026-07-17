import XCTest
import Foundation
@testable import CCFidoCore

final class CLIHelperTests: XCTestCase {
    func testRenderPlist() {
        let xml = renderPlist(binary: "/opt/cc-fido-gate/cc-fido")
        XCTAssertTrue(xml.contains("<string>_ccfido</string>"))
        XCTAssertTrue(xml.contains("/opt/cc-fido-gate/cc-fido"))
        XCTAssertTrue(xml.contains("<string>daemon</string>"))
        XCTAssertTrue(xml.contains("com.cc-fido-gate.brokerd"))
    }
    func testRenderManaged() throws {
        let s = try JSONSerialization.jsonObject(with: Data(renderManagedSettings(hookCmd: "/opt/cc-fido-gate/cc-fido hook").utf8)) as! [String: Any]
        XCTAssertEqual(s["allowManagedHooksOnly"] as? Bool, true)
    }
}
