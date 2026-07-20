import XCTest
import Foundation
@testable import CCGateCore

final class CustodyTests: XCTestCase {
    func testPlanEnrollFile() {
        XCTAssertEqual(planEnrollFile("/tmp/x/.env", mode: 0o600, profile: testProfile), [
            ["/usr/sbin/chown", "_ccfido", "/tmp/x/.env"],
            ["/bin/chmod", "600", "/tmp/x/.env"],
            ["/usr/bin/chflags", "uchg", "/tmp/x/.env"]])
    }
    func testPlanEnrollDir() {
        XCTAssertEqual(planEnrollDir("/tmp/LA", profile: testProfile), [
            ["/usr/sbin/chown", "_ccfido", "/tmp/LA"], ["/bin/chmod", "755", "/tmp/LA"]])
    }
    func testWritableAncestorDetected() throws {
        let base = NSTemporaryDirectory() + "cust-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: base + "/sub", withIntermediateDirectories: true)
        let target = base + "/sub/secret"; FileManager.default.createFile(atPath: target, contents: Data("x".utf8))
        XCTAssertTrue(checkAncestors(target, safeOwners: [0]).contains(base))
    }
    func testRegistryRoundTrip() throws {
        let p = NSTemporaryDirectory() + "custody-\(UUID().uuidString).json"
        try CustodyRegistry.add(file: "/a/b", dir: nil, path: p)
        try CustodyRegistry.add(file: nil, dir: "/c", path: p)
        let (files, dirs) = CustodyRegistry.load(path: p)
        XCTAssertEqual(files, ["/a/b"]); XCTAssertEqual(dirs, ["/c"])
    }
    func testRegistryDedupsAcrossFirmlinkAndRepeat() throws {
        let p = NSTemporaryDirectory() + "custody-\(UUID().uuidString).json"
        try CustodyRegistry.add(file: "/var/foo", dir: nil, path: p)
        try CustodyRegistry.add(file: "/private/var/foo", dir: nil, path: p)  // firmlink form of the same file
        try CustodyRegistry.add(file: "/var/foo", dir: nil, path: p)          // exact repeat
        XCTAssertEqual(CustodyRegistry.load(path: p).files, ["/var/foo"])     // one entry, normalized
    }
    func testRegistryConcurrentAddsPreservesAllEntries() throws {
        // Verifies the flock-serialized RMW: concurrent adds must not race and drop entries.
        let path = NSTemporaryDirectory() + "custody-concurrent-\(UUID().uuidString).json"
        let count = 20
        let group = DispatchGroup()
        for i in 0..<count {
            group.enter()
            DispatchQueue.global().async {
                try? CustodyRegistry.add(file: "/tmp/concurrent-file-\(i)", dir: nil, path: path)
                group.leave()
            }
        }
        group.wait()
        let (files, _) = CustodyRegistry.load(path: path)
        XCTAssertEqual(files.count, count, "expected \(count) entries but got \(files.count): \(files)")
    }
}
