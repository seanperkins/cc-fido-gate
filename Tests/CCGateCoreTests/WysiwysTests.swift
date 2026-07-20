import XCTest
@testable import CCGateCore

final class WysiwysTests: XCTestCase {
    private func doc(_ path: String, _ content: Data) -> SignedDocument {
        buildSignedDocument(op: "execute-write", path: path, contentSha256: sha256Hex(content),
                            cwd: "/tmp", nonceHex: "00", callerUid: 501)
    }
    func testHomoglyphPathsRenderDistinctly() {
        let a = humanRendering(doc("/Users/sean/.zshrc", Data("x".utf8)), content: Data("x".utf8))
        let b = humanRendering(doc("/Users/s\u{0435}an/.zshrc", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertNotEqual(a, b)
    }
    func testZeroWidthEscaped() {
        let r = humanRendering(doc("/tmp/a\u{200B}b", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertFalse(r.contains("\u{200B}")); XCTAssertTrue(r.contains("U+200B"))
    }
    func testEscapeIsInjective_literalAngleBracketDiffersFromRealZWS() {
        // real U+200B vs the literal characters "<U+200B>" must NOT render identically
        let real = humanRendering(doc("/tmp/a\u{200B}b", Data("x".utf8)), content: Data("x".utf8))
        let literal = humanRendering(doc("/tmp/a<U+200B>b", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertNotEqual(real, literal)
    }
    func testTrailingWhitespaceSurfaced() {
        XCTAssertNotEqual(humanRendering(doc("/tmp/x", Data("cmd".utf8)), content: Data("cmd".utf8)),
                          humanRendering(doc("/tmp/x", Data("cmd ".utf8)), content: Data("cmd ".utf8)))
    }
    // --- digest shown only where the content is NOT rendered verbatim ---
    func testVerbatimContentOmitsTheRedundantDigest() {
        let c = Data("hello".utf8)
        let r = humanRendering(doc("/tmp/x", c), content: c)
        XCTAssertTrue(r.contains("hello"), "content must be shown")
        XCTAssertTrue(r.contains("5 bytes"), "byte count is the part with human value — keep it")
        XCTAssertFalse(r.contains("sha256:"), "digest is redundant when the body IS the content")
    }
    func testVerbatimRenderingsStayInjectiveWithoutTheDigest() {
        // The property the digest used to backstop here. escapeConfusables removes newlines and
        // escapes '<', so the body can never forge the delimiters or the header/tail lines.
        var seen = Set<String>()
        let payloads = ["a", "b", "a ", " a", "a\nb", "a<U+000A>b", "---", "\n---\n",
                        "cwd: /tmp", "EXECUTE-WRITE /tmp/y", "5 bytes", "[binary, 1 bytes]"]
        for p in payloads {
            let c = Data(p.utf8)
            let r = humanRendering(doc("/tmp/x", c), content: c)
            XCTAssertTrue(seen.insert(r).inserted, "collision for payload \(p.debugDescription): \(r)")
        }
    }
    func testDistinctBinariesOfEqualSizeStillDisambiguated() {
        // Binary bodies are a length-only placeholder, so WITHOUT the digest these would be identical.
        let a = Data([0xff, 0xfe, 0x00, 0x01]), b = Data([0xff, 0xfe, 0x00, 0x02])
        XCTAssertNil(String(data: a, encoding: .utf8), "fixture must actually be non-UTF8")
        let ra = humanRendering(doc("/tmp/x", a), content: a)
        let rb = humanRendering(doc("/tmp/x", b), content: b)
        XCTAssertTrue(ra.contains("[binary, 4 bytes]"), "binary body is a placeholder")
        XCTAssertTrue(ra.contains("sha256:"), "placeholder body ⇒ digest is load-bearing")
        XCTAssertNotEqual(ra, rb, "same-size distinct binaries must not render identically")
    }
    func testTextMimickingTheBinaryPlaceholderCannotCollideWithRealBinary() {
        // Cross-branch check: verbatim text that reads exactly like the placeholder must not collide
        // with an actual binary of that size. The sha256 tail is what separates the branches.
        let spoof = Data("[binary, 4 bytes]".utf8)
        let real = Data([0xff, 0xfe, 0x00, 0x01])
        XCTAssertNotEqual(humanRendering(doc("/tmp/x", spoof), content: spoof),
                          humanRendering(doc("/tmp/x", real), content: real))
    }
    func testDigestModeFullHashNoContent() {
        let big = Data(repeating: 0x41, count: INLINE_MAX + 1)
        let r = humanRendering(doc("/tmp/big", big), content: big)
        XCTAssertTrue(r.contains(sha256Hex(big)))            // FULL 64-hex digest
        XCTAssertTrue(r.contains("\(big.count) bytes"))
        XCTAssertFalse(r.contains(String(repeating: "A", count: 50)))
    }
}
