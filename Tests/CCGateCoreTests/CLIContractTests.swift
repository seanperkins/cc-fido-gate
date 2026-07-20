import XCTest
import Foundation

/// CLI-level contract tests: spawn the BUILT binary and assert on (exit code, stdout, stderr).
///
/// These cover the security-critical **emit-on-valid-only** contract of `_render-policy`. `install.sh`
/// consumes it as:
///
///     "$BIN" _render-policy "$POLICY" "$LOGIN_HOME" | sudo tee "$CODE_DIR/policy.json" >/dev/null
///
/// `tee` truncates and writes the LIVE policy as bytes arrive, and it does so before `pipefail` can
/// abort the script — and there is no `test -s` belt on the rendered policy (the ones in install.sh
/// guard `allowed_signers`). So "non-zero exit ⇒ **nothing** on stdout" is the only thing standing
/// between a rejected policy and a corrupted live one. That contract lived only in USER-RUN scripts
/// until these tests; it is exactly the kind of thing a refactor can silently break, since emitting
/// a diagnostic on stdout instead of stderr would look harmless in review.
///
/// Both products are exercised: the logic is shared, so a divergence between them is a regression.
final class CLIContractTests: XCTestCase {

    // The test bundle sits in .build/<config>/; the product binaries are its siblings.
    private func binary(_ name: String) throws -> URL {
        let dir = Bundle(for: type(of: self)).bundleURL.deletingLastPathComponent()
        let url = dir.appendingPathComponent(name)
        guard FileManager.default.isExecutableFile(atPath: url.path) else {
            throw XCTSkip("\(name) not built at \(url.path) — run `swift build` first")
        }
        return url
    }

    private func run(_ product: String, _ args: [String]) throws -> (code: Int32, out: String, err: String) {
        let p = Process()
        p.executableURL = try binary(product)
        p.arguments = args
        let o = Pipe(), e = Pipe()
        p.standardOutput = o; p.standardError = e
        try p.run()
        // Drain BEFORE waitUntilExit: a child that fills the pipe buffer would otherwise deadlock.
        let od = o.fileHandleForReading.readDataToEndOfFile()
        let ed = e.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: od, as: UTF8.self), String(decoding: ed, as: UTF8.self))
    }

    private func writeFixture(_ json: String) throws -> String {
        let path = NSTemporaryDirectory() + "policy-\(UUID().uuidString).json"
        try json.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    /// A policy that passes parse + lint, with `allow_tier` overridable to force a fatal.
    private func policyJSON(allowTier: String = "\"__HOME__/**\"",
                            bashAdvisory: String = "\"rm -rf .*\"",
                            includeMcpAllow: Bool = true) -> String {
        let mcp = includeMcpAllow ? #""mcp_allow": [["gh", "list_prs"]]"# : #""unused": []"#
        return """
        {
          "sensitive_globs": ["**/.env*", "**/.ssh/*", "**/*.pem"],
          "allow_tier": [\(allowTier)],
          "locked_paths": [],
          "bash_advisory": [\(bashAdvisory)],
          \(mcp)
        }
        """
    }

    private let products = ["cc-fido", "cc-touch-id"]

    // MARK: - the valid path must actually emit

    func testRenderPolicyValidEmitsSubstitutedJSONAndExitsZero() throws {
        let src = try writeFixture(policyJSON())
        for product in products {
            let r = try run(product, ["_render-policy", src, NSHomeDirectory()])
            XCTAssertEqual(r.code, 0, "\(product): valid policy must exit 0 (stderr: \(r.err))")
            XCTAssertFalse(r.out.isEmpty, "\(product): valid policy must emit the rendered JSON")
            let obj = try JSONSerialization.jsonObject(with: Data(r.out.utf8)) as? [String: Any]
            let allow = try XCTUnwrap(obj?["allow_tier"] as? [String], "\(product): allow_tier missing")
            XCTAssertEqual(allow, [NSHomeDirectory() + "/**"], "\(product): __HOME__ must be substituted")
            XCTAssertFalse(r.out.contains("__HOME__"), "\(product): no placeholder may survive")
        }
    }

    // MARK: - every rejection path must leave stdout EMPTY

    /// The core invariant. Each case is a distinct rejection reason, because they exit through
    /// different branches (lint fatal / parse throw / render throw) and only one of them was ever
    /// smoke-tested by hand.
    func testEveryRejectionPathExitsNonZeroWithEmptyStdout() throws {
        let validHome = NSHomeDirectory()
        let cases: [(name: String, src: String, home: String)] = [
            ("blanket allow_tier (lint fatal)", try writeFixture(policyJSON(allowTier: "\"**\"")), validHome),
            ("rooted blanket grant",            try writeFixture(policyJSON(allowTier: "\"/**\"")), validHome),
            ("invalid bash_advisory regex",     try writeFixture(policyJSON(bashAdvisory: "\"(\"")), validHome),
            ("missing required key",            try writeFixture(policyJSON(includeMcpAllow: false)), validHome),
            ("malformed JSON",                  try writeFixture("{ not json"), validHome),
            ("top-level not an object",         try writeFixture("[1,2,3]"), validHome),
            ("nonexistent source",              "/no/such/policy-\(UUID().uuidString).json", validHome),
            ("banned home: root",               try writeFixture(policyJSON()), "/var/root"),
            ("banned home: /",                  try writeFixture(policyJSON()), "/"),
            ("banned home: empty",              try writeFixture(policyJSON()), ""),
            ("relative home",                   try writeFixture(policyJSON()), "relative/path"),
        ]
        for product in products {
            for c in cases {
                let r = try run(product, ["_render-policy", c.src, c.home])
                XCTAssertNotEqual(r.code, 0, "\(product)/\(c.name): must NOT exit 0")
                XCTAssertEqual(r.out, "",
                    "\(product)/\(c.name): stdout MUST be empty on rejection — install.sh pipes it "
                    + "straight into the live policy.json via tee. Got: \(r.out.prefix(200))")
                XCTAssertFalse(r.err.isEmpty, "\(product)/\(c.name): the reason must go to stderr")
            }
        }
    }

    /// Diagnostics must be on stderr, never stdout — the failure mode that would silently corrupt
    /// the policy is a warning printed to the wrong stream.
    func testWarningsGoToStderrNotStdout() throws {
        // A nonexistent allow_tier prefix warns (not fatal) — the rendered JSON must still be the
        // ONLY thing on stdout.
        let src = try writeFixture(policyJSON(allowTier: "\"/no-such-dir-zzz/**\""))
        for product in products {
            let r = try run(product, ["_render-policy", src, NSHomeDirectory()])
            XCTAssertEqual(r.code, 0, "\(product): a warning must not be fatal (stderr: \(r.err))")
            XCTAssertTrue(r.err.contains("WARNING"), "\(product): expected a lint warning on stderr")
            XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(r.out.utf8)),
                             "\(product): stdout must be pure JSON, no diagnostics mixed in")
        }
    }

    /// End-to-end reproduction of install.sh's pipeline: on rejection the destination must be left
    /// empty, proving nothing partial reaches a `tee`.
    func testRejectionWritesNothingThroughAPipeline() throws {
        let src = try writeFixture(policyJSON(allowTier: "\"**\""))
        let dest = NSTemporaryDirectory() + "piped-\(UUID().uuidString).json"
        let bin = try binary("cc-touch-id").path
        let sh = Process()
        sh.executableURL = URL(fileURLWithPath: "/bin/bash")
        sh.arguments = ["-c", "set -o pipefail; '\(bin)' _render-policy '\(src)' '\(NSHomeDirectory())' | tee '\(dest)' >/dev/null"]
        sh.standardError = FileHandle.nullDevice
        try sh.run(); sh.waitUntilExit()
        XCTAssertNotEqual(sh.terminationStatus, 0, "pipefail must surface the rejection")
        let written = (try? String(contentsOfFile: dest, encoding: .utf8)) ?? ""
        XCTAssertEqual(written, "", "a rejected policy must leave the tee'd destination empty")
    }

    // MARK: - _validate-policy

    func testValidatePolicyAcceptsValidAndRejectsBlanket() throws {
        // _validate-policy reads an ALREADY-rendered policy, so use a concrete path (no __HOME__).
        let good = try writeFixture(policyJSON(allowTier: "\"\(NSHomeDirectory())/**\""))
        let bad = try writeFixture(policyJSON(allowTier: "\"**\""))
        for product in products {
            let ok = try run(product, ["_validate-policy", good])
            XCTAssertEqual(ok.code, 0, "\(product): valid policy must validate (stderr: \(ok.err))")
            XCTAssertTrue(ok.out.contains("policy OK"), "\(product): expected a summary, got: \(ok.out)")

            let no = try run(product, ["_validate-policy", bad])
            XCTAssertNotEqual(no.code, 0, "\(product): blanket grant must be rejected")
            XCTAssertTrue(no.err.contains("FATAL"), "\(product): expected FATAL on stderr")
        }
    }

    func testWrongArityIsRejectedNotMisinterpreted() throws {
        for product in products {
            // _render-policy needs exactly <src> <home>; a missing arg must not fall through to a
            // partial render against a defaulted home.
            for args in [["_render-policy"], ["_render-policy", "/tmp/only-one"]] {
                let r = try run(product, args)
                XCTAssertNotEqual(r.code, 0, "\(product): \(args) must be rejected")
                XCTAssertEqual(r.out, "", "\(product): \(args) must emit nothing on stdout")
            }
        }
    }
}
