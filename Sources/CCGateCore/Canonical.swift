import Foundation

public enum CanonicalError: Error { case notEncodable }

public struct SignedDocument: Codable, Equatable {
    public let v: Int
    public let op: String
    public let path: String
    public let contentSha256: String
    public let cwd: String
    public let nonce: String
    public let callerUid: Int
    public let contentMode: String
    public let ns: String?
    enum CodingKeys: String, CodingKey {
        case v, op, path, cwd, nonce, ns
        case contentSha256 = "content_sha256"
        case callerUid = "caller_uid"
        case contentMode = "content_mode"
    }
}
public func buildSignedDocument(op: String, path: String, contentSha256: String, cwd: String,
                                nonceHex: String, callerUid: Int,
                                contentMode: String = "inline", ns: String? = nil) -> SignedDocument {
    SignedDocument(v: 1, op: op, path: path, contentSha256: contentSha256, cwd: cwd,
                   nonce: nonceHex, callerUid: callerUid, contentMode: contentMode, ns: ns)
}
public func canonicalBytes<T: Encodable>(_ obj: T) throws -> Data {
    let enc = JSONEncoder()
    enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try enc.encode(obj)
}
/// Canonical bytes for an arbitrary already-parsed JSON object (the `approve` payload).
/// .sortedKeys sorts nested keys too; compact by default.
public func canonicalJSON(_ obj: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(obj) else { throw CanonicalError.notEncodable }
    return try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes])
}

public let INLINE_MAX = 4096

func escapeConfusables(_ s: String) -> String {
    var out = ""
    for scalar in s.unicodeScalars {
        let v = scalar.value
        let cat = scalar.properties.generalCategory
        let dangerous = v < 0x20 || v == 0x7f || v > 0x7e
            || cat == .format || cat == .lineSeparator || cat == .paragraphSeparator
            || (0x200b...0x200f).contains(v) || (0x202a...0x202e).contains(v)
        // Escape '<' too so the escape token "<U+XXXX>" cannot collide with literal input. (injectivity)
        if dangerous || v == 0x3c { out += String(format: "<U+%04X>", v) }
        else { out += String(scalar) }
    }
    return out
}
/// WYSIWYS rendering. MUST be injective in (op, path, cwd, content): if two different execution
/// inputs could render identically, an attacker could show a benign dialog while signing a malicious
/// payload. Display-only — the signature covers `canonicalBytes(doc)`, never this string.
///
/// The digest appears ONLY when the content is not shown verbatim. `escapeConfusables` strips every
/// scalar below 0x20 (newlines included), everything above 0x7e, and `<` itself, so escaped path,
/// cwd and body are each a single line of printable ASCII and the `\n---\n` delimiters cannot occur
/// inside a field. That makes the line structure unambiguous, so when the body IS the content the
/// rendering is already injective and a digest would add nothing a reader can use. When the body is
/// a PLACEHOLDER — digest mode, or binary content whose stand-in carries only a length — the content
/// is absent from the rendering entirely, and the digest is the only thing keeping two distinct
/// payloads of equal size from rendering identically. There it is load-bearing.
///
/// The branches stay mutually distinguishable: only the placeholder forms carry a `sha256:` tail, so
/// content that literally reads "[binary, 5 bytes]" cannot collide with a real 5-byte binary.
public func humanRendering(_ doc: SignedDocument, content: Data) -> String {
    let header = "\(doc.op.uppercased()) \(escapeConfusables(doc.path))\ncwd: \(escapeConfusables(doc.cwd))"
    let size = "\n\(content.count) bytes"
    let digest = "  sha256:\(doc.contentSha256)"        // FULL digest, never truncated
    if content.count > INLINE_MAX {                      // placeholder: content withheld for size
        return "\(header)\n[digest mode — content not shown]\(size)\(digest)"
    }
    guard let text = String(data: content, encoding: .utf8) else {   // placeholder: not renderable
        return "\(header)\n---\n[binary, \(content.count) bytes]\n---\(size)\(digest)"
    }
    return "\(header)\n---\n\(escapeConfusables(text))\n---\(size)"   // body IS the content
}
