import Foundation
import CCGateCore
public struct TouchIdEnroller: Enroller {
    let priv: ([String]) -> Bool
    public init(priv: @escaping ([String]) -> Bool = { runPrivileged($0) }) { self.priv = priv }

    /// Overwrite the single enrolled hex-X9.63 pubkey ($1 positional — never interpolated).
    @discardableResult
    public func register(pubHex: String, profile: GateProfile) -> Bool {
        priv(["/bin/sh", "-c", "printf '%s\\n' \"$1\" > \(profile.allowedSigners)", "sh", pubHex])
    }
    public func enroll(home: String, keys: Int, profile: GateProfile) throws {
        seDeleteKey(tag: touchIdKeyTag)                                   // idempotent re-enroll
        FileHandle.standardError.write(Data(">>> Creating the cc-touch-id Secure Enclave key <<<\n".utf8))
        _ = try seCreateKey(tag: touchIdKeyTag)                           // needs the entitled binary
        let pubHex = hexEncode(try seExportPublicKey(tag: touchIdKeyTag))
        guard register(pubHex: pubHex, profile: profile) else { throw EnrollError.failed("register pubkey") }
        guard priv(["/usr/sbin/chown", profile.serviceAccount, profile.allowedSigners]) else {
            throw EnrollError.failed("chown allowed_signers")
        }
        guard priv(["/bin/chmod", "600", profile.allowedSigners]) else {
            throw EnrollError.failed("chmod allowed_signers")
        }
    }
    public func positiveControl(home: String, profile: GateProfile) -> Bool {
        let nonce = randomBytes(32)
        FileHandle.standardError.write(Data(">>> TOUCH to confirm enrollment <<<\n".utf8))
        guard let sig = try? seSign(message: nonce, tag: touchIdKeyTag, reason: "confirm cc-touch-id enrollment") else { return false }
        return TouchIdVerifier(allowedSigners: profile.allowedSigners).verify(challenge: nonce, signature: sig)
    }
    public func isEnrolled(home: String) -> Bool { seKeyExists(tag: touchIdKeyTag) }
    public func removeKeyMaterial(home: String) { _ = seDeleteKey(tag: touchIdKeyTag) }
}
