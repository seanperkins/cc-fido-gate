import Foundation
/// All per-product filesystem topology + identity. Replaces the old `Paths` constant bag.
/// Crypto-primitive details (keygen paths, key handle, ssh signing principal) do NOT live here —
/// they are backend constructor args.
public struct GateProfile {
    public let serviceAccount: String      // e.g. "_ccfido"
    public let accountRealName: String     // e.g. "cc-fido broker"
    public let namespace: String           // signing-domain separator, e.g. "cc-fido-gate@example.test"
    public let keydir: String              // e.g. "/var/ccfido"
    public let runDir: String              // e.g. "/var/ccfido-run"
    public let sock: String                // e.g. "/var/ccfido-run/gate.sock"
    public let daemonLogErr: String        // e.g. "/var/ccfido/brokerd.err"
    public let codeDir: String             // e.g. "/opt/cc-fido-gate"
    public let policy: String              // e.g. "/opt/cc-fido-gate/policy.json"
    public let binaryName: String          // e.g. "cc-fido"
    public let displayName: String         // dialog title, e.g. "cc-fido-gate"
    public let launchdLabel: String        // e.g. "com.cc-fido-gate.brokerd"
    public let plist: String               // e.g. "/Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist"
    public let daemonMatchPattern: String  // pkill -f arg, e.g. "cc-fido daemon"
    public let claudeCodeDir: String       // "/Library/Application Support/ClaudeCode"
    public let managedSettings: String     // claudeCodeDir + "/managed-settings.json"

    public init(serviceAccount: String, accountRealName: String, namespace: String,
                keydir: String, runDir: String, sock: String, daemonLogErr: String,
                codeDir: String, policy: String, binaryName: String, displayName: String,
                launchdLabel: String, plist: String, daemonMatchPattern: String,
                claudeCodeDir: String, managedSettings: String) {
        self.serviceAccount = serviceAccount; self.accountRealName = accountRealName
        self.namespace = namespace; self.keydir = keydir; self.runDir = runDir; self.sock = sock
        self.daemonLogErr = daemonLogErr; self.codeDir = codeDir; self.policy = policy
        self.binaryName = binaryName; self.displayName = displayName; self.launchdLabel = launchdLabel
        self.plist = plist; self.daemonMatchPattern = daemonMatchPattern
        self.claudeCodeDir = claudeCodeDir; self.managedSettings = managedSettings
    }

    // Control files are DERIVED from roots so the deny logic lives in one place.
    public var allowedSigners: String { keydir + "/allowed_signers" }
    public var audit: String { keydir + "/audit.log" }
    public var custody: String { keydir + "/custody.json" }
    public var ceremonyLock: String { keydir + "/ceremony.lock" }
    /// Same six entries as today's Paths.controlDenylist, derived.
    public var controlDenylist: [String] { [allowedSigners, audit, custody, ceremonyLock, sock, policy] }
}
