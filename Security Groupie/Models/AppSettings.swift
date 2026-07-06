//
//  AppSettings.swift
//  Security Groupie
//

import Foundation
import SwiftUI

enum AWSAuthMethod: String, Codable, CaseIterable {
    case sso = "sso"
    case accessKey = "accessKey"

    var displayName: String {
        switch self {
        case .sso: return "IAM Identity Center"
        case .accessKey: return "Access Key"
        }
    }
}

@Observable
final class AppSettings {
    static let shared = AppSettings()

    private let defaults: UserDefaults

    // Keys
    private enum Keys {
        static let securityGroupId = "securityGroupId"
        static let awsRegion = "awsRegion"
        static let authMethod = "authMethod"
        static let awsAccessKeyId = "awsAccessKeyId"
        static let ssoStartURL = "ssoStartURL"
        static let ssoRegion = "ssoRegion"
        static let ssoAccountId = "ssoAccountId"
        static let ssoRoleName = "ssoRoleName"
        static let deviceNickname = "deviceNickname"
        static let port = "port"
        static let lastKnownIP = "lastKnownIP"
    }

    var securityGroupId: String {
        didSet { defaults.set(securityGroupId, forKey: Keys.securityGroupId) }
    }

    var awsRegion: String {
        didSet { defaults.set(awsRegion, forKey: Keys.awsRegion) }
    }

    var authMethod: AWSAuthMethod {
        didSet { defaults.set(authMethod.rawValue, forKey: Keys.authMethod) }
    }

    var awsAccessKeyId: String {
        didSet { defaults.set(awsAccessKeyId, forKey: Keys.awsAccessKeyId) }
    }

    var ssoStartURL: String {
        didSet { defaults.set(ssoStartURL, forKey: Keys.ssoStartURL) }
    }

    var ssoRegion: String {
        didSet { defaults.set(ssoRegion, forKey: Keys.ssoRegion) }
    }

    var ssoAccountId: String {
        didSet { defaults.set(ssoAccountId, forKey: Keys.ssoAccountId) }
    }

    var ssoRoleName: String {
        didSet { defaults.set(ssoRoleName, forKey: Keys.ssoRoleName) }
    }

    var deviceNickname: String {
        didSet { defaults.set(deviceNickname, forKey: Keys.deviceNickname) }
    }

    var port: Int {
        didSet { defaults.set(port, forKey: Keys.port) }
    }

    var lastKnownIP: String? {
        didSet { defaults.set(lastKnownIP, forKey: Keys.lastKnownIP) }
    }

    var isConfigured: Bool {
        !securityGroupId.isEmpty && hasValidAuth && isValidDeviceName(deviceNickname)
    }

    // A static configuration check only — an expired SSO session still passes here
    // and surfaces as AuthError at call time
    var hasValidAuth: Bool {
        switch authMethod {
        case .sso:
            return !ssoStartURL.isEmpty && !ssoRegion.isEmpty
                && !ssoAccountId.isEmpty && !ssoRoleName.isEmpty
        case .accessKey:
            return !awsAccessKeyId.isEmpty && AuthService.shared.hasAccessKeySecret
        }
    }

    // MARK: - Device Name Validation

    /// AWS security group description rules:
    /// - Up to 255 characters
    /// - Allowed: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$*
    private static let allowedCharacterSet: CharacterSet = {
        var set = CharacterSet()
        set.insert(charactersIn: "abcdefghijklmnopqrstuvwxyz")
        set.insert(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        set.insert(charactersIn: "0123456789")
        set.insert(charactersIn: " ._-:/()#,@[]+=;{}!$*")
        return set
    }()

    static let maxDeviceNameLength = 255

    /// Validates a device name against AWS rules
    func isValidDeviceName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        guard name.count <= Self.maxDeviceNameLength else { return false }
        return name.unicodeScalars.allSatisfy { Self.allowedCharacterSet.contains($0) }
    }

    /// Returns validation error message, or nil if valid
    func deviceNameValidationError(_ name: String) -> String? {
        if name.isEmpty {
            return "Device name is required"
        }
        if name.count > Self.maxDeviceNameLength {
            return "Device name must be 255 characters or less"
        }
        let invalidChars = name.unicodeScalars.filter { !Self.allowedCharacterSet.contains($0) }
        if !invalidChars.isEmpty {
            let invalidString = String(String.UnicodeScalarView(invalidChars.prefix(5)))
            return "Invalid characters: \(invalidString)"
        }
        return nil
    }

    /// Sanitizes a string to only contain valid AWS description characters
    static func sanitizeDeviceName(_ name: String) -> String {
        let sanitized = String(name.unicodeScalars.filter { allowedCharacterSet.contains($0) })
        return String(sanitized.prefix(maxDeviceNameLength))
    }

    private convenience init() {
        self.init(defaults: .standard)
    }

    init(defaults: UserDefaults) {
        self.defaults = defaults
        self.securityGroupId = defaults.string(forKey: Keys.securityGroupId) ?? ""
        self.awsRegion = defaults.string(forKey: Keys.awsRegion) ?? "us-east-1"
        self.authMethod = Self.migratedAuthMethod(from: defaults)
        self.awsAccessKeyId = defaults.string(forKey: Keys.awsAccessKeyId) ?? ""
        self.ssoStartURL = defaults.string(forKey: Keys.ssoStartURL) ?? ""
        self.ssoRegion = defaults.string(forKey: Keys.ssoRegion) ?? "us-east-1"
        self.ssoAccountId = defaults.string(forKey: Keys.ssoAccountId) ?? ""
        self.ssoRoleName = defaults.string(forKey: Keys.ssoRoleName) ?? ""
        self.deviceNickname = defaults.string(forKey: Keys.deviceNickname) ?? Self.defaultDeviceName()
        self.port = defaults.integer(forKey: Keys.port) == 0 ? 22 : defaults.integer(forKey: Keys.port)
        self.lastKnownIP = defaults.string(forKey: Keys.lastKnownIP)

        defaults.removeObject(forKey: "awsProfile")
    }

    // The removed .profile method read ~/.aws/credentials; users who had it selected
    // fall back to access keys when they have any, otherwise SSO onboarding
    private static func migratedAuthMethod(from defaults: UserDefaults) -> AWSAuthMethod {
        let stored = defaults.string(forKey: Keys.authMethod) ?? ""
        if stored == "profile" {
            let hasKeys = !(defaults.string(forKey: Keys.awsAccessKeyId) ?? "").isEmpty
            let migrated: AWSAuthMethod = hasKeys ? .accessKey : .sso
            defaults.set(migrated.rawValue, forKey: Keys.authMethod)
            return migrated
        }
        return AWSAuthMethod(rawValue: stored) ?? .sso
    }

    private static func defaultDeviceName() -> String {
        let rawName = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        let sanitized = sanitizeDeviceName(rawName)
        // If sanitization removed everything, use a fallback
        return sanitized.isEmpty ? "My Device" : sanitized
    }
}
