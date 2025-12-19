//
//  AppSettings.swift
//  Security Groupie
//

import Foundation
import SwiftUI

enum AWSAuthMethod: String, Codable, CaseIterable {
    case profile = "profile"
    case accessKey = "accessKey"

    var displayName: String {
        switch self {
        case .profile: return "AWS Profile"
        case .accessKey: return "Access Key"
        }
    }
}

@Observable
final class AppSettings {
    static let shared = AppSettings()

    private let defaults = UserDefaults.standard

    // Keys
    private enum Keys {
        static let securityGroupId = "securityGroupId"
        static let awsRegion = "awsRegion"
        static let authMethod = "authMethod"
        static let awsProfile = "awsProfile"
        static let awsAccessKeyId = "awsAccessKeyId"
        static let awsSecretAccessKey = "awsSecretAccessKey"
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

    var awsProfile: String {
        didSet { defaults.set(awsProfile, forKey: Keys.awsProfile) }
    }

    var awsAccessKeyId: String {
        didSet { defaults.set(awsAccessKeyId, forKey: Keys.awsAccessKeyId) }
    }

    var awsSecretAccessKey: String {
        didSet { defaults.set(awsSecretAccessKey, forKey: Keys.awsSecretAccessKey) }
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

    var hasValidAuth: Bool {
        switch authMethod {
        case .profile:
            return !awsProfile.isEmpty
        case .accessKey:
            return !awsAccessKeyId.isEmpty && !awsSecretAccessKey.isEmpty
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

    private init() {
        self.securityGroupId = defaults.string(forKey: Keys.securityGroupId) ?? ""
        self.awsRegion = defaults.string(forKey: Keys.awsRegion) ?? "us-east-1"
        self.authMethod = AWSAuthMethod(rawValue: defaults.string(forKey: Keys.authMethod) ?? "") ?? .profile
        self.awsProfile = defaults.string(forKey: Keys.awsProfile) ?? "default"
        self.awsAccessKeyId = defaults.string(forKey: Keys.awsAccessKeyId) ?? ""
        self.awsSecretAccessKey = defaults.string(forKey: Keys.awsSecretAccessKey) ?? ""
        self.deviceNickname = defaults.string(forKey: Keys.deviceNickname) ?? Self.defaultDeviceName()
        self.port = defaults.integer(forKey: Keys.port) == 0 ? 22 : defaults.integer(forKey: Keys.port)
        self.lastKnownIP = defaults.string(forKey: Keys.lastKnownIP)
    }

    private static func defaultDeviceName() -> String {
        let rawName = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        let sanitized = sanitizeDeviceName(rawName)
        // If sanitization removed everything, use a fallback
        return sanitized.isEmpty ? "My Device" : sanitized
    }
}
