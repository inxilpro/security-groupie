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
        !securityGroupId.isEmpty && hasValidAuth
    }

    var hasValidAuth: Bool {
        switch authMethod {
        case .profile:
            return !awsProfile.isEmpty
        case .accessKey:
            return !awsAccessKeyId.isEmpty && !awsSecretAccessKey.isEmpty
        }
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
        Host.current().localizedName ?? ProcessInfo.processInfo.hostName
    }
}
