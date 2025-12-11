//
//  AWSConfigService.swift
//  Security Groupie
//

import Foundation

@Observable
final class AWSConfigService {
    static let shared = AWSConfigService()

    private(set) var profiles: [String] = []
    private(set) var hasConfigFile: Bool = false

    private let credentialsPath: URL
    private let configPath: URL

    private init() {
        // Use NSHomeDirectory() alternative that works in sandbox
        // The ~ path resolves to the real home directory with the temporary exception entitlement
        let homeDir = URL(fileURLWithPath: NSHomeDirectory())

        // In sandboxed apps, NSHomeDirectory() returns the container path
        // We need to use the real home directory path for the .aws folder
        let realHomeDir: URL
        if let pw = getpwuid(getuid()), let home = pw.pointee.pw_dir {
            realHomeDir = URL(fileURLWithPath: String(cString: home))
        } else {
            realHomeDir = homeDir
        }

        self.credentialsPath = realHomeDir.appendingPathComponent(".aws/credentials")
        self.configPath = realHomeDir.appendingPathComponent(".aws/config")
        reload()
    }

    func reload() {
        var foundProfiles = Set<String>()

        // Check credentials file
        if let credentialsProfiles = parseProfilesFromFile(credentialsPath) {
            foundProfiles.formUnion(credentialsProfiles)
        }

        // Check config file (profiles are prefixed with "profile " except default)
        if let configProfiles = parseProfilesFromFile(configPath, stripProfilePrefix: true) {
            foundProfiles.formUnion(configProfiles)
        }

        hasConfigFile = !foundProfiles.isEmpty
        profiles = foundProfiles.sorted()

        // Ensure "default" is first if present
        if let defaultIndex = profiles.firstIndex(of: "default"), defaultIndex != 0 {
            profiles.remove(at: defaultIndex)
            profiles.insert("default", at: 0)
        }
    }

    private func parseProfilesFromFile(_ url: URL, stripProfilePrefix: Bool = false) -> Set<String>? {
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return nil
        }

        var profiles = Set<String>()
        let lines = contents.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Match [profile_name] or [profile profile_name]
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                var profileName = String(trimmed.dropFirst().dropLast())

                if stripProfilePrefix && profileName.hasPrefix("profile ") {
                    profileName = String(profileName.dropFirst("profile ".count))
                }

                profileName = profileName.trimmingCharacters(in: .whitespaces)
                if !profileName.isEmpty {
                    profiles.insert(profileName)
                }
            }
        }

        return profiles.isEmpty ? nil : profiles
    }
}
