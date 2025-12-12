//
//  AWSConfigService.swift
//  Security Groupie
//

import Foundation

struct AWSProfileCredentials {
    let accessKeyId: String
    let secretAccessKey: String
    let region: String?
}

@Observable
final class AWSConfigService {
    static let shared = AWSConfigService()

    private(set) var profiles: [String] = []
    private(set) var hasConfigFile: Bool = false

    private let credentialsPath: URL
    private let configPath: URL
    private var profileCredentials: [String: AWSProfileCredentials] = [:]
    private var profileRegions: [String: String] = [:]

    private init() {
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
        profileCredentials = [:]
        profileRegions = [:]

        // Parse credentials file for access keys
        if let parsed = parseCredentialsFile(credentialsPath) {
            for (profile, creds) in parsed {
                foundProfiles.insert(profile)
                profileCredentials[profile] = creds
            }
        }

        // Parse config file for regions and additional profiles
        if let parsed = parseConfigFile(configPath) {
            for (profile, region) in parsed {
                foundProfiles.insert(profile)
                profileRegions[profile] = region
            }
        }

        hasConfigFile = !foundProfiles.isEmpty
        profiles = foundProfiles.sorted()

        // Ensure "default" is first if present
        if let defaultIndex = profiles.firstIndex(of: "default"), defaultIndex != 0 {
            profiles.remove(at: defaultIndex)
            profiles.insert("default", at: 0)
        }
    }

    func credentials(for profile: String) -> AWSProfileCredentials? {
        guard let creds = profileCredentials[profile] else {
            return nil
        }
        // Merge region from config file if available
        let region = profileRegions[profile] ?? creds.region
        return AWSProfileCredentials(
            accessKeyId: creds.accessKeyId,
            secretAccessKey: creds.secretAccessKey,
            region: region
        )
    }

    func region(for profile: String) -> String? {
        profileRegions[profile]
    }

    private func parseCredentialsFile(_ url: URL) -> [String: AWSProfileCredentials]? {
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return nil
        }

        var result: [String: AWSProfileCredentials] = [:]
        var currentProfile: String?
        var currentAccessKey: String?
        var currentSecretKey: String?
        var currentRegion: String?

        let lines = contents.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                // Save previous profile
                if let profile = currentProfile,
                   let accessKey = currentAccessKey,
                   let secretKey = currentSecretKey {
                    result[profile] = AWSProfileCredentials(
                        accessKeyId: accessKey,
                        secretAccessKey: secretKey,
                        region: currentRegion
                    )
                }

                // Start new profile
                currentProfile = String(trimmed.dropFirst().dropLast())
                currentAccessKey = nil
                currentSecretKey = nil
                currentRegion = nil
            } else if let (key, value) = parseKeyValue(trimmed) {
                switch key.lowercased() {
                case "aws_access_key_id":
                    currentAccessKey = value
                case "aws_secret_access_key":
                    currentSecretKey = value
                case "region":
                    currentRegion = value
                default:
                    break
                }
            }
        }

        // Save last profile
        if let profile = currentProfile,
           let accessKey = currentAccessKey,
           let secretKey = currentSecretKey {
            result[profile] = AWSProfileCredentials(
                accessKeyId: accessKey,
                secretAccessKey: secretKey,
                region: currentRegion
            )
        }

        return result.isEmpty ? nil : result
    }

    private func parseConfigFile(_ url: URL) -> [String: String]? {
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return nil
        }

        var result: [String: String] = [:]
        var currentProfile: String?

        let lines = contents.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                var profileName = String(trimmed.dropFirst().dropLast())
                if profileName.hasPrefix("profile ") {
                    profileName = String(profileName.dropFirst("profile ".count))
                }
                currentProfile = profileName.trimmingCharacters(in: .whitespaces)
            } else if let (key, value) = parseKeyValue(trimmed),
                      key.lowercased() == "region",
                      let profile = currentProfile {
                result[profile] = value
            }
        }

        return result.isEmpty ? nil : result
    }

    private func parseKeyValue(_ line: String) -> (String, String)? {
        guard let equalsIndex = line.firstIndex(of: "=") else {
            return nil
        }
        let key = String(line[..<equalsIndex]).trimmingCharacters(in: .whitespaces)
        let value = String(line[line.index(after: equalsIndex)...]).trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty && !value.isEmpty else {
            return nil
        }
        return (key, value)
    }
}
