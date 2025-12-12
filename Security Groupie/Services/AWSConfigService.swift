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
        if let ini = INIParser(url: credentialsPath) {
            for section in ini.sectionNames {
                if let accessKey = ini.value(forKey: "aws_access_key_id", inSection: section),
                   let secretKey = ini.value(forKey: "aws_secret_access_key", inSection: section) {
                    foundProfiles.insert(section)
                    profileCredentials[section] = AWSProfileCredentials(
                        accessKeyId: accessKey,
                        secretAccessKey: secretKey,
                        region: ini.value(forKey: "region", inSection: section)
                    )
                }
            }
        }

        // Parse config file for regions and additional profiles
        if let ini = INIParser(url: configPath) {
            for section in ini.sectionNames {
                // AWS config uses "profile foo" for non-default profiles
                var profileName = section
                if profileName.hasPrefix("profile ") {
                    profileName = String(profileName.dropFirst("profile ".count))
                }

                if let region = ini.value(forKey: "region", inSection: section) {
                    foundProfiles.insert(profileName)
                    profileRegions[profileName] = region
                }
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
}
