//
//  EC2Service.swift
//  Security Groupie
//

import Foundation
import AWSEC2
import SmithyIdentity

struct SecurityGroupInfo: Identifiable, Hashable {
    let id: String
    let name: String
    let description: String
    let vpcId: String?

    var displayName: String {
        if name.isEmpty {
            return id
        }
        return "\(name) (\(id))"
    }
}

struct AWSRegionInfo: Identifiable, Hashable {
    let id: String
    let name: String

    var displayName: String {
        "\(name) (\(id))"
    }

    // Common region display names
    static func displayName(for regionId: String) -> String {
        let names: [String: String] = [
            "us-east-1": "US East (N. Virginia)",
            "us-east-2": "US East (Ohio)",
            "us-west-1": "US West (N. California)",
            "us-west-2": "US West (Oregon)",
            "af-south-1": "Africa (Cape Town)",
            "ap-east-1": "Asia Pacific (Hong Kong)",
            "ap-south-1": "Asia Pacific (Mumbai)",
            "ap-south-2": "Asia Pacific (Hyderabad)",
            "ap-southeast-1": "Asia Pacific (Singapore)",
            "ap-southeast-2": "Asia Pacific (Sydney)",
            "ap-southeast-3": "Asia Pacific (Jakarta)",
            "ap-southeast-4": "Asia Pacific (Melbourne)",
            "ap-northeast-1": "Asia Pacific (Tokyo)",
            "ap-northeast-2": "Asia Pacific (Seoul)",
            "ap-northeast-3": "Asia Pacific (Osaka)",
            "ca-central-1": "Canada (Central)",
            "ca-west-1": "Canada West (Calgary)",
            "eu-central-1": "Europe (Frankfurt)",
            "eu-central-2": "Europe (Zurich)",
            "eu-west-1": "Europe (Ireland)",
            "eu-west-2": "Europe (London)",
            "eu-west-3": "Europe (Paris)",
            "eu-south-1": "Europe (Milan)",
            "eu-south-2": "Europe (Spain)",
            "eu-north-1": "Europe (Stockholm)",
            "il-central-1": "Israel (Tel Aviv)",
            "me-south-1": "Middle East (Bahrain)",
            "me-central-1": "Middle East (UAE)",
            "sa-east-1": "South America (São Paulo)",
        ]
        return names[regionId] ?? regionId
    }
}

actor EC2Service {
    static let shared = EC2Service()

    private init() {}

    func fetchRegions(credentials: AWSCredentials) async throws -> [AWSRegionInfo] {
        // Use us-east-1 as the bootstrap region to fetch the list of all regions
        let bootstrapCredentials = AWSCredentials(
            accessKeyId: credentials.accessKeyId,
            secretAccessKey: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken,
            region: "us-east-1"
        )
        let client = try await createEC2Client(credentials: bootstrapCredentials)

        let input = DescribeRegionsInput(
            allRegions: false // Only return regions enabled for this account
        )
        let output = try await client.describeRegions(input: input)

        guard let regions = output.regions else {
            return []
        }

        return regions.compactMap { region -> AWSRegionInfo? in
            guard let regionName = region.regionName else { return nil }
            return AWSRegionInfo(
                id: regionName,
                name: AWSRegionInfo.displayName(for: regionName)
            )
        }.sorted { $0.id < $1.id }
    }

    func fetchSecurityGroups(credentials: AWSCredentials) async throws -> [SecurityGroupInfo] {
        let client = try await createEC2Client(credentials: credentials)

        let input = DescribeSecurityGroupsInput()
        let output = try await client.describeSecurityGroups(input: input)

        guard let securityGroups = output.securityGroups else {
            return []
        }

        return securityGroups.compactMap { sg -> SecurityGroupInfo? in
            guard let groupId = sg.groupId else { return nil }
            return SecurityGroupInfo(
                id: groupId,
                name: sg.groupName ?? "",
                description: sg.description ?? "",
                vpcId: sg.vpcId
            )
        }.sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    func updateSecurityGroupRule(
        securityGroupId: String,
        region: String,
        ipAddress: String,
        port: Int,
        description: String,
        credentials: AWSCredentials
    ) async throws -> UpdateResult {
        let cidrIp = "\(ipAddress)/32"
        let client = try await createEC2Client(credentials: credentials)

        // First, try to find an existing rule with the same description
        let existingRule = try await findExistingRule(
            client: client,
            securityGroupId: securityGroupId,
            description: description
        )

        if let rule = existingRule {
            // Check if the IP already matches
            if rule.cidrIp == cidrIp {
                return .noChangeNeeded
            }

            // Update existing rule with new IP
            try await modifySecurityGroupRule(
                client: client,
                securityGroupId: securityGroupId,
                ruleId: rule.ruleId,
                cidrIp: cidrIp,
                port: port,
                description: description
            )
            return .updated
        } else {
            // Create new rule
            do {
                try await createSecurityGroupRule(
                    client: client,
                    securityGroupId: securityGroupId,
                    cidrIp: cidrIp,
                    port: port,
                    description: description
                )
                return .created
            } catch {
                // Check if this is a duplicate permission error
                let errorString = String(describing: error)
                if errorString.contains("InvalidPermission.Duplicate") {
                    return .alreadyExistsElsewhere
                }
                throw error
            }
        }
    }

    private func createEC2Client(credentials: AWSCredentials) async throws -> EC2Client {
        let identity = AWSCredentialIdentity(
            accessKey: credentials.accessKeyId,
            secret: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken
        )
        let resolver = try StaticAWSCredentialIdentityResolver(identity)
        let config = try await EC2Client.EC2ClientConfiguration(
            awsCredentialIdentityResolver: resolver,
            region: credentials.region
        )

        return EC2Client(config: config)
    }

    private struct ExistingRuleInfo {
        let ruleId: String
        let cidrIp: String?
    }

    private func findExistingRule(
        client: EC2Client,
        securityGroupId: String,
        description: String
    ) async throws -> ExistingRuleInfo? {
        let input = DescribeSecurityGroupRulesInput(
            filters: [
                EC2ClientTypes.Filter(name: "group-id", values: [securityGroupId])
            ]
        )

        let output = try await client.describeSecurityGroupRules(input: input)

        guard let rules = output.securityGroupRules else {
            return nil
        }

        // Find a rule matching our description
        for rule in rules {
            if rule.description == description, let ruleId = rule.securityGroupRuleId {
                return ExistingRuleInfo(ruleId: ruleId, cidrIp: rule.cidrIpv4)
            }
        }

        return nil
    }

    private func modifySecurityGroupRule(
        client: EC2Client,
        securityGroupId: String,
        ruleId: String,
        cidrIp: String,
        port: Int,
        description: String
    ) async throws {
        let ruleUpdate = EC2ClientTypes.SecurityGroupRuleUpdate(
            securityGroupRule: EC2ClientTypes.SecurityGroupRuleRequest(
                cidrIpv4: cidrIp,
                description: description,
                fromPort: port,
                ipProtocol: "tcp",
                toPort: port
            ),
            securityGroupRuleId: ruleId
        )

        let input = ModifySecurityGroupRulesInput(
            groupId: securityGroupId,
            securityGroupRules: [ruleUpdate]
        )

        _ = try await client.modifySecurityGroupRules(input: input)
    }

    private func createSecurityGroupRule(
        client: EC2Client,
        securityGroupId: String,
        cidrIp: String,
        port: Int,
        description: String
    ) async throws {
        let ipPermission = EC2ClientTypes.IpPermission(
            fromPort: port,
            ipProtocol: "tcp",
            ipRanges: [
                EC2ClientTypes.IpRange(
                    cidrIp: cidrIp,
                    description: description
                )
            ],
            toPort: port
        )

        let input = AuthorizeSecurityGroupIngressInput(
            groupId: securityGroupId,
            ipPermissions: [ipPermission]
        )

        _ = try await client.authorizeSecurityGroupIngress(input: input)
    }
}

struct AWSCredentials {
    let accessKeyId: String
    let secretAccessKey: String
    let sessionToken: String?
    let region: String
}

enum SecurityGroupError: LocalizedError {
    case notConfigured
    case ruleNotFound
    case apiError(String)
    case invalidCredentials
    case duplicateRule

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "AWS credentials not configured"
        case .ruleNotFound:
            return "Security group rule not found"
        case .apiError(let message):
            return "AWS API error: \(message)"
        case .invalidCredentials:
            return "Invalid AWS credentials"
        case .duplicateRule:
            return "A rule for this IP already exists"
        }
    }
}

enum UpdateResult {
    case created                    // New rule was created for this device
    case updated                    // Existing rule was updated with new IP
    case noChangeNeeded             // Rule exists and already has correct IP
    case alreadyExistsElsewhere     // IP is allowed by a different rule (different description)
}
