//
//  SecurityGroupService.swift
//  Security Groupie
//

import Foundation

actor SecurityGroupService {
    static let shared = SecurityGroupService()

    private init() {}

    func updateSecurityGroupRule(
        securityGroupId: String,
        region: String,
        ipAddress: String,
        port: Int,
        description: String,
        credentials: AWSCredentials
    ) async throws {
        let cidrIp = "\(ipAddress)/32"

        // First, try to find an existing rule with the same description
        let existingRuleId = try await findExistingRule(
            securityGroupId: securityGroupId,
            region: region,
            description: description,
            credentials: credentials
        )

        if let ruleId = existingRuleId {
            // Update existing rule
            try await modifySecurityGroupRule(
                securityGroupId: securityGroupId,
                region: region,
                ruleId: ruleId,
                cidrIp: cidrIp,
                port: port,
                description: description,
                credentials: credentials
            )
        } else {
            // Create new rule
            try await createSecurityGroupRule(
                securityGroupId: securityGroupId,
                region: region,
                cidrIp: cidrIp,
                port: port,
                description: description,
                credentials: credentials
            )
        }
    }

    private func findExistingRule(
        securityGroupId: String,
        region: String,
        description: String,
        credentials: AWSCredentials
    ) async throws -> String? {
        // For now, this is a placeholder - will be implemented with AWS SDK
        // The AWS SDK will query security group rules and find one matching the description
        return nil
    }

    private func modifySecurityGroupRule(
        securityGroupId: String,
        region: String,
        ruleId: String,
        cidrIp: String,
        port: Int,
        description: String,
        credentials: AWSCredentials
    ) async throws {
        // Placeholder for AWS SDK implementation
        // Will call ModifySecurityGroupRules API
        print("Would modify rule \(ruleId) to \(cidrIp)")
    }

    private func createSecurityGroupRule(
        securityGroupId: String,
        region: String,
        cidrIp: String,
        port: Int,
        description: String,
        credentials: AWSCredentials
    ) async throws {
        // Placeholder for AWS SDK implementation
        // Will call AuthorizeSecurityGroupIngress API
        print("Would create new rule for \(cidrIp)")
    }
}

struct AWSCredentials {
    enum Source {
        case profile(String)
        case accessKey(accessKeyId: String, secretAccessKey: String)
    }

    let source: Source
    let region: String
}

enum SecurityGroupError: LocalizedError {
    case notConfigured
    case ruleNotFound
    case apiError(String)
    case invalidCredentials

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
        }
    }
}
