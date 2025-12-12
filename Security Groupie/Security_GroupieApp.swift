//
//  Security_GroupieApp.swift
//  Security Groupie
//
//  Created by Chris Morrell on 12/11/25.
//

import SwiftUI

@main
struct Security_GroupieApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
                .environment(appState)
        } label: {
            Image(systemName: appState.statusIcon)
        }

        Settings {
            SettingsView()
                .environment(appState)
        }
    }
}

@Observable
final class AppState {
    enum Status {
        case idle
        case checking
        case updating
        case success
        case error(String)
    }

    var status: Status = .idle
    var currentIP: String?
    var lastUpdated: Date?

    var statusIcon: String {
        switch status {
        case .idle:
            return "shield"
        case .checking, .updating:
            return "shield.badge.arrow.right"
        case .success:
            return "shield.checkered"
        case .error:
            return "shield.fill.xmark"
        }
    }

    var statusText: String {
        switch status {
        case .idle:
            return "Idle"
        case .checking:
            return "Checking IP..."
        case .updating:
            return "Updating security group..."
        case .success:
            return "Up to date"
        case .error(let message):
            return "Error: \(message)"
        }
    }

    func checkAndUpdateIP() async {
        status = .checking

        do {
            let ip = try await IPService.shared.fetchCurrentIP()
            currentIP = ip

            let settings = AppSettings.shared
            guard settings.isConfigured else {
                status = .error("Not configured")
                return
            }

            // Check if IP changed
            if ip == settings.lastKnownIP {
                status = .success
                return
            }

            status = .updating

            let accessKeyId: String
            let secretAccessKey: String

            if settings.authMethod == .profile {
                guard let profileCreds = AWSConfigService.shared.credentials(for: settings.awsProfile) else {
                    status = .error("Profile credentials not found")
                    return
                }
                accessKeyId = profileCreds.accessKeyId
                secretAccessKey = profileCreds.secretAccessKey
            } else {
                accessKeyId = settings.awsAccessKeyId
                secretAccessKey = settings.awsSecretAccessKey
            }

            let credentials = AWSCredentials(
                accessKeyId: accessKeyId,
                secretAccessKey: secretAccessKey,
                region: settings.awsRegion
            )

            try await SecurityGroupService.shared.updateSecurityGroupRule(
                securityGroupId: settings.securityGroupId,
                region: settings.awsRegion,
                ipAddress: ip,
                port: settings.port,
                description: settings.deviceNickname,
                credentials: credentials
            )

            settings.lastKnownIP = ip
            lastUpdated = Date()
            status = .success
        } catch {
            status = .error(error.localizedDescription)
        }
    }
}
