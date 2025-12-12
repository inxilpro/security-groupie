//
//  Security_GroupieApp.swift
//  Security Groupie
//
//  Created by Chris Morrell on 12/11/25.
//

import SwiftUI
import UserNotifications

@main
struct Security_GroupieApp: App {
    @State private var appState = AppState.shared

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
    static let shared = AppState()

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

    private init() {
        // Request notification permissions
        Task {
            await requestNotificationPermissions()
        }

        // Start network monitoring - use cached IP check for network changes
        NetworkMonitor.shared.startMonitoring {
            Task {
                await AppState.shared.checkAndUpdateIP(force: false)
            }
        }

        // Check immediately on launch - always force update
        Task {
            await checkAndUpdateIP(force: true)
        }
    }

    private func requestNotificationPermissions() async {
        do {
            try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
        } catch {
            print("Failed to request notification permissions: \(error)")
        }
    }

    var statusIcon: String {
        switch status {
        case .idle:
            return "shield"
        case .checking, .updating:
            return "arrow.trianglehead.2.clockwise"
        case .success:
            return "checkmark.shield"
        case .error:
            return "xmark.shield"
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

    func checkAndUpdateIP(force: Bool = false) async {
        status = .checking
        print("[Security Groupie] Starting IP check (force: \(force))...")

        do {
            let ip = try await IPService.shared.fetchCurrentIP()
            currentIP = ip
            print("[Security Groupie] Current IP: \(ip)")

            let settings = AppSettings.shared
            print("[Security Groupie] isConfigured: \(settings.isConfigured), securityGroupId: '\(settings.securityGroupId)', authMethod: \(settings.authMethod), profile: '\(settings.awsProfile)'")

            guard settings.isConfigured else {
                print("[Security Groupie] Not configured - missing security group or credentials")
                status = .error("Not configured")
                return
            }

            // Check if IP changed (skip this check if force is true)
            let isNewRule = settings.lastKnownIP == nil
            print("[Security Groupie] lastKnownIP: \(settings.lastKnownIP ?? "nil"), isNewRule: \(isNewRule), force: \(force)")

            if !force && ip == settings.lastKnownIP {
                print("[Security Groupie] IP unchanged, skipping update")
                status = .success
                return
            }

            status = .updating
            print("[Security Groupie] Updating security group...")

            // Build credentials
            let accessKeyId: String
            let secretAccessKey: String

            if settings.authMethod == .profile {
                guard let profileCreds = AWSConfigService.shared.credentials(for: settings.awsProfile) else {
                    print("[Security Groupie] Profile credentials not found for profile: \(settings.awsProfile)")
                    status = .error("Profile credentials not found")
                    return
                }
                accessKeyId = profileCreds.accessKeyId
                secretAccessKey = profileCreds.secretAccessKey
                print("[Security Groupie] Using profile credentials for: \(settings.awsProfile)")
            } else {
                accessKeyId = settings.awsAccessKeyId
                secretAccessKey = settings.awsSecretAccessKey
                print("[Security Groupie] Using access key credentials")
            }

            let credentials = AWSCredentials(
                accessKeyId: accessKeyId,
                secretAccessKey: secretAccessKey,
                region: settings.awsRegion
            )

            // Update the security group
            print("[Security Groupie] Calling EC2 API - securityGroupId: \(settings.securityGroupId), region: \(settings.awsRegion), port: \(settings.port), description: \(settings.deviceNickname)")
            let result = try await EC2Service.shared.updateSecurityGroupRule(
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
            print("[Security Groupie] Result: \(result)")

            // Send notification based on result
            switch result {
            case .created:
                await sendNotification(
                    title: "Security Group Rule Created",
                    body: "IP address set to \(ip)"
                )
            case .updated:
                await sendNotification(
                    title: "Security Group Rule Updated",
                    body: "IP address updated to \(ip)"
                )
            case .alreadyExists:
                await sendNotification(
                    title: "IP Already Allowed",
                    body: "There is already another security group rule for your IP address. Skipping."
                )
            }
        } catch {
            print("[Security Groupie] Error: \(error)")
            status = .error(error.localizedDescription)
        }
    }

    private func sendNotification(title: String, body: String) async {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil // Deliver immediately
        )

        do {
            try await UNUserNotificationCenter.current().add(request)
        } catch {
            print("Failed to send notification: \(error)")
        }
    }
}
