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

    private var isCheckInProgress = false

    private init() {
        // Request notification permissions
        Task {
            await requestNotificationPermissions()
        }

        // Start network monitoring
        NetworkMonitor.shared.startMonitoring {
            Task {
                await AppState.shared.handleNetworkChange()
            }
        }

        // Check immediately on launch
        Task {
            await handleManualRefresh()
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

    var statusText: String? {
        switch status {
        case .idle:
            return nil
        case .checking:
            return "Checking IP..."
        case .updating:
            return "Updating security group..."
        case .success:
            return nil
        case .error(let message):
            return "Error: \(message)"
        }
    }

    /// Called when a network change is detected. Only checks AWS if IP changed.
    /// Only notifies on actual changes (created/updated), not when already configured.
    func handleNetworkChange() async {
        guard !isCheckInProgress else {
            print("[Security Groupie] Check already in progress, skipping...")
            return
        }

        isCheckInProgress = true
        defer { isCheckInProgress = false }

        status = .checking
        print("[Security Groupie] Network change detected, checking IP...")

        do {
            let ip = try await IPService.shared.fetchCurrentIP()
            currentIP = ip
            print("[Security Groupie] Current IP: \(ip)")

            let settings = AppSettings.shared

            guard settings.isConfigured else {
                print("[Security Groupie] Not configured, skipping")
                status = .error("Not configured")
                return
            }

            // For network changes, skip if IP hasn't changed
            if ip == settings.lastKnownIP {
                print("[Security Groupie] IP unchanged, skipping AWS check")
                status = .success
                return
            }

            // IP changed, check AWS
            let result = try await updateSecurityGroup(ip: ip, settings: settings)

            settings.lastKnownIP = ip
            lastUpdated = Date()
            status = .success
            print("[Security Groupie] Result: \(result)")

            // Only notify on actual changes
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
            case .noChangeNeeded, .alreadyExistsElsewhere:
                // No notification for network changes when already configured
                break
            }
        } catch {
            print("[Security Groupie] Error: \(error)")
            status = .error(error.localizedDescription)
        }
    }

    /// Called for manual refresh (menu button, settings open, app launch).
    /// Always checks AWS and always notifies with result.
    func handleManualRefresh() async {
        guard !isCheckInProgress else {
            print("[Security Groupie] Check already in progress, skipping...")
            return
        }

        isCheckInProgress = true
        defer { isCheckInProgress = false }

        status = .checking
        print("[Security Groupie] Manual refresh, checking IP and AWS...")

        do {
            let ip = try await IPService.shared.fetchCurrentIP()
            currentIP = ip
            print("[Security Groupie] Current IP: \(ip)")

            let settings = AppSettings.shared

            guard settings.isConfigured else {
                print("[Security Groupie] Not configured")
                status = .error("Not configured")
                return
            }

            // Always check AWS for manual refresh
            let result = try await updateSecurityGroup(ip: ip, settings: settings)

            settings.lastKnownIP = ip
            lastUpdated = Date()
            status = .success
            print("[Security Groupie] Result: \(result)")

            // Always notify for manual refresh
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
            case .noChangeNeeded:
                await sendNotification(
                    title: "Already Configured",
                    body: "Security group rule is already set to \(ip)"
                )
            case .alreadyExistsElsewhere:
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

    /// Core logic to update the security group rule
    private func updateSecurityGroup(ip: String, settings: AppSettings) async throws -> UpdateResult {
        status = .updating
        print("[Security Groupie] Updating security group...")

        let credentials = try await AuthService.shared.credentials(forRegion: settings.awsRegion)

        print("[Security Groupie] Calling EC2 API - securityGroupId: \(settings.securityGroupId), region: \(settings.awsRegion), port: \(settings.port), description: \(settings.deviceNickname)")
        return try await EC2Service.shared.updateSecurityGroupRule(
            securityGroupId: settings.securityGroupId,
            region: settings.awsRegion,
            ipAddress: ip,
            port: settings.port,
            description: settings.deviceNickname,
            credentials: credentials
        )
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
