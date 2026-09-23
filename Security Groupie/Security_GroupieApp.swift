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
        case signInRequired
        case error(String)
    }

    enum SignInNotification {
        static let identifier = "sign-in-required"
        static let category = "SIGN_IN_REQUIRED"
        static let signInAction = "SIGN_IN"
    }

    var status: Status = .idle
    var currentIP: String?
    var lastUpdated: Date?

    // Non-nil means an update for this IP is waiting on sign-in
    private(set) var pendingSignInIP: String?
    private var notifiedSignInIP: String?

    private var isCheckInProgress = false
    private let notificationDelegate = NotificationDelegate()

    private init() {
        let center = UNUserNotificationCenter.current()
        center.delegate = notificationDelegate
        center.setNotificationCategories([
            UNNotificationCategory(
                identifier: SignInNotification.category,
                actions: [
                    UNNotificationAction(identifier: SignInNotification.signInAction, title: "Log In to AWS")
                ],
                intentIdentifiers: []
            )
        ])

        Task {
            await requestNotificationPermissions()
        }

        NetworkMonitor.shared.startMonitoring {
            Task {
                await AppState.shared.handleNetworkChange()
            }
        }

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
        case .signInRequired:
            return "exclamationmark.shield"
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
        case .signInRequired:
            return "Log into AWS to update security group"
        case .error(let message):
            return "Error: \(message)"
        }
    }

    var needsSignIn: Bool {
        pendingSignInIP != nil
    }

    /// Called when a network change is detected. Only checks AWS if IP changed.
    /// Only notifies on actual changes (created/updated), not when already configured.
    func handleNetworkChange() async {
        await runCheck(skipIfIPUnchanged: true, notifyAlways: false)
    }

    /// Called for manual refresh (menu button, settings open, app launch).
    /// Always checks AWS and always notifies with result. Pass `promptForSignIn: false` when the
    /// user is already somewhere they can sign in, so they aren't nagged with a notification.
    func handleManualRefresh(promptForSignIn: Bool = true) async {
        await runCheck(skipIfIPUnchanged: false, notifyAlways: true, promptForSignIn: promptForSignIn)
    }

    /// Starts (or resumes) the Identity Center sign-in and, once it completes, applies
    /// any security group update that was blocked on authentication.
    func signInAndUpdate() async throws {
        let auth = AuthService.shared

        // A second device-flow request would invalidate the code the user may already be confirming
        if case .authorizing(_, let verificationURL, _) = auth.ssoState {
            NSWorkspace.shared.open(verificationURL)
            return
        }

        try await auth.signIn()

        // signIn returns without throwing when superseded or cancelled
        guard case .signedIn = auth.ssoState else { return }

        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [SignInNotification.identifier])

        if needsSignIn {
            // Detached so callers (e.g. Settings) aren't held up by the EC2 round-trip
            Task {
                await runCheck(skipIfIPUnchanged: false, notifyAlways: false)
            }
        }
    }

    func beginSignIn() async {
        do {
            try await signInAndUpdate()
        } catch {
            print("[Security Groupie] Sign-in failed: \(error)")
            status = .error(error.localizedDescription)
        }
    }

    private func runCheck(skipIfIPUnchanged: Bool, notifyAlways: Bool, promptForSignIn shouldPrompt: Bool = true) async {
        guard !isCheckInProgress else {
            print("[Security Groupie] Check already in progress, skipping...")
            return
        }

        isCheckInProgress = true
        defer { isCheckInProgress = false }

        status = .checking
        print("[Security Groupie] Checking IP (skipIfIPUnchanged: \(skipIfIPUnchanged))...")

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

            let ipChanged = ip != settings.lastKnownIP

            if skipIfIPUnchanged && !ipChanged {
                print("[Security Groupie] IP unchanged, skipping AWS check")
                // Back on the IP the rule already allows, so a pending sign-in no longer matters
                pendingSignInIP = nil
                notifiedSignInIP = nil
                status = .success
                return
            }

            let result: UpdateResult
            do {
                result = try await updateSecurityGroup(ip: ip, settings: settings)
            } catch let error where Self.requiresSignIn(error, authMethod: settings.authMethod) {
                print("[Security Groupie] Not authenticated: \(error)")
                await promptForSignIn(ip: ip, ipChanged: ipChanged, notify: shouldPrompt)
                return
            }

            settings.lastKnownIP = ip
            pendingSignInIP = nil
            notifiedSignInIP = nil
            lastUpdated = Date()
            status = .success
            print("[Security Groupie] Result: \(result)")

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
            case .noChangeNeeded where notifyAlways:
                await sendNotification(
                    title: "Already Configured",
                    body: "Security group rule is already set to \(ip)"
                )
            case .alreadyExistsElsewhere where notifyAlways:
                await sendNotification(
                    title: "IP Already Allowed",
                    body: "There is already another security group rule for your IP address. Skipping."
                )
            case .noChangeNeeded, .alreadyExistsElsewhere:
                break
            }
        } catch {
            print("[Security Groupie] Error: \(error)")
            status = .error(error.localizedDescription)
        }
    }

    static func requiresSignIn(_ error: Error, authMethod: AWSAuthMethod) -> Bool {
        guard authMethod == .sso, let authError = error as? AuthError else {
            return false
        }
        switch authError {
        case .notSignedIn, .sessionExpired:
            return true
        case .signInTimedOut, .signInDenied, .missingConfiguration:
            return false
        }
    }

    private func promptForSignIn(ip: String, ipChanged: Bool, notify: Bool) async {
        status = .signInRequired
        // Recorded even when silent so a sign-in from Settings still applies the update
        pendingSignInIP = ip

        // Network path updates fire in bursts; one prompt per IP is enough
        guard notify, notifiedSignInIP != ip else { return }
        notifiedSignInIP = ip

        await sendNotification(
            title: ipChanged ? "Your IP has changed" : "AWS Sign-In Required",
            body: "Log into AWS to update security group",
            identifier: SignInNotification.identifier,
            categoryIdentifier: SignInNotification.category
        )
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

    private func sendNotification(
        title: String,
        body: String,
        identifier: String = UUID().uuidString,
        categoryIdentifier: String? = nil
    ) async {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        if let categoryIdentifier {
            content.categoryIdentifier = categoryIdentifier
        }

        let request = UNNotificationRequest(
            identifier: identifier,
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

final class NotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let category = response.notification.request.content.categoryIdentifier
        let action = response.actionIdentifier

        await MainActor.run {
            guard category == AppState.SignInNotification.category,
                  action == UNNotificationDefaultActionIdentifier || action == AppState.SignInNotification.signInAction else {
                return
            }

            // The device flow can take minutes; don't hold the system's response handler open for it
            Task {
                await AppState.shared.beginSignIn()
            }
        }
    }

    // Without this, notifications are suppressed while Settings has the app frontmost
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }
}
