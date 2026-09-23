//
//  AuthService.swift
//  Security Groupie
//

import AppKit
import AWSSSO
import AWSSSOOIDC
import Foundation
import Observation

struct SSOClientRegistration: Codable {
    let clientId: String
    let clientSecret: String
    let expiresAt: Date
    let startURL: String
    let ssoRegion: String

    func isUsable(startURL: String, ssoRegion: String, now: Date = Date()) -> Bool {
        expiresAt > now.addingTimeInterval(60)
            && self.startURL == startURL
            && self.ssoRegion == ssoRegion
    }
}

struct SSOToken: Codable {
    let accessToken: String
    let refreshToken: String?
    let expiresAt: Date

    // Refresh slightly early so in-flight requests don't race token expiry
    static let expiryBuffer: TimeInterval = 120

    func isExpired(now: Date = Date()) -> Bool {
        expiresAt <= now.addingTimeInterval(Self.expiryBuffer)
    }
}

struct SSOAccountInfo: Identifiable, Hashable {
    let id: String
    let name: String
    let email: String?
}

enum SSOSignInState: Equatable {
    case signedOut
    case authorizing(userCode: String, verificationURL: URL, expiresAt: Date)
    case signedIn(tokenExpiresAt: Date)
}

enum AuthError: LocalizedError {
    case notSignedIn
    case sessionExpired
    case signInTimedOut
    case signInDenied
    case missingConfiguration

    var errorDescription: String? {
        switch self {
        case .notSignedIn:
            return "Not signed in — open Settings and sign in to AWS"
        case .sessionExpired:
            return "AWS session expired — open Settings and sign in again"
        case .signInTimedOut:
            return "Sign-in timed out — try again"
        case .signInDenied:
            return "Sign-in was denied"
        case .missingConfiguration:
            return "AWS authentication is not configured"
        }
    }
}

@MainActor
@Observable
final class AuthService {
    static let shared = AuthService()

    private(set) var ssoState: SSOSignInState = .signedOut
    private(set) var accounts: [SSOAccountInfo] = []
    private(set) var roles: [String] = []

    private let store: SecureStore
    private var cachedRoleCredentials: (credentials: AWSCredentials, expiresAt: Date, accountId: String, roleName: String)?
    private var signInTask: Task<SSOToken, Error>?
    private var refreshTask: Task<SSOToken, Error>?
    private var cachedAccessKeySecret: String

    private enum StoreKeys {
        static let registration = "sso.registration"
        static let token = "sso.token"
        static let accessKeySecret = "accessKey.secret"
    }

    // Role credentials are reused until close to expiry; getRoleCredentials is cheap but not free
    private static let roleCredentialsReuseBuffer: TimeInterval = 300

    init(
        store: SecureStore = KeychainStore(service: "com.securitygroupie.Security-Groupie"),
        defaults: UserDefaults = .standard
    ) {
        self.store = store

        // Older versions kept the secret access key in plaintext UserDefaults
        if let legacySecret = defaults.string(forKey: "awsSecretAccessKey"), !legacySecret.isEmpty {
            try? store.setString(legacySecret, forKey: StoreKeys.accessKeySecret)
            defaults.removeObject(forKey: "awsSecretAccessKey")
        }

        self.cachedAccessKeySecret = (try? store.string(forKey: StoreKeys.accessKeySecret)) ?? ""

        if let token = try? store.codable(SSOToken.self, forKey: StoreKeys.token) {
            if !token.isExpired() || token.refreshToken != nil {
                // Optimistic: an expired-but-refreshable token is renewed lazily on first use
                ssoState = .signedIn(tokenExpiresAt: token.expiresAt)
            } else {
                try? store.delete(key: StoreKeys.token)
            }
        }
    }

    // MARK: - Credentials (unified entry point)

    func credentials(forRegion region: String) async throws -> AWSCredentials {
        let settings = AppSettings.shared

        switch settings.authMethod {
        case .accessKey:
            guard !settings.awsAccessKeyId.isEmpty, !cachedAccessKeySecret.isEmpty else {
                throw AuthError.missingConfiguration
            }
            return AWSCredentials(
                accessKeyId: settings.awsAccessKeyId,
                secretAccessKey: cachedAccessKeySecret,
                sessionToken: nil,
                region: region
            )

        case .sso:
            guard !settings.ssoAccountId.isEmpty, !settings.ssoRoleName.isEmpty else {
                throw AuthError.missingConfiguration
            }

            if let cached = cachedRoleCredentials,
               cached.accountId == settings.ssoAccountId,
               cached.roleName == settings.ssoRoleName,
               cached.expiresAt > Date().addingTimeInterval(Self.roleCredentialsReuseBuffer) {
                return AWSCredentials(
                    accessKeyId: cached.credentials.accessKeyId,
                    secretAccessKey: cached.credentials.secretAccessKey,
                    sessionToken: cached.credentials.sessionToken,
                    region: region
                )
            }

            let token = try await validAccessToken()
            let client = try SSOClient(region: settings.ssoRegion)
            let output: GetRoleCredentialsOutput
            do {
                output = try await client.getRoleCredentials(input: GetRoleCredentialsInput(
                    accessToken: token.accessToken,
                    accountId: settings.ssoAccountId,
                    roleName: settings.ssoRoleName
                ))
            } catch is AWSSSO.UnauthorizedException {
                // The token looked valid locally but Identity Center revoked it (e.g. portal sign-out)
                clearSession()
                throw AuthError.sessionExpired
            }

            guard let role = output.roleCredentials,
                  let accessKeyId = role.accessKeyId,
                  let secretAccessKey = role.secretAccessKey else {
                throw AuthError.sessionExpired
            }

            let credentials = AWSCredentials(
                accessKeyId: accessKeyId,
                secretAccessKey: secretAccessKey,
                sessionToken: role.sessionToken,
                region: region
            )
            let expiresAt = Self.roleCredentialsExpiration(epochMilliseconds: role.expiration)
            cachedRoleCredentials = (credentials, expiresAt, settings.ssoAccountId, settings.ssoRoleName)
            return credentials
        }
    }

    // MARK: - Access token lifecycle

    private func validAccessToken() async throws -> SSOToken {
        guard let token = try? store.codable(SSOToken.self, forKey: StoreKeys.token) else {
            ssoState = .signedOut
            throw AuthError.notSignedIn
        }

        if !token.isExpired() {
            return token
        }

        guard token.refreshToken != nil else {
            clearSession()
            throw AuthError.sessionExpired
        }

        if let refreshTask {
            return try await refreshTask.value
        }

        let task = Task<SSOToken, Error> { [weak self] in
            guard let self else { throw AuthError.notSignedIn }
            return try await self.refreshAccessToken(token)
        }
        refreshTask = task
        defer { refreshTask = nil }
        return try await task.value
    }

    private func refreshAccessToken(_ token: SSOToken) async throws -> SSOToken {
        let settings = AppSettings.shared
        guard let registration = try? store.codable(SSOClientRegistration.self, forKey: StoreKeys.registration),
              registration.isUsable(startURL: settings.ssoStartURL, ssoRegion: settings.ssoRegion) else {
            clearSession()
            throw AuthError.sessionExpired
        }

        do {
            let client = try SSOOIDCClient(region: settings.ssoRegion)
            let output = try await client.createToken(input: CreateTokenInput(
                clientId: registration.clientId,
                clientSecret: registration.clientSecret,
                grantType: "refresh_token",
                refreshToken: token.refreshToken
            ))

            guard let accessToken = output.accessToken else {
                clearSession()
                throw AuthError.sessionExpired
            }

            let refreshed = SSOToken(
                accessToken: accessToken,
                // Identity Center may rotate the refresh token or omit it; keep the old one if omitted
                refreshToken: output.refreshToken ?? token.refreshToken,
                expiresAt: Date().addingTimeInterval(Double(output.expiresIn))
            )
            try store.setCodable(refreshed, forKey: StoreKeys.token)
            ssoState = .signedIn(tokenExpiresAt: refreshed.expiresAt)
            return refreshed
        } catch is InvalidGrantException {
            clearSession()
            throw AuthError.sessionExpired
        } catch is ExpiredTokenException {
            clearSession()
            throw AuthError.sessionExpired
        }
    }

    // MARK: - Sign in (OIDC device authorization flow, RFC 8628)

    func signIn() async throws {
        let settings = AppSettings.shared
        guard !settings.ssoStartURL.isEmpty, !settings.ssoRegion.isEmpty else {
            throw AuthError.missingConfiguration
        }

        signInTask?.cancel()

        let client = try SSOOIDCClient(region: settings.ssoRegion)
        let registration = try await usableRegistration(client: client, settings: settings)

        let authorization = try await client.startDeviceAuthorization(input: StartDeviceAuthorizationInput(
            clientId: registration.clientId,
            clientSecret: registration.clientSecret,
            startUrl: settings.ssoStartURL
        ))

        guard let deviceCode = authorization.deviceCode,
              let userCode = authorization.userCode,
              let verificationString = authorization.verificationUriComplete,
              let verificationURL = URL(string: verificationString) else {
            throw AuthError.signInDenied
        }

        let deadline = Date().addingTimeInterval(Double(authorization.expiresIn))
        ssoState = .authorizing(userCode: userCode, verificationURL: verificationURL, expiresAt: deadline)
        NSWorkspace.shared.open(verificationURL)

        let interval = authorization.interval
        let task = Task<SSOToken, Error> { [weak self] in
            guard let self else { throw AuthError.notSignedIn }
            return try await self.pollForToken(
                client: client,
                registration: registration,
                deviceCode: deviceCode,
                initialInterval: interval,
                deadline: deadline
            )
        }
        signInTask = task
        defer { signInTask = nil }

        do {
            let token = try await task.value
            try store.setCodable(token, forKey: StoreKeys.token)
            cachedRoleCredentials = nil
            ssoState = .signedIn(tokenExpiresAt: token.expiresAt)
        } catch is CancellationError {
            ssoState = .signedOut
            return
        } catch {
            ssoState = .signedOut
            throw error
        }

        try? await loadAccounts()
        if !settings.ssoAccountId.isEmpty {
            try? await loadRoles(accountId: settings.ssoAccountId)
        }
    }

    func cancelSignIn() {
        signInTask?.cancel()
    }

    private func usableRegistration(client: SSOOIDCClient, settings: AppSettings) async throws -> SSOClientRegistration {
        if let existing = try? store.codable(SSOClientRegistration.self, forKey: StoreKeys.registration),
           existing.isUsable(startURL: settings.ssoStartURL, ssoRegion: settings.ssoRegion) {
            return existing
        }

        let output = try await client.registerClient(input: RegisterClientInput(
            clientName: "Security Groupie",
            clientType: "public",
            // Both grant types plus the account-access scope are required for Identity Center
            // to issue a refresh token alongside the device-flow access token
            grantTypes: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            scopes: ["sso:account:access"]
        ))

        guard let clientId = output.clientId, let clientSecret = output.clientSecret else {
            throw AuthError.signInDenied
        }

        let registration = SSOClientRegistration(
            clientId: clientId,
            clientSecret: clientSecret,
            // clientSecretExpiresAt is epoch seconds
            expiresAt: Date(timeIntervalSince1970: Double(output.clientSecretExpiresAt)),
            startURL: settings.ssoStartURL,
            ssoRegion: settings.ssoRegion
        )
        try store.setCodable(registration, forKey: StoreKeys.registration)
        return registration
    }

    private func pollForToken(
        client: SSOOIDCClient,
        registration: SSOClientRegistration,
        deviceCode: String,
        initialInterval: Int,
        deadline: Date
    ) async throws -> SSOToken {
        var interval = Self.nextPollInterval(current: initialInterval, afterSlowDown: false)

        while true {
            try Task.checkCancellation()
            guard Date() < deadline else { throw AuthError.signInTimedOut }

            try await Task.sleep(for: .seconds(interval))

            do {
                let output = try await client.createToken(input: CreateTokenInput(
                    clientId: registration.clientId,
                    clientSecret: registration.clientSecret,
                    deviceCode: deviceCode,
                    grantType: "urn:ietf:params:oauth:grant-type:device_code"
                ))

                guard let accessToken = output.accessToken else {
                    throw AuthError.signInDenied
                }

                return SSOToken(
                    accessToken: accessToken,
                    refreshToken: output.refreshToken,
                    expiresAt: Date().addingTimeInterval(Double(output.expiresIn))
                )
            } catch is AuthorizationPendingException {
                continue
            } catch is SlowDownException {
                interval = Self.nextPollInterval(current: interval, afterSlowDown: true)
                continue
            } catch is ExpiredTokenException {
                throw AuthError.signInTimedOut
            } catch is AccessDeniedException {
                throw AuthError.signInDenied
            }
        }
    }

    // RoleCredentials.expiration is epoch milliseconds, unlike the other SSO timestamps
    static func roleCredentialsExpiration(epochMilliseconds: Int) -> Date {
        Date(timeIntervalSince1970: Double(epochMilliseconds) / 1000)
    }

    // RFC 8628 §3.5: default interval is 5s when the server sends none, slow_down adds 5s
    static func nextPollInterval(current: Int, afterSlowDown: Bool) -> Int {
        let base = current > 0 ? current : 5
        return afterSlowDown ? base + 5 : base
    }

    // MARK: - Sign out

    func signOut() async {
        signInTask?.cancel()
        refreshTask?.cancel()

        if let token = try? store.codable(SSOToken.self, forKey: StoreKeys.token) {
            let ssoRegion = AppSettings.shared.ssoRegion
            if !ssoRegion.isEmpty, let client = try? SSOClient(region: ssoRegion) {
                try? await client.logout(input: LogoutInput(accessToken: token.accessToken))
            }
        }

        // Registration stays cached — it's reusable across sessions and avoids re-registering
        clearSession()
    }

    private func clearSession() {
        try? store.delete(key: StoreKeys.token)
        cachedRoleCredentials = nil
        accounts = []
        roles = []
        ssoState = .signedOut
    }

    // MARK: - Accounts & roles

    func loadAccounts() async throws {
        let token = try await validAccessToken()
        let client = try SSOClient(region: AppSettings.shared.ssoRegion)

        var loaded: [SSOAccountInfo] = []
        var nextToken: String? = nil
        repeat {
            let output = try await client.listAccounts(input: ListAccountsInput(
                accessToken: token.accessToken,
                nextToken: nextToken
            ))
            for account in output.accountList ?? [] {
                guard let id = account.accountId else { continue }
                loaded.append(SSOAccountInfo(
                    id: id,
                    name: account.accountName ?? id,
                    email: account.emailAddress
                ))
            }
            nextToken = output.nextToken
        } while nextToken != nil

        accounts = loaded.sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    func loadRoles(accountId: String) async throws {
        let token = try await validAccessToken()
        let client = try SSOClient(region: AppSettings.shared.ssoRegion)

        var loaded: [String] = []
        var nextToken: String? = nil
        repeat {
            let output = try await client.listAccountRoles(input: ListAccountRolesInput(
                accessToken: token.accessToken,
                accountId: accountId,
                nextToken: nextToken
            ))
            loaded.append(contentsOf: (output.roleList ?? []).compactMap(\.roleName))
            nextToken = output.nextToken
        } while nextToken != nil

        roles = loaded.sorted()
    }

    // MARK: - Access key secret (Keychain-backed)

    var accessKeySecret: String {
        get { cachedAccessKeySecret }
        set {
            cachedAccessKeySecret = newValue
            if newValue.isEmpty {
                try? store.delete(key: StoreKeys.accessKeySecret)
            } else {
                try? store.setString(newValue, forKey: StoreKeys.accessKeySecret)
            }
        }
    }

    var hasAccessKeySecret: Bool {
        !cachedAccessKeySecret.isEmpty
    }
}
