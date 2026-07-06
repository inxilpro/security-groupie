//
//  Security_GroupieTests.swift
//  Security GroupieTests
//
//  Created by Chris Morrell on 12/11/25.
//

import Foundation
import Testing
@testable import Security_Groupie

@MainActor
final class InMemorySecureStore: SecureStore {
    private var storage: [String: Data] = [:]

    func data(forKey key: String) throws -> Data? {
        storage[key]
    }

    func set(_ data: Data, forKey key: String) throws {
        storage[key] = data
    }

    func delete(key: String) throws {
        storage.removeValue(forKey: key)
    }
}

@MainActor
struct SSOTokenTests {
    @Test func freshTokenIsNotExpired() {
        let token = SSOToken(
            accessToken: "token",
            refreshToken: nil,
            expiresAt: Date().addingTimeInterval(3600)
        )
        #expect(!token.isExpired())
    }

    @Test func pastTokenIsExpired() {
        let token = SSOToken(
            accessToken: "token",
            refreshToken: nil,
            expiresAt: Date().addingTimeInterval(-1)
        )
        #expect(token.isExpired())
    }

    @Test func tokenInsideExpiryBufferIsExpired() {
        let now = Date()
        let token = SSOToken(
            accessToken: "token",
            refreshToken: nil,
            expiresAt: now.addingTimeInterval(SSOToken.expiryBuffer - 1)
        )
        #expect(token.isExpired(now: now))
    }

    @Test func tokenJustOutsideExpiryBufferIsNotExpired() {
        let now = Date()
        let token = SSOToken(
            accessToken: "token",
            refreshToken: nil,
            expiresAt: now.addingTimeInterval(SSOToken.expiryBuffer + 1)
        )
        #expect(!token.isExpired(now: now))
    }
}

@MainActor
struct SSOClientRegistrationTests {
    private func makeRegistration(expiresAt: Date) -> SSOClientRegistration {
        SSOClientRegistration(
            clientId: "client-id",
            clientSecret: "client-secret",
            expiresAt: expiresAt,
            startURL: "https://my-org.awsapps.com/start",
            ssoRegion: "us-east-1"
        )
    }

    @Test func unexpiredMatchingRegistrationIsUsable() {
        let registration = makeRegistration(expiresAt: Date().addingTimeInterval(86400))
        #expect(registration.isUsable(startURL: "https://my-org.awsapps.com/start", ssoRegion: "us-east-1"))
    }

    @Test func expiredRegistrationIsNotUsable() {
        let registration = makeRegistration(expiresAt: Date().addingTimeInterval(-1))
        #expect(!registration.isUsable(startURL: "https://my-org.awsapps.com/start", ssoRegion: "us-east-1"))
    }

    @Test func registrationForDifferentStartURLIsNotUsable() {
        let registration = makeRegistration(expiresAt: Date().addingTimeInterval(86400))
        #expect(!registration.isUsable(startURL: "https://other-org.awsapps.com/start", ssoRegion: "us-east-1"))
    }

    @Test func registrationForDifferentRegionIsNotUsable() {
        let registration = makeRegistration(expiresAt: Date().addingTimeInterval(86400))
        #expect(!registration.isUsable(startURL: "https://my-org.awsapps.com/start", ssoRegion: "eu-west-1"))
    }
}

@MainActor
struct SecureStoreTests {
    @Test func codableRoundTrip() throws {
        let store = InMemorySecureStore()
        let token = SSOToken(
            accessToken: "access",
            refreshToken: "refresh",
            expiresAt: Date(timeIntervalSince1970: 1_767_225_600)
        )

        try store.setCodable(token, forKey: "sso.token")
        let loaded = try store.codable(SSOToken.self, forKey: "sso.token")

        #expect(loaded?.accessToken == "access")
        #expect(loaded?.refreshToken == "refresh")
        #expect(loaded?.expiresAt == token.expiresAt)
    }

    @Test func stringRoundTrip() throws {
        let store = InMemorySecureStore()
        try store.setString("shh-secret", forKey: "accessKey.secret")
        #expect(try store.string(forKey: "accessKey.secret") == "shh-secret")
    }

    @Test func missingKeyReturnsNil() throws {
        let store = InMemorySecureStore()
        #expect(try store.codable(SSOToken.self, forKey: "nope") == nil)
        #expect(try store.string(forKey: "nope") == nil)
    }

    @Test func deleteRemovesValue() throws {
        let store = InMemorySecureStore()
        try store.setString("value", forKey: "key")
        try store.delete(key: "key")
        #expect(try store.string(forKey: "key") == nil)
    }
}

@MainActor
struct PollIntervalTests {
    @Test func serverIntervalIsRespected() {
        #expect(AuthService.nextPollInterval(current: 8, afterSlowDown: false) == 8)
    }

    @Test func missingIntervalDefaultsToFiveSeconds() {
        #expect(AuthService.nextPollInterval(current: 0, afterSlowDown: false) == 5)
        #expect(AuthService.nextPollInterval(current: -3, afterSlowDown: false) == 5)
    }

    @Test func slowDownAddsFiveSeconds() {
        #expect(AuthService.nextPollInterval(current: 5, afterSlowDown: true) == 10)
        #expect(AuthService.nextPollInterval(current: 10, afterSlowDown: true) == 15)
    }
}

@MainActor
struct RoleCredentialsExpirationTests {
    @Test func epochMillisecondsMapToDate() {
        let date = AuthService.roleCredentialsExpiration(epochMilliseconds: 1_767_225_600_000)
        #expect(date == Date(timeIntervalSince1970: 1_767_225_600))
    }
}

@MainActor
struct AppSettingsMigrationTests {
    private func makeDefaults(_ name: String) -> UserDefaults {
        let suiteName = "AppSettingsMigrationTests.\(name)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }

    @Test func profileMethodWithAccessKeyMigratesToAccessKey() {
        let defaults = makeDefaults(#function)
        defaults.set("profile", forKey: "authMethod")
        defaults.set("AKIAEXAMPLE", forKey: "awsAccessKeyId")

        let settings = AppSettings(defaults: defaults)

        #expect(settings.authMethod == .accessKey)
        #expect(defaults.string(forKey: "authMethod") == "accessKey")
    }

    @Test func profileMethodWithoutAccessKeyMigratesToSSO() {
        let defaults = makeDefaults(#function)
        defaults.set("profile", forKey: "authMethod")

        let settings = AppSettings(defaults: defaults)

        #expect(settings.authMethod == .sso)
        #expect(defaults.string(forKey: "authMethod") == "sso")
    }

    @Test func freshInstallDefaultsToSSO() {
        let defaults = makeDefaults(#function)
        let settings = AppSettings(defaults: defaults)
        #expect(settings.authMethod == .sso)
    }

    @Test func existingAccessKeyMethodIsPreserved() {
        let defaults = makeDefaults(#function)
        defaults.set("accessKey", forKey: "authMethod")

        let settings = AppSettings(defaults: defaults)

        #expect(settings.authMethod == .accessKey)
    }

    @Test func legacyProfileKeyIsRemoved() {
        let defaults = makeDefaults(#function)
        defaults.set("default", forKey: "awsProfile")

        _ = AppSettings(defaults: defaults)

        #expect(defaults.string(forKey: "awsProfile") == nil)
    }
}

@MainActor
struct AuthServiceTests {
    private func makeDefaults(_ name: String) -> UserDefaults {
        let suiteName = "AuthServiceTests.\(name)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }

    @Test func legacySecretMovesFromDefaultsToStore() throws {
        let defaults = makeDefaults(#function)
        defaults.set("legacy-secret", forKey: "awsSecretAccessKey")
        let store = InMemorySecureStore()

        let auth = AuthService(store: store, defaults: defaults)

        #expect(auth.accessKeySecret == "legacy-secret")
        #expect(try store.string(forKey: "accessKey.secret") == "legacy-secret")
        #expect(defaults.string(forKey: "awsSecretAccessKey") == nil)
    }

    @Test func settingSecretPersistsToStore() throws {
        let store = InMemorySecureStore()
        let auth = AuthService(store: store, defaults: makeDefaults(#function))

        auth.accessKeySecret = "new-secret"

        #expect(auth.hasAccessKeySecret)
        #expect(try store.string(forKey: "accessKey.secret") == "new-secret")
    }

    @Test func clearingSecretRemovesIt() throws {
        let store = InMemorySecureStore()
        let auth = AuthService(store: store, defaults: makeDefaults(#function))

        auth.accessKeySecret = "secret"
        auth.accessKeySecret = ""

        #expect(!auth.hasAccessKeySecret)
        #expect(try store.string(forKey: "accessKey.secret") == nil)
    }

    @Test func existingRefreshableTokenRestoresSignedInState() throws {
        let store = InMemorySecureStore()
        let token = SSOToken(
            accessToken: "access",
            refreshToken: "refresh",
            expiresAt: Date().addingTimeInterval(-100)
        )
        try store.setCodable(token, forKey: "sso.token")

        let auth = AuthService(store: store, defaults: makeDefaults(#function))

        #expect(auth.ssoState == .signedIn(tokenExpiresAt: token.expiresAt))
    }

    @Test func expiredTokenWithoutRefreshTokenIsCleared() throws {
        let store = InMemorySecureStore()
        let token = SSOToken(
            accessToken: "access",
            refreshToken: nil,
            expiresAt: Date().addingTimeInterval(-100)
        )
        try store.setCodable(token, forKey: "sso.token")

        let auth = AuthService(store: store, defaults: makeDefaults(#function))

        #expect(auth.ssoState == .signedOut)
        #expect(try store.codable(SSOToken.self, forKey: "sso.token") == nil)
    }
}
