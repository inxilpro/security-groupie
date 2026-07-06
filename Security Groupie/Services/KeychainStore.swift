//
//  KeychainStore.swift
//  Security Groupie
//

import Foundation
import Security

protocol SecureStore {
    func data(forKey key: String) throws -> Data?
    func set(_ data: Data, forKey key: String) throws
    func delete(key: String) throws
}

enum SecureStoreError: LocalizedError {
    case unhandledStatus(OSStatus)

    var errorDescription: String? {
        switch self {
        case .unhandledStatus(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Keychain error: \(message)"
        }
    }
}

struct KeychainStore: SecureStore {
    let service: String

    private func baseQuery(forKey key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
    }

    func data(forKey key: String) throws -> Data? {
        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            return result as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw SecureStoreError.unhandledStatus(status)
        }
    }

    func set(_ data: Data, forKey key: String) throws {
        let attributes = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(baseQuery(forKey: key) as CFDictionary, attributes as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var query = baseQuery(forKey: key)
            query[kSecValueData as String] = data
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw SecureStoreError.unhandledStatus(addStatus)
            }
        default:
            throw SecureStoreError.unhandledStatus(updateStatus)
        }
    }

    func delete(key: String) throws {
        let status = SecItemDelete(baseQuery(forKey: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureStoreError.unhandledStatus(status)
        }
    }
}

extension SecureStore {
    func codable<T: Codable>(_ type: T.Type, forKey key: String) throws -> T? {
        guard let data = try data(forKey: key) else { return nil }
        return try JSONDecoder().decode(type, from: data)
    }

    func setCodable<T: Codable>(_ value: T, forKey key: String) throws {
        try set(JSONEncoder().encode(value), forKey: key)
    }

    func string(forKey key: String) throws -> String? {
        guard let data = try data(forKey: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func setString(_ value: String, forKey key: String) throws {
        try set(Data(value.utf8), forKey: key)
    }
}
