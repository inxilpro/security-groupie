//
//  IPService.swift
//  Security Groupie
//

import Foundation

actor IPService {
    static let shared = IPService()

    private let ipProviders: [URL] = [
        URL(string: "https://checkip.amazonaws.com")!,
        URL(string: "https://api.ipify.org")!,
        URL(string: "https://icanhazip.com")!,
    ]

    private init() {}

    func fetchCurrentIP() async throws -> String {
        var lastError: Error?

        for providerURL in ipProviders {
            do {
                let ip = try await fetchIP(from: providerURL)
                return ip
            } catch {
                lastError = error
                continue
            }
        }

        throw lastError ?? IPServiceError.noProvidersAvailable
    }

    private func fetchIP(from url: URL) async throws -> String {
        let (data, response) = try await URLSession.shared.data(from: url)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw IPServiceError.invalidResponse
        }

        guard let ipString = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !ipString.isEmpty else {
            throw IPServiceError.invalidIPFormat
        }

        guard isValidIPv4(ipString) else {
            throw IPServiceError.invalidIPFormat
        }

        return ipString
    }

    private func isValidIPv4(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return false }

        return parts.allSatisfy { part in
            guard let num = Int(part), num >= 0, num <= 255 else { return false }
            return true
        }
    }
}

enum IPServiceError: LocalizedError {
    case noProvidersAvailable
    case invalidResponse
    case invalidIPFormat

    var errorDescription: String? {
        switch self {
        case .noProvidersAvailable:
            return "No IP providers available"
        case .invalidResponse:
            return "Invalid response from IP provider"
        case .invalidIPFormat:
            return "Invalid IP address format"
        }
    }
}
