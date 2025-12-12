//
//  INIParser.swift
//  Security Groupie
//

import Foundation

/// A simple INI file parser
struct INIParser {
    /// Parsed sections with their key-value pairs
    let sections: [String: [String: String]]

    /// Initialize by parsing INI content from a string
    init(content: String) {
        self.sections = Self.parse(content: content)
    }

    /// Initialize by parsing INI content from a file URL
    init?(url: URL) {
        guard let content = try? String(contentsOf: url, encoding: .utf8) else {
            return nil
        }
        self.init(content: content)
    }

    /// Get a value from a specific section
    func value(forKey key: String, inSection section: String) -> String? {
        sections[section]?[key.lowercased()]
    }

    /// Get all keys in a section
    func keys(inSection section: String) -> [String] {
        sections[section].map { Array($0.keys) } ?? []
    }

    /// Get all section names
    var sectionNames: [String] {
        Array(sections.keys)
    }

    // MARK: - Private parsing

    private static func parse(content: String) -> [String: [String: String]] {
        var result: [String: [String: String]] = [:]
        var currentSection: String?
        var currentValues: [String: String] = [:]

        let lines = content.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip empty lines and comments
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") {
                continue
            }

            // Check for section header
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                // Save previous section
                if let section = currentSection, !currentValues.isEmpty {
                    result[section] = currentValues
                }

                // Start new section
                currentSection = String(trimmed.dropFirst().dropLast())
                currentValues = [:]
            } else if let (key, value) = parseKeyValue(trimmed) {
                // Store key in lowercase for case-insensitive lookup
                currentValues[key.lowercased()] = value
            }
        }

        // Save last section
        if let section = currentSection, !currentValues.isEmpty {
            result[section] = currentValues
        }

        return result
    }

    private static func parseKeyValue(_ line: String) -> (String, String)? {
        guard let equalsIndex = line.firstIndex(of: "=") else {
            return nil
        }
        let key = String(line[..<equalsIndex]).trimmingCharacters(in: .whitespaces)
        let value = String(line[line.index(after: equalsIndex)...]).trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty && !value.isEmpty else {
            return nil
        }
        return (key, value)
    }
}
