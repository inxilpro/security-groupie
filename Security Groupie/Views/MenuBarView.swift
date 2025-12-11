//
//  MenuBarView.swift
//  Security Groupie
//

import SwiftUI

struct MenuBarView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Status section
            HStack {
                Image(systemName: appState.statusIcon)
                Text(appState.statusText)
            }
            .font(.headline)

            Divider()

            // Current IP
            if let ip = appState.currentIP {
                HStack {
                    Text("IP:")
                        .foregroundStyle(.secondary)
                    Text(ip)
                        .fontDesign(.monospaced)
                }
            }

            // Last updated
            if let lastUpdated = appState.lastUpdated {
                HStack {
                    Text("Updated:")
                        .foregroundStyle(.secondary)
                    Text(lastUpdated, style: .relative)
                }
                .font(.caption)
            }

            Divider()

            // Actions
            Button("Check Now") {
                Task {
                    await appState.checkAndUpdateIP()
                }
            }
            .keyboardShortcut("r", modifiers: .command)

            Divider()

            SettingsLink {
                Text("Settings...")
            }
            .keyboardShortcut(",", modifiers: .command)

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: .command)
        }
        .padding(.vertical, 8)
    }
}
