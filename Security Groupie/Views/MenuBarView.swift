//
//  MenuBarView.swift
//  Security Groupie
//

import SwiftUI

struct MenuBarView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        Text(appState.statusText)
            .disabled(true)

        if let ip = appState.currentIP {
            Text(ip)
                .disabled(true)
        }

        if let lastUpdated = appState.lastUpdated {
            Text("Updated \(lastUpdated.formatted(.relative(presentation: .named)))")
                .disabled(true)
        }

        Divider()

        Button("Refresh Now") {
            Task {
                await appState.checkAndUpdateIP(force: true)
            }
        }
        .keyboardShortcut("r", modifiers: .command)

        Divider()

        SettingsLink {
            Text("Settings…")
        }
        .keyboardShortcut(",", modifiers: .command)

        Button("Quit") {
            NSApplication.shared.terminate(nil)
        }
        .keyboardShortcut("q", modifiers: .command)
    }
}
