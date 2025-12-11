//
//  SettingsView.swift
//  Security Groupie
//

import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            AWSSettingsView()
                .tabItem {
                    Label("AWS", systemImage: "cloud")
                }
        }
        .frame(width: 450, height: 300)
        .onAppear {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
        }
        .onDisappear {
            NSApp.setActivationPolicy(.accessory)
        }
    }
}

struct GeneralSettingsView: View {
    private var settings = AppSettings.shared

    var body: some View {
        Form {
            Section {
                TextField("Security Group ID", text: Binding(
                    get: { settings.securityGroupId },
                    set: { settings.securityGroupId = $0 }
                ))
                .textFieldStyle(.roundedBorder)
                .help("e.g., sg-0123456789abcdef0")

                TextField("Port", value: Binding(
                    get: { settings.port },
                    set: { settings.port = $0 }
                ), format: .number)
                .textFieldStyle(.roundedBorder)
                .help("The port to allow (default: 22 for SSH)")

                TextField("Device Name", text: Binding(
                    get: { settings.deviceNickname },
                    set: { settings.deviceNickname = $0 }
                ))
                .textFieldStyle(.roundedBorder)
                .help("Used to identify this device's rule in the security group")
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

struct AWSSettingsView: View {
    private var settings = AppSettings.shared
    private var awsConfig = AWSConfigService.shared

    var body: some View {
        Form {
            Section {
                TextField("Region", text: Binding(
                    get: { settings.awsRegion },
                    set: { settings.awsRegion = $0 }
                ))
                .textFieldStyle(.roundedBorder)
                .help("e.g., us-east-1")

                if awsConfig.hasConfigFile {
                    Picker("Authentication", selection: Binding(
                        get: { settings.authMethod },
                        set: { settings.authMethod = $0 }
                    )) {
                        ForEach(AWSAuthMethod.allCases, id: \.self) { method in
                            Text(method.displayName).tag(method)
                        }
                    }
                    .pickerStyle(.segmented)
                }
            }

            Section {
                if awsConfig.hasConfigFile && settings.authMethod == .profile {
                    Picker("Profile", selection: Binding(
                        get: { settings.awsProfile },
                        set: { settings.awsProfile = $0 }
                    )) {
                        ForEach(awsConfig.profiles, id: \.self) { profile in
                            Text(profile).tag(profile)
                        }
                    }
                    .help("AWS profile from ~/.aws/credentials")

                    Button("Refresh Profiles") {
                        awsConfig.reload()
                    }
                    .buttonStyle(.link)
                } else {
                    TextField("Access Key ID", text: Binding(
                        get: { settings.awsAccessKeyId },
                        set: { settings.awsAccessKeyId = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)

                    SecureField("Secret Access Key", text: Binding(
                        get: { settings.awsSecretAccessKey },
                        set: { settings.awsSecretAccessKey = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                }
            }
        }
        .formStyle(.grouped)
        .padding()
        .onAppear {
            // If no config file exists, force access key method
            if !awsConfig.hasConfigFile {
                settings.authMethod = .accessKey
            }
        }
    }
}
