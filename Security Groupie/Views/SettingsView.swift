//
//  SettingsView.swift
//  Security Groupie
//

import SwiftUI
import ServiceManagement

@Observable
class AWSConnectionState {
    static let shared = AWSConnectionState()

    var regions: [AWSRegionInfo] = []
    var securityGroups: [SecurityGroupInfo] = []
    var isLoading = false
    var error: String?

    private init() {}

    private func makeCredentials(forRegion region: String? = nil) -> AWSCredentials? {
        let settings = AppSettings.shared
        let awsConfig = AWSConfigService.shared

        let accessKeyId: String
        let secretAccessKey: String

        if settings.authMethod == .profile {
            guard let profileCreds = awsConfig.credentials(for: settings.awsProfile) else {
                return nil
            }
            accessKeyId = profileCreds.accessKeyId
            secretAccessKey = profileCreds.secretAccessKey
        } else {
            guard !settings.awsAccessKeyId.isEmpty && !settings.awsSecretAccessKey.isEmpty else {
                return nil
            }
            accessKeyId = settings.awsAccessKeyId
            secretAccessKey = settings.awsSecretAccessKey
        }

        return AWSCredentials(
            accessKeyId: accessKeyId,
            secretAccessKey: secretAccessKey,
            region: region ?? settings.awsRegion
        )
    }

    func fetchAll() async {
        let settings = AppSettings.shared

        guard settings.hasValidAuth else {
            regions = []
            securityGroups = []
            error = nil
            return
        }

        isLoading = true
        error = nil

        guard let credentials = makeCredentials() else {
            isLoading = false
            return
        }

        do {
            // Fetch regions and security groups in parallel
            async let regionsTask = EC2Service.shared.fetchRegions(credentials: credentials)
            async let groupsTask = EC2Service.shared.fetchSecurityGroups(credentials: credentials)

            let (fetchedRegions, fetchedGroups) = try await (regionsTask, groupsTask)
            regions = fetchedRegions
            securityGroups = fetchedGroups
            error = nil
        } catch {
            securityGroups = []
            self.error = error.localizedDescription
        }

        isLoading = false
    }

    func fetchSecurityGroups() async {
        let settings = AppSettings.shared

        guard settings.hasValidAuth else {
            securityGroups = []
            error = nil
            return
        }

        isLoading = true
        error = nil

        guard let credentials = makeCredentials() else {
            isLoading = false
            return
        }

        do {
            let groups = try await EC2Service.shared.fetchSecurityGroups(credentials: credentials)
            securityGroups = groups
            error = nil
        } catch {
            securityGroups = []
            self.error = error.localizedDescription
        }

        isLoading = false
    }
}

struct SettingsView: View {
    @Environment(AppState.self) private var appState
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    private var settings = AppSettings.shared
    private var awsConfig = AWSConfigService.shared
    private var connectionState = AWSConnectionState.shared

    var body: some View {
        Form {
            // General Section
            Section("General") {
                Toggle("Launch at Login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in
                        do {
                            if newValue {
                                try SMAppService.mainApp.register()
                            } else {
                                try SMAppService.mainApp.unregister()
                            }
                        } catch {
                            print("Failed to \(newValue ? "enable" : "disable") launch at login: \(error)")
                            // Revert the toggle if it failed
                            launchAtLogin = !newValue
                        }
                    }
            }

            // AWS Connection Section
            Section("AWS Connection") {
                if connectionState.regions.isEmpty {
                    TextField("Region", text: Binding(
                        get: { settings.awsRegion },
                        set: { settings.awsRegion = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .help("e.g., us-east-1")
                    .onChange(of: settings.awsRegion) {
                        triggerSecurityGroupsFetch()
                    }
                } else {
                    Picker("Region", selection: Binding(
                        get: { settings.awsRegion },
                        set: { settings.awsRegion = $0 }
                    )) {
                        ForEach(connectionState.regions) { region in
                            Text(region.displayName).tag(region.id)
                        }
                    }
                    .help("Select your AWS region")
                    .onChange(of: settings.awsRegion) {
                        triggerSecurityGroupsFetch()
                    }
                }

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
                    .onChange(of: settings.authMethod) {
                        triggerFullFetch()
                    }
                }

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
                    .onChange(of: settings.awsProfile) {
                        triggerFullFetch()
                    }
                } else {
                    TextField("Access Key ID", text: Binding(
                        get: { settings.awsAccessKeyId },
                        set: { settings.awsAccessKeyId = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: settings.awsAccessKeyId) {
                        triggerFullFetch()
                    }

                    SecureField("Secret Access Key", text: Binding(
                        get: { settings.awsSecretAccessKey },
                        set: { settings.awsSecretAccessKey = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: settings.awsSecretAccessKey) {
                        triggerFullFetch()
                    }
                }

                // Connection status
                HStack {
                    if connectionState.isLoading {
                        ProgressView()
                            .scaleEffect(0.5)
                        Text("Connecting...")
                            .foregroundStyle(.secondary)
                    } else if let error = connectionState.error {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.caption)
                            .lineLimit(2)
                    } else if !connectionState.securityGroups.isEmpty {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                        Text("Connected")
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Button("Test Connection") {
                        triggerFullFetch()
                    }
                    .disabled(connectionState.isLoading || !settings.hasValidAuth)
                }
            }

            // Security Group Section
            Section("Security Group") {
                if connectionState.securityGroups.isEmpty {
                    TextField("Security Group ID", text: Binding(
                        get: { settings.securityGroupId },
                        set: { settings.securityGroupId = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .help("e.g., sg-0123456789abcdef0")
                } else {
                    Picker("Security Group", selection: Binding(
                        get: { settings.securityGroupId },
                        set: { settings.securityGroupId = $0 }
                    )) {
                        Text("Select a security group...").tag("")
                        ForEach(connectionState.securityGroups) { sg in
                            Text(sg.displayName).tag(sg.id)
                        }
                    }
                    .help("Select from your AWS security groups")
                }

                TextField("Port", value: Binding(
                    get: { settings.port },
                    set: { settings.port = $0 }
                ), format: .number)
                .textFieldStyle(.roundedBorder)
                .help("The port to allow (default: 22 for SSH)")
            }

            // Device Section
            Section("Device") {
                TextField("Device Name", text: Binding(
                    get: { settings.deviceNickname },
                    set: { settings.deviceNickname = $0 }
                ))
                .textFieldStyle(.roundedBorder)
                .help("Used to identify this device's rule in the security group")

                if let error = settings.deviceNameValidationError(settings.deviceNickname) {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text(error)
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                } else {
                    Text("Allowed: letters, numbers, spaces, and ._-:/()#,@[]+=;{}!$*")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
            }
        }
        .formStyle(.grouped)
        .padding()
        .frame(width: 600, height: 540)
        .onAppear {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)

            // Set the app icon explicitly for the Dock
            if let appIcon = NSImage(named: NSImage.applicationIconName) {
                NSApp.applicationIconImage = appIcon
            }

            // If no config file exists, force access key method
            if !awsConfig.hasConfigFile {
                settings.authMethod = .accessKey
            }
            // Fetch regions and security groups on appear if we have credentials
            if settings.hasValidAuth {
                triggerFullFetch()
            }
            // Refresh IP immediately when settings opens
            Task {
                await AppState.shared.handleManualRefresh()
            }
        }
        .onDisappear {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    private func triggerFullFetch() {
        Task {
            await connectionState.fetchAll()
        }
    }

    private func triggerSecurityGroupsFetch() {
        Task {
            await connectionState.fetchSecurityGroups()
        }
    }
}
