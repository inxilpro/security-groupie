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

        do {
            let credentials = try await AuthService.shared.credentials(forRegion: settings.awsRegion)

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

        do {
            let credentials = try await AuthService.shared.credentials(forRegion: settings.awsRegion)
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
    private var auth = AuthService.shared
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

                if settings.authMethod == .sso {
                    ssoFields
                } else {
                    accessKeyFields
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

            // Repopulate the account/role pickers when reopening settings in a signed-in session
            if case .signedIn = auth.ssoState, auth.accounts.isEmpty {
                Task {
                    try? await auth.loadAccounts()
                    if !settings.ssoAccountId.isEmpty {
                        try? await auth.loadRoles(accountId: settings.ssoAccountId)
                    }
                }
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

    @ViewBuilder
    private var ssoFields: some View {
        TextField("Start URL", text: Binding(
            get: { settings.ssoStartURL },
            set: { settings.ssoStartURL = $0 }
        ))
        .textFieldStyle(.roundedBorder)
        .help("e.g., https://my-org.awsapps.com/start")
        .onChange(of: settings.ssoStartURL) {
            signOutIfSignedIn()
        }

        TextField("SSO Region", text: Binding(
            get: { settings.ssoRegion },
            set: { settings.ssoRegion = $0 }
        ))
        .textFieldStyle(.roundedBorder)
        .help("Region where IAM Identity Center is deployed, e.g., us-east-1")
        .onChange(of: settings.ssoRegion) {
            signOutIfSignedIn()
        }

        switch auth.ssoState {
        case .signedOut:
            HStack {
                Text("Not signed in")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Sign In") {
                    startSignIn()
                }
                .disabled(settings.ssoStartURL.isEmpty || settings.ssoRegion.isEmpty)
            }

        case .authorizing(let userCode, let verificationURL, _):
            HStack {
                ProgressView()
                    .scaleEffect(0.5)
                Text("Confirm code: \(userCode)")
                    .font(.body.monospaced())
                Spacer()
                Button("Open Browser") {
                    NSWorkspace.shared.open(verificationURL)
                }
                Button("Cancel") {
                    auth.cancelSignIn()
                }
            }

        case .signedIn:
            HStack {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Text("Signed in")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Sign Out") {
                    Task {
                        await auth.signOut()
                    }
                }
            }

            Picker("Account", selection: Binding(
                get: { settings.ssoAccountId },
                set: { settings.ssoAccountId = $0 }
            )) {
                Text("Select an account...").tag("")
                ForEach(auth.accounts) { account in
                    Text("\(account.name) (\(account.id))").tag(account.id)
                }
            }
            .help("AWS account to manage security groups in")
            .onChange(of: settings.ssoAccountId) { _, newValue in
                settings.ssoRoleName = ""
                guard !newValue.isEmpty else { return }
                Task {
                    try? await auth.loadRoles(accountId: newValue)
                }
            }

            if !settings.ssoAccountId.isEmpty {
                Picker("Role", selection: Binding(
                    get: { settings.ssoRoleName },
                    set: { settings.ssoRoleName = $0 }
                )) {
                    Text("Select a role...").tag("")
                    ForEach(auth.roles, id: \.self) { role in
                        Text(role).tag(role)
                    }
                }
                .help("Permission set role to assume")
                .onChange(of: settings.ssoRoleName) {
                    triggerFullFetch()
                }
            }
        }
    }

    @ViewBuilder
    private var accessKeyFields: some View {
        TextField("Access Key ID", text: Binding(
            get: { settings.awsAccessKeyId },
            set: { settings.awsAccessKeyId = $0 }
        ))
        .textFieldStyle(.roundedBorder)
        .onChange(of: settings.awsAccessKeyId) {
            triggerFullFetch()
        }

        SecureField("Secret Access Key", text: Binding(
            get: { auth.accessKeySecret },
            set: { auth.accessKeySecret = $0 }
        ))
        .textFieldStyle(.roundedBorder)
        .onChange(of: auth.accessKeySecret) {
            triggerFullFetch()
        }
    }

    private func startSignIn() {
        connectionState.error = nil
        Task {
            do {
                try await auth.signIn()
                triggerFullFetch()
            } catch {
                connectionState.error = error.localizedDescription
            }
        }
    }

    private func signOutIfSignedIn() {
        // A registration/token minted for a different Identity Center instance is useless
        if case .signedOut = auth.ssoState { return }
        Task {
            await auth.signOut()
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
