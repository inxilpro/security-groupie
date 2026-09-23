//
//  UpdaterController.swift
//  Security Groupie
//

import Combine
import Foundation
import Observation
import Sparkle

/// Owns the one Sparkle updater for the app's lifetime.
@Observable
final class UpdaterController {
    static let shared = UpdaterController()

    private(set) var canCheckForUpdates = false

    var automaticallyChecksForUpdates: Bool {
        didSet { controller.updater.automaticallyChecksForUpdates = automaticallyChecksForUpdates }
    }

    /// Only Release builds check the feed: a Debug build would offer to replace itself with the
    /// published release, and unit tests (hosted in the app) must never touch the network.
    static var isEnabled: Bool {
        #if DEBUG
        false
        #else
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil
        #endif
    }

    @ObservationIgnored private let controller: SPUStandardUpdaterController
    @ObservationIgnored private var canCheckSubscription: AnyCancellable?

    private init() {
        controller = SPUStandardUpdaterController(
            startingUpdater: Self.isEnabled,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
        automaticallyChecksForUpdates = controller.updater.automaticallyChecksForUpdates
        canCheckSubscription = controller.updater.publisher(for: \.canCheckForUpdates)
            .sink { [weak self] in self?.canCheckForUpdates = $0 }
    }

    func checkForUpdates() {
        controller.checkForUpdates(nil)
    }
}
