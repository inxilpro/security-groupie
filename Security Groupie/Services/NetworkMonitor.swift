//
//  NetworkMonitor.swift
//  Security Groupie
//

import Foundation
import Network

@Observable
final class NetworkMonitor {
    static let shared = NetworkMonitor()

    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "NetworkMonitor")

    var isConnected: Bool = false
    var connectionType: ConnectionType = .unknown

    enum ConnectionType {
        case wifi
        case cellular
        case wired
        case unknown
    }

    private var onNetworkChange: (() -> Void)?

    private init() {
        monitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                self?.isConnected = path.status == .satisfied
                self?.connectionType = self?.getConnectionType(path) ?? .unknown

                if path.status == .satisfied {
                    self?.onNetworkChange?()
                }
            }
        }
    }

    func startMonitoring(onNetworkChange: @escaping () -> Void) {
        self.onNetworkChange = onNetworkChange
        monitor.start(queue: queue)
    }

    func stopMonitoring() {
        monitor.cancel()
        onNetworkChange = nil
    }

    private func getConnectionType(_ path: NWPath) -> ConnectionType {
        if path.usesInterfaceType(.wifi) {
            return .wifi
        } else if path.usesInterfaceType(.cellular) {
            return .cellular
        } else if path.usesInterfaceType(.wiredEthernet) {
            return .wired
        } else {
            return .unknown
        }
    }
}
