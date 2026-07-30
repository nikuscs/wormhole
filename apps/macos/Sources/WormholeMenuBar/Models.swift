import Foundation

struct DaemonStatus: Decodable, Equatable {
    let version: String
    let uptimeSeconds: Int
    let pid: Int
    let services: Int
    let endpoints: Int

    enum CodingKeys: String, CodingKey {
        case version, pid, services, endpoints
        case uptimeSeconds = "uptime_seconds"
    }
}

enum EndpointStatus: Decodable, Equatable {
    case online
    case reconnecting
    case offline
    case error(String)

    init(from decoder: Decoder) throws {
        if let value = try? decoder.singleValueContainer().decode(String.self) {
            switch value {
            case "online": self = .online
            case "reconnecting": self = .reconnecting
            case "offline": self = .offline
            default: self = .error(value)
            }
            return
        }
        let value = try decoder.singleValueContainer().decode([String: String].self)
        self = .error(value["error"] ?? "Unknown error")
    }

    var label: String {
        switch self {
        case .online: "Online"
        case .reconnecting: "Reconnecting"
        case .offline: "Offline"
        case .error: "Error"
        }
    }

    var symbol: String {
        switch self {
        case .online: "checkmark.circle.fill"
        case .reconnecting: "arrow.triangle.2.circlepath.circle.fill"
        case .offline: "pause.circle.fill"
        case .error: "exclamationmark.triangle.fill"
        }
    }

    var detail: String? {
        guard case let .error(message) = self else { return nil }
        return message
    }
}

struct Endpoint: Decodable, Identifiable, Equatable {
    let id: UUID
    let service: String
    let driver: String
    let urls: [String]
    let status: EndpointStatus
    let bufferedDelivered: UInt64
    let bufferedPending: UInt32
    let bufferedFailed: UInt32

    enum CodingKeys: String, CodingKey {
        case id, service, driver, urls, status
        case bufferedDelivered = "buffered_delivered"
        case bufferedPending = "buffered_pending"
        case bufferedFailed = "buffered_failed"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        service = try values.decode(String.self, forKey: .service)
        driver = try values.decode(String.self, forKey: .driver)
        urls = try values.decode([String].self, forKey: .urls)
        status = try values.decode(EndpointStatus.self, forKey: .status)
        bufferedDelivered = try values.decodeIfPresent(UInt64.self, forKey: .bufferedDelivered) ?? 0
        bufferedPending = try values.decodeIfPresent(UInt32.self, forKey: .bufferedPending) ?? 0
        bufferedFailed = try values.decodeIfPresent(UInt32.self, forKey: .bufferedFailed) ?? 0
    }
}
