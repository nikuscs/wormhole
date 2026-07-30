import AppKit
import SwiftUI

@main
struct WormholeMenuBarApp: App {
    @StateObject private var model = AppModel()

    init() {
        NSApplication.shared.setActivationPolicy(.accessory)
    }

    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: model)
                .task { await model.runRefreshLoop() }
        } label: {
            MenuBarIconView()
        }
        .menuBarExtraStyle(.menu)
    }
}

struct MenuBarIconView: View {
    var body: some View {
        Group {
            if let image = AppIcon.templateImage {
                Image(nsImage: image)
                    .renderingMode(.template)
            } else {
                Image(systemName: "point.3.connected.trianglepath.dotted")
            }
        }
        .accessibilityLabel("Wormhole")
    }
}

enum AppIcon {
    static let templateImage: NSImage? = {
        guard let url = Bundle.module.url(forResource: "app-icon", withExtension: "svg"),
              let source = NSImage(contentsOf: url)
        else {
            return nil
        }
        let size = NSSize(width: 16, height: 16)
        let image = NSImage(size: size, flipped: false) { bounds in
            source.draw(in: bounds)
            return true
        }
        image.isTemplate = true
        return image
    }()
}
