//
  //  TweaksView.swift
  //  lara
  //
  import SwiftUI

  struct TweaksView: View {
      let mgr: laramgr

      var body: some View {
          NavigationStack {
              List {
                  // ── Kernel & MobileGestalt ──────────────────
                  Section(header: Label("Kernel & System", systemImage: "cpu")) {
                      NavigationLink(destination: GestaltView(mgr: mgr)) {
                          TweakRow(icon: "slider.horizontal.3", title: "MobileGestalt", sub: "Override device capability keys")
                      }
                      NavigationLink(destination: dirtyZeroView().environmentObject(mgr)) {
                          TweakRow(icon: "memorychip", title: "Dirty Zero", sub: "Kernel memory tweaks")
                      }
                      NavigationLink(destination: ScreenTimeView(mgr: mgr)) {
                          TweakRow(icon: "hourglass", title: "Screen Time", sub: "Bypass & manage Screen Time")
                      }
                      NavigationLink(destination: DecryptView()) {
                          TweakRow(icon: "lock.open.fill", title: "App Decryptor", sub: "Decrypt app binaries")
                      }
                  }

                  // ── SpringBoard & UI ────────────────────────
                  Section(header: Label("SpringBoard & UI", systemImage: "iphone")) {
                      NavigationLink(destination: SpringBoardView(mgr: mgr)) {
                          TweakRow(icon: "square.grid.3x3.fill", title: "SpringBoard", sub: "SpringBoard patches")
                      }
                      NavigationLink(destination: LiquidGlassView().environmentObject(mgr)) {
                          TweakRow(icon: "drop.fill", title: "Liquid Glass", sub: "Dynamic glass UI effects")
                      }
                      NavigationLink(destination: CardView()) {
                          TweakRow(icon: "creditcard.fill", title: "Card / Shortcuts", sub: "Action card tweaks")
                      }
                      NavigationLink(destination: FontPicker(mgr: mgr)) {
                          TweakRow(icon: "textformat", title: "Font Picker", sub: "Replace system font")
                      }
                      NavigationLink(destination: SystemColor(mgr: mgr)) {
                          TweakRow(icon: "paintpalette.fill", title: "System Color", sub: "Override accent colors")
                      }
                      NavigationLink(destination: PasscodeView(mgr: mgr)) {
                          TweakRow(icon: "lock.fill", title: "Passcode", sub: "Custom passcode UI")
                      }
                  }

                  // ── Apps & Remote ───────────────────────────
                  Section(header: Label("Apps & Remote", systemImage: "app.badge.fill")) {
                      NavigationLink(destination: IPAInstallerView().environmentObject(mgr)) {
                          TweakRow(icon: "arrow.down.app.fill", title: "IPA Installer", sub: "Install IPAs without a PC or store")
                      }
                      NavigationLink(destination: AppsView().environmentObject(mgr)) {
                          TweakRow(icon: "square.stack.3d.up.fill", title: "Apps", sub: "Manage installed apps")
                      }
                      NavigationLink(destination: RemoteView(mgr: mgr)) {
                          TweakRow(icon: "dot.radiowaves.left.and.right", title: "Remote Call", sub: "RC framework control")
                      }
                      NavigationLink(destination: JitView(mgr: mgr)) {
                          TweakRow(icon: "bolt.fill", title: "JIT", sub: "Enable Just-In-Time compilation")
                      }
                  }

                  // ── Filesystem & Tools ──────────────────────
                  Section(header: Label("Filesystem & Tools", systemImage: "folder.fill")) {
                      NavigationLink(destination: ToolsView(mgr: mgr)) {
                          TweakRow(icon: "wrench.and.screwdriver.fill", title: "Tools", sub: "System utilities")
                      }
                      NavigationLink(destination: VarCleanView(mgr: mgr)) {
                          TweakRow(icon: "trash.fill", title: "Var Clean", sub: "Clean /var directories")
                      }
                      NavigationLink(destination: OTAView(mgr: mgr)) {
                          TweakRow(icon: "arrow.down.circle.fill", title: "OTA", sub: "Over-the-air update control")
                      }
                      NavigationLink(destination: CustomView(mgr: mgr)) {
                          TweakRow(icon: "doc.badge.gearshape.fill", title: "Custom Overwrite", sub: "Custom file overwrite")
                      }
                      NavigationLink(destination: WhitelistView(mgr: mgr)) {
                          TweakRow(icon: "list.bullet.rectangle.fill", title: "Whitelist", sub: "App whitelist manager")
                      }
                  }
              }
              .navigationTitle("Tweaks")
              .listStyle(.insetGrouped)
          }
      }
  }

  struct TweakRow: View {
      let icon: String
      let title: String
      let sub: String

      var body: some View {
          Label {
              VStack(alignment: .leading, spacing: 2) {
                  Text(title).font(.body)
                  Text(sub).font(.caption).foregroundStyle(.secondary)
              }
          } icon: {
              Image(systemName: icon)
                  .foregroundStyle(.tint)
                  .frame(width: 28, height: 28)
          }
      }
  }
  