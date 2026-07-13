//
//  CCView.swift
//  lara
//
//  Control Center tweaks via GlobalPreferences plist overwrite.
//  Uses the same lara_overwritefile pattern as LiquidGlassView.
//
//  Supported tweaks (all toggle-based, applied on reboot/respring):
//    • Layout     — CC swipe direction, portrait lock indicator
//    • Modules    — always-show WiFi/BT details, battery %, NFC
//    • Appearance — disable CC blur, dark status bar in CC
//    • Behaviour  — disable CC on Lock Screen, disable CC in apps
//
//  Created by ruter on 16.04.26.
//

import SwiftUI

// MARK: - Path constants (gpCurrentPath is declared in LiquidGlassView.swift at module scope)

private let ccPrefsPath = "/var/mobile/Library/Preferences/com.apple.controlcenter.plist"
private let sbPrefsPath = "/var/mobile/Library/Preferences/com.apple.springboard.plist"

// MARK: - View

struct CCView: View {
    @EnvironmentObject private var mgr: laramgr

    // Global Preferences dict (shared with LiquidGlass writer)
    @State private var gpDict: NSMutableDictionary = NSMutableDictionary()
    // SpringBoard prefs dict (for lock-screen / in-app CC flags)
    @State private var sbDict: NSMutableDictionary = NSMutableDictionary()

    @State private var refresh: Bool = false
    @State private var isApplying: Bool = false

    var body: some View {
        NavigationStack {
            List {

                // ── Apply / Reset ──────────────────────────────────────────
                Section {
                    Button {
                        applyTweaks()
                    } label: {
                        Label("Apply Tweaks", systemImage: "checkmark.circle")
                    }
                    .disabled(isApplying)

                    Button(role: .destructive) {
                        resetTweaks()
                    } label: {
                        Label("Reset to Defaults", systemImage: "arrow.counterclockwise")
                    }
                    .disabled(isApplying)
                } header: {
                    Text("RespringCC")
                } footer: {
                    Text("Uses lara's respring helper. Changes take effect after a respring or reboot.")
                }

                // ── Appearance ─────────────────────────────────────────────
                Section(
                    header: HeaderLabel(text: "Appearance", icon: "paintbrush"),
                    footer: Text("Disabling the blur gives CC a solid dark background (useful on OLED displays).")
                ) {
                    Toggle("Disable CC Background Blur",
                           isOn: gpBool("SBControlCenterDisableBlurring"))
                    Toggle("Dark Status Bar in CC",
                           isOn: gpBool("SBControlCenterForceDarkStatusBar"))
                    Toggle("Disable Specular Motion in CC",
                           isOn: gpBool("SBDisableSpecularEverywhereUsingLSSAssertion"))
                }

                // ── Modules ────────────────────────────────────────────────
                Section(
                    header: HeaderLabel(text: "Modules", icon: "square.grid.2x2"),
                    footer: Text("Force-show WiFi & Bluetooth detail labels and always display battery percentage.")
                ) {
                    Toggle("Show WiFi Network Name",
                           isOn: gpBool("SBCCWiFiModuleShowNetworkName"))
                    Toggle("Show Bluetooth Device Name",
                           isOn: gpBool("SBCCBluetoothModuleShowDeviceName"))
                    Toggle("Always Show Battery Percentage",
                           isOn: gpBool("SBShowBatteryLevel", inDict: &sbDict))
                    Toggle("Show NFC Button",
                           isOn: gpBool("SBCCShowNFCModule"))
                    Toggle("Show Screen Recording Button",
                           isOn: gpBool("SBCCShowScreenRecordingModule", inDict: &sbDict))
                }

                // ── Behaviour ──────────────────────────────────────────────
                Section(
                    header: HeaderLabel(text: "Behaviour", icon: "hand.tap"),
                    footer: Text("Restricting CC access on the Lock Screen prevents CC from appearing before unlock.")
                ) {
                    Toggle("Disable CC on Lock Screen",
                           isOn: sbBool("SBControlCenterEnabledInLockScreen", invert: true))
                    Toggle("Disable CC in Apps",
                           isOn: sbBool("SBControlCenterEnabledInApps", invert: true))
                    Toggle("Dismiss CC on Tap Outside",
                           isOn: gpBool("SBControlCenterDismissOnOutsideTap"))
                }

                // ── Layout ─────────────────────────────────────────────────
                Section(
                    header: HeaderLabel(text: "Layout", icon: "slider.horizontal.3"),
                    footer: Text("Portrait Lock indicator shows a padlock badge on the rotation lock CC button.")
                ) {
                    Toggle("Show Portrait Lock Indicator",
                           isOn: gpBool("SBCCShowPortraitLockIndicator"))
                    Toggle("Compact CC Header",
                           isOn: gpBool("SBCCUseCompactHeader"))
                    Toggle("Haptic Feedback on CC Toggle",
                           isOn: gpBool("SBCCHapticsEnabled", default: true))
                }

            }
            .navigationTitle("Control Center")
            .onAppear { loadData() }
        }
    }

    // MARK: – Data loading

    private func loadData() {
        let docsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

        // Load GlobalPreferences plist (create backup if needed)
        let gpSaved = docsDir.appendingPathComponent("SavedGPForCC.plist")
        let gpURL   = URL(fileURLWithPath: gpCurrentPath)
        do {
            if !FileManager.default.fileExists(atPath: gpSaved.path) {
                try FileManager.default.copyItem(at: gpURL, to: gpSaved)
            }
            chmod(gpSaved.path, 0o644)
            gpDict = (try NSMutableDictionary(contentsOf: gpURL, error: ())) 
        } catch {
            Alertinator.shared.alert(
                title: "Failed to load GlobalPreferences",
                body: "Please restart the app and try again.\n\(error)")
        }

        // Load SpringBoard prefs
        let sbURL = URL(fileURLWithPath: sbPrefsPath)
        let sbSaved = docsDir.appendingPathComponent("SavedSBForCC.plist")
        do {
            if !FileManager.default.fileExists(atPath: sbSaved.path) {
                try? FileManager.default.copyItem(at: sbURL, to: sbSaved)
            }
            sbDict = (try NSMutableDictionary(contentsOf: sbURL, error: ()))
        } catch {
            sbDict = NSMutableDictionary()
        }
    }

    // MARK: – Apply / Reset

    private func applyTweaks() {
        isApplying = true
        defer { isApplying = false }

        do {
            // Write GlobalPreferences
            let gpData = try verifyPlist(gpDict, targetPath: gpCurrentPath)
            let gpResult = mgr.lara_overwritefile(target: gpCurrentPath, data: gpData)
            guard gpResult.ok else { throw "GP overwrite failed: \(gpResult.message)" }

            // Write SpringBoard prefs (contains lock-screen and battery flags)
            let sbData = try verifyPlist(sbDict, targetPath: sbPrefsPath)
            let sbResult = mgr.lara_overwritefile(target: sbPrefsPath, data: sbData)
            if !sbResult.ok {
                // Non-fatal: SB prefs may be guarded by sandbox on some builds
                Alertinator.shared.alert(
                    title: "Partial Success",
                    body: "GlobalPreferences applied. SpringBoard prefs could not be written (\(sbResult.message)). Battery % and lock-screen CC toggles may not take effect.")
                return
            }

            Alertinator.shared.alert(
                title: "CC Tweaks Applied",
                body: "Respring your device to see the changes.")
        } catch {
            Alertinator.shared.alert(
                title: "Failed to Apply CC Tweaks",
                body: "\(error)")
        }
    }

    private func resetTweaks() {
        let docsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let gpSaved = docsDir.appendingPathComponent("SavedGPForCC.plist")
        let sbSaved = docsDir.appendingPathComponent("SavedSBForCC.plist")

        do {
            if FileManager.default.fileExists(atPath: gpSaved.path) {
                gpDict = try NSMutableDictionary(contentsOf: gpSaved, error: ())
            }
            if FileManager.default.fileExists(atPath: sbSaved.path) {
                sbDict = try NSMutableDictionary(contentsOf: sbSaved, error: ())
            }
            applyTweaks()
        } catch {
            Alertinator.shared.alert(
                title: "Failed to Reset CC Tweaks",
                body: "\(error)")
        }
    }

    // MARK: – Bindings

    /// Bool binding backed by any NSMutableDictionary (reference type — no inout needed)
    private func gpBool(
        _ key: String,
        inDict dictRef: NSMutableDictionary,
        default defaultVal: Bool = false,
        enable: Bool = true
    ) -> Binding<Bool> {
        Binding(
            get: {
                _ = refresh
                return (dictRef[key] as? Bool ?? defaultVal) == enable
            },
            set: { on in
                refresh.toggle()
                if on { dictRef[key] = enable } else { dictRef.removeObject(forKey: key) }
            }
        )
    }

    /// Convenience overload that defaults to gpDict
    private func gpBool(
        _ key: String,
        default defaultVal: Bool = false,
        enable: Bool = true
    ) -> Binding<Bool> {
        gpBool(key, inDict: gpDict, default: defaultVal, enable: enable)
    }

    /// Bool binding backed by sbDict (SpringBoard prefs), with optional invert
    private func sbBool(_ key: String, invert: Bool = false) -> Binding<Bool> {
        Binding(
            get: {
                _ = refresh
                let raw = sbDict[key] as? Bool ?? true
                return invert ? !raw : raw
            },
            set: { on in
                refresh.toggle()
                let stored = invert ? !on : on
                sbDict[key] = stored
            }
        )
    }
}

#Preview {
    CCView()
        .environmentObject(laramgr())
}
