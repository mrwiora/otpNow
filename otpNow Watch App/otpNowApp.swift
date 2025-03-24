import SwiftUI
import WatchConnectivity

// MARK: - Data Models

enum OTPType: String, Codable {
    case totp, hotp
}

// Update OTPCodeInfo to include group color information
struct OTPCodeInfo: Identifiable, Codable, Equatable {
    var id: UUID
    var name: String
    var type: OTPType
    var digits: Int
    var currentCode: String
    var previousCode: String?
    var nextCode: String?
    var timeRemaining: Int?
    var period: Int?
    var counter: Int?
    var groupColorHex: String? // New field for group color
    
    static func == (lhs: OTPCodeInfo, rhs: OTPCodeInfo) -> Bool {
        lhs.id == rhs.id &&
        lhs.name == rhs.name &&
        lhs.type == rhs.type &&
        lhs.digits == rhs.digits &&
        lhs.currentCode == rhs.currentCode &&
        lhs.previousCode == rhs.previousCode &&
        lhs.nextCode == rhs.nextCode &&
        lhs.timeRemaining == rhs.timeRemaining &&
        lhs.period == rhs.period &&
        lhs.counter == rhs.counter &&
        lhs.groupColorHex == rhs.groupColorHex
    }
}

// Color utility extension for Watch
extension Color {
    init(hex: String?) {
        guard let hex = hex else {
            self.init(.gray)
            return
        }
        
        let trimmedHex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: trimmedHex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch trimmedHex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

// MARK: - Store for Watch App

class WatchOTPStore: NSObject, ObservableObject, WCSessionDelegate {
    @Published var codeInfos: [OTPCodeInfo] = []
    private var isConnectedToPhone = false
    
    private let saveKey = "watchOTPCodeInfos"
    
    override init() {
        super.init()
        setupWatchConnectivity()
        load()
    }
    
    private func setupWatchConnectivity() {
        guard WCSession.isSupported() else { return }
        
        WCSession.default.delegate = self
        WCSession.default.activate()
    }
    
    func incrementHOTPCounter(_ codeInfo: OTPCodeInfo) {
        if let index = codeInfos.firstIndex(where: { $0.id == codeInfo.id }),
           codeInfos[index].type == .hotp,
           let counter = codeInfos[index].counter {
            
            if WCSession.default.isReachable {
                WCSession.default.sendMessage(
                    ["action": "incrementCounter", "secretId": codeInfo.id.uuidString],
                    replyHandler: nil
                )
                
                codeInfos[index].counter = counter + 1
            }
        }
    }
    
    func requestUpdate() {
        if WCSession.default.isReachable {
            WCSession.default.sendMessage(["action": "requestUpdate"], replyHandler: nil)
        }
    }
    
    private func save() {
        if let encoded = try? JSONEncoder().encode(codeInfos) {
            UserDefaults.standard.set(encoded, forKey: saveKey)
        }
    }
    
    private func load() {
        if let data = UserDefaults.standard.data(forKey: saveKey),
           let decoded = try? JSONDecoder().decode([OTPCodeInfo].self, from: data) {
            codeInfos = decoded
        }
    }
    
    private func refreshConnectionStatus() {
        guard WCSession.isSupported() else {
            isConnectedToPhone = false
            return
        }
        
        isConnectedToPhone = WCSession.default.activationState == .activated
        
        if isConnectedToPhone && WCSession.default.isReachable {
            requestUpdate()
        }
    }
    
    // MARK: - WCSessionDelegate Methods
    
    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        DispatchQueue.main.async {
            self.isConnectedToPhone = activationState == .activated
            if self.isConnectedToPhone {
                self.requestUpdate()
            }
        }
    }
    
    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any]) {
        if let codeInfosData = userInfo["codeInfos"] as? Data,
           let decodedCodeInfos = try? JSONDecoder().decode([OTPCodeInfo].self, from: codeInfosData) {
            DispatchQueue.main.async {
                self.codeInfos = decodedCodeInfos
                self.save()
            }
        }
    }
    
    func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        if let codeInfosData = message["codeInfos"] as? Data,
           let decodedCodeInfos = try? JSONDecoder().decode([OTPCodeInfo].self, from: codeInfosData) {
            DispatchQueue.main.async {
                self.codeInfos = decodedCodeInfos
                self.save()
            }
        }
    }
}

// MARK: - Time Remaining Indicator

struct WatchTimeRemainingView: View {
    let codeInfo: OTPCodeInfo
    @State private var timeRemaining: Int
    @State private var period: Int
    
    init(codeInfo: OTPCodeInfo) {
        self.codeInfo = codeInfo
        self._timeRemaining = State(initialValue: codeInfo.timeRemaining ?? 30)
        self._period = State(initialValue: codeInfo.period ?? 30)
    }
    
    let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(lineWidth: 2)
                .opacity(0.3)
                .foregroundColor(.gray)
            
            Circle()
                .trim(from: 0.0, to: max(0, CGFloat(timeRemaining)) / CGFloat(period))
                .stroke(style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                .foregroundColor(timeRemaining > 5 ? .blue : .red)
                .rotationEffect(.degrees(-90))
                .animation(.linear, value: timeRemaining)
        }
        .frame(width: 20, height: 20)
        .onReceive(timer) { _ in
            if timeRemaining > 0 {
                timeRemaining -= 1
            } else {
                timeRemaining = period
            }
        }
        .onChange(of: codeInfo.timeRemaining) { oldValue, newValue in
            if let newTime = newValue {
                timeRemaining = newTime
            }
        }
    }
}

// MARK: - Updated List Item View with group colors

struct WatchOTPListRow: View {
    let codeInfo: OTPCodeInfo
    @State private var refreshID = UUID()
    
    var body: some View {
        HStack {
            // Add a small colored circle for the group if available
            if let colorHex = codeInfo.groupColorHex {
                Circle()
                    .fill(Color(hex: colorHex))
                    .frame(width: 8, height: 8)
                    .padding(.trailing, 2)
            } else {
                Circle()
                    .stroke(Color.white, lineWidth: 1)
                    .frame(width: 8, height: 8)
                    .padding(.trailing, 2)
            }
                
            VStack(alignment: .leading) {
                Text(codeInfo.name)
                    .font(.caption)
                    .lineLimit(1)
                
                Text(codeInfo.currentCode)
                    .font(.system(.body, design: .monospaced))
                    .bold()
                    .id("list_\(refreshID)")
            }
            
            Spacer()
            
            if codeInfo.type == .totp {
                WatchTimeRemainingView(codeInfo: codeInfo)
                    .id("list_timer_\(refreshID)")
            } else {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.footnote)
            }
        }
        .listRowBackground(
            RoundedRectangle(cornerRadius: 8)
                .fill(backgroundColorForGroup)
                .padding(2)
        )
        .onChange(of: codeInfo) { oldValue, newValue in
            refreshID = UUID()
        }
    }
    
    // Background color based on group
    private var backgroundColorForGroup: Color {
        if let colorHex = codeInfo.groupColorHex {
            // Use a lighter version of the group color for the background
            return Color(hex: colorHex).opacity(0.2)
        } else {
            // Default background if no group assigned
            return Color.clear
        }
    }
}

// MARK: - Updated Detail View with group colors

struct WatchOTPDetailView: View {
    @ObservedObject var store: WatchOTPStore
    let codeInfo: OTPCodeInfo
    @State private var refreshID = UUID()
    
    let timer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()
    
    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                if codeInfo.type == .totp {
                    // Next code (top)
                    VStack(spacing: 2) {
                        Text("Next")
                            .font(.footnote)
                            .foregroundColor(.gray)
                        Text(codeInfo.nextCode ?? "")
                            .font(.system(.body, design: .monospaced))
                            .foregroundColor(.gray)
                            .id("next_\(refreshID)")
                    }
                    .padding(.vertical, 2)
                    
                    // Current code (middle)
                    VStack(spacing: 2) {
                        HStack {
                            Text("Current")
                                .font(.footnote)
                                .bold()
                            WatchTimeRemainingView(codeInfo: codeInfo)
                                .id("timer_\(refreshID)")
                        }
                        Text(codeInfo.currentCode)
                            .font(.system(.title3, design: .monospaced))
                            .bold()
                            .id("current_\(refreshID)")
                    }
                    .padding(.vertical, 6)
                    
                    // Previous code (bottom)
                    VStack(spacing: 2) {
                        Text("Previous")
                            .font(.footnote)
                            .foregroundColor(.gray)
                        Text(codeInfo.previousCode ?? "")
                            .font(.system(.body, design: .monospaced))
                            .foregroundColor(.gray)
                            .id("prev_\(refreshID)")
                    }
                    .padding(.vertical, 2)
                } else {
                    // HOTP
                    VStack {
                        Text(codeInfo.currentCode)
                            .font(.system(.title2, design: .monospaced))
                            .bold()
                            .id("hotp_\(refreshID)")
                        
                        Button("Next Code") {
                            store.incrementHOTPCounter(codeInfo)
                        }
                        .padding(.top, 8)
                    }
                }
            }
            .padding()
        }
        .onReceive(timer) { _ in
            store.requestUpdate()
        }
        .onAppear {
            store.requestUpdate()
        }
        .onChange(of: codeInfo) { oldValue, newValue in
            refreshID = UUID()
        }
    }
    
    // Background color based on group
    private var backgroundColorForGroup: Color {
        if let colorHex = codeInfo.groupColorHex {
            // Use a lighter version of the group color for the background
            return Color(hex: colorHex).opacity(0.15)
        } else {
            // Default background if no group assigned
            return Color.clear
        }
    }
}

// MARK: - Updated List View with Group Filtering

struct OTPListView: View {
    @ObservedObject var store: WatchOTPStore
    @State private var selectedGroupColor: String? = nil
    let timer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()
    
    var body: some View {
        VStack(spacing: 0) {
            // Only show group filter if we have groups
            if !availableGroupColors.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 12) {
                        // All filter
                        FilterButton(
                            isSelected: selectedGroupColor == nil,
                            color: .white
                        ) {
                            selectedGroupColor = nil
                        }
                        
                        // Group color filters
                        ForEach(availableGroupColors, id: \.self) { colorHex in
                            FilterButton(
                                isSelected: selectedGroupColor == colorHex,
                                color: Color(hex: colorHex)
                            ) {
                                selectedGroupColor = colorHex
                            }
                        }
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 12)
                }
            }

            List {
                if filteredCodeInfos.isEmpty {
                    Text("No authentication codes")
                        .foregroundColor(.gray)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding()
                } else {
                    ForEach(filteredCodeInfos) { codeInfo in
                        NavigationLink(destination: WatchOTPDetailView(store: store, codeInfo: codeInfo)) {
                            WatchOTPListRow(codeInfo: codeInfo)
                        }
                    }
                }
            }
        }
        //.navigationTitle("AuthNow")
        .onAppear {
            store.requestUpdate()
        }
        .onReceive(timer) { _ in
            store.requestUpdate()
        }
    }
    
    // Get unique group colors for filtering
    private var availableGroupColors: [String] {
        let colors = store.codeInfos.compactMap { $0.groupColorHex }
        return Array(Set(colors))
    }
    
    // Filter code infos based on selected group color
    private var filteredCodeInfos: [OTPCodeInfo] {
        if let selectedColor = selectedGroupColor {
            return store.codeInfos.filter { $0.groupColorHex == selectedColor }
        } else {
            return store.codeInfos
        }
    }
}

// Small circular filter button for Watch
struct FilterButton: View {
    let isSelected: Bool
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Circle()
                .fill(color.opacity(isSelected ? 1.0 : 0.5))
                .frame(width: 16, height: 16)
                .overlay(
                    Circle()
                        .stroke(Color.white, lineWidth: isSelected ? 2 : 0)
                )
        }
        .buttonStyle(PlainButtonStyle())
    }
}

// MARK: - App Entry Point

@main
struct AuthenticatorWatchApp: App {
    @StateObject private var store = WatchOTPStore()
    
    var body: some Scene {
        WindowGroup {
            NavigationView {
                OTPListView(store: store)
            }
        }
    }
}
