import SwiftUI
import WatchConnectivity

// MARK: - Data Models

enum OTPType: String, Codable {
    case totp, hotp
}

// Update OTPCodeInfo to include timestamp information
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
    var groupColorHex: String?
    var lastUpdated: Date // New field to track when the code was last updated
    
    // Default initializer to add lastUpdated property
    init(id: UUID, name: String, type: OTPType, digits: Int, currentCode: String,
         previousCode: String? = nil, nextCode: String? = nil, timeRemaining: Int? = nil,
         period: Int? = nil, counter: Int? = nil, groupColorHex: String? = nil,
         lastUpdated: Date = Date()) {
        self.id = id
        self.name = name
        self.type = type
        self.digits = digits
        self.currentCode = currentCode
        self.previousCode = previousCode
        self.nextCode = nextCode
        self.timeRemaining = timeRemaining
        self.period = period
        self.counter = counter
        self.groupColorHex = groupColorHex
        self.lastUpdated = lastUpdated
    }
    
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
        lhs.groupColorHex == rhs.groupColorHex &&
        lhs.lastUpdated == rhs.lastUpdated
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
    private var updateTimer: Timer?
    
    private let saveKey
    = "watchOTPCodeInfos"
    
    override init() {
        super.init()
        setupWatchConnectivity()
        load()
        startUpdateTimer()
    }
    
    deinit {
        updateTimer?.invalidate()
    }
    
    private func setupWatchConnectivity() {
        guard WCSession.isSupported() else { return }
        
        WCSession.default.delegate = self
        WCSession.default.activate()
    }
    
    // Start a timer to periodically request updates
    private func startUpdateTimer() {
        updateTimer?.invalidate()
        
        // Request updates more frequently to ensure we always have fresh codes
        updateTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.requestUpdate()
        }
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
                // Update timestamp for this specific code
                codeInfos[index].lastUpdated = Date()
                save()
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
    
    // Check if a code is fresh enough to display
    func isCodeFresh(_ codeInfo: OTPCodeInfo) -> Bool {
        // For HOTP codes, they're valid for a longer time as they don't expire automatically
        if codeInfo.type == .hotp {
            // Still enforce some freshness check for HOTP codes, but give them a longer window
            // This prevents showing very old HOTP codes that might have been incremented on phone
            let currentTime = Date()
            let timeInterval = currentTime.timeIntervalSince(codeInfo.lastUpdated)
            
            // HOTP codes are considered fresh for 1 hour
            return timeInterval <= 3600
        }
        
        // For TOTP codes, check if they're stale
        let currentTime = Date()
        let timeInterval = currentTime.timeIntervalSince(codeInfo.lastUpdated)
        
        // If code is older than its period, consider it stale
        let maxAge = Double(codeInfo.period ?? 30)
        return timeInterval <= maxAge
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
                // Update timestamp for all received codes
                let updatedCodeInfos = decodedCodeInfos.map { codeInfo in
                    var updatedInfo = codeInfo
                    updatedInfo.lastUpdated = Date()
                    return updatedInfo
                }
                
                self.codeInfos = updatedCodeInfos
                self.save()
            }
        }
    }
    
    func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        if let codeInfosData = message["codeInfos"] as? Data,
           let decodedCodeInfos = try? JSONDecoder().decode([OTPCodeInfo].self, from: codeInfosData) {
            DispatchQueue.main.async {
                // Update timestamp for all received codes
                let updatedCodeInfos = decodedCodeInfos.map { codeInfo in
                    var updatedInfo = codeInfo
                    updatedInfo.lastUpdated = Date()
                    return updatedInfo
                }
                
                self.codeInfos = updatedCodeInfos
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

// MARK: - Updated List Item View with code freshness check

struct WatchOTPListRow: View {
    let codeInfo: OTPCodeInfo
    @ObservedObject var store: WatchOTPStore
    @State private var refreshID = UUID()
    
    // Computed property to check if code is stale
    private var isCodeFresh: Bool {
        store.isCodeFresh(codeInfo)
    }
    
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
                
                if isCodeFresh {
                    // Show the actual code if it's fresh
                    Text(codeInfo.currentCode)
                        .font(.system(.body, design: .monospaced))
                        .bold()
                        .id("list_\(refreshID)")
                } else {
                    // Show placeholder when code is stale
                    Text(String(repeating: "•", count: codeInfo.digits))
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.gray)
                }
            }
            
            Spacer()
            
            if codeInfo.type == .totp {
                if isCodeFresh {
                    WatchTimeRemainingView(codeInfo: codeInfo)
                        .id("list_timer_\(refreshID)")
                } else {
                    // Just show a simple icon for stale TOTP codes
                    Image(systemName: "ellipsis")
                        .foregroundColor(.gray)
                        .font(.footnote)
                }
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
        .onAppear {
            // Request an update when this row appears
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
            return Color(hex: colorHex).opacity(0.2)
        } else {
            // Default background if no group assigned
            return Color.clear
        }
    }
}

// MARK: - Updated Detail View with code freshness check

struct WatchOTPDetailView: View {
    @ObservedObject var store: WatchOTPStore
    @State private var currentCodeInfo: OTPCodeInfo
    @State private var refreshID = UUID()
    
    let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    
    // Initializer to keep our local state synced with the store
    init(store: WatchOTPStore, codeInfo: OTPCodeInfo) {
        self.store = store
        self._currentCodeInfo = State(initialValue: codeInfo)
    }
    
    // Computed property to check if code is stale
    private var isCodeFresh: Bool {
        store.isCodeFresh(currentCodeInfo)
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                // Always show the same layout, but with placeholders for stale data
                if currentCodeInfo.type == .totp {
                    // Next code (top)
                    VStack(spacing: 2) {
                        Text("Next")
                            .font(.footnote)
                            .foregroundColor(.gray)
                        if isCodeFresh {
                            Text(currentCodeInfo.nextCode ?? "")
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.gray)
                                .id("next_\(refreshID)")
                        } else {
                            Text(String(repeating: "•", count: currentCodeInfo.digits))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.gray)
                        }
                    }
                    .padding(.vertical, 2)
                    
                    // Current code (middle)
                    VStack(spacing: 2) {
                        HStack {
                            Text("Current")
                                .font(.footnote)
                                .bold()
                            if isCodeFresh {
                                WatchTimeRemainingView(codeInfo: currentCodeInfo)
                                    .id("timer_\(refreshID)")
                            } else {
                                // Empty space for alignment when timer is hidden
                                Circle()
                                    .fill(Color.clear)
                                    .frame(width: 20, height: 20)
                            }
                        }
                        if isCodeFresh {
                            Text(currentCodeInfo.currentCode)
                                .font(.system(.title3, design: .monospaced))
                                .bold()
                                .id("current_\(refreshID)")
                        } else {
                            Text(String(repeating: "•", count: currentCodeInfo.digits))
                                .font(.system(.title3, design: .monospaced))
                                .foregroundColor(.gray)
                        }
                    }
                    .padding(.vertical, 6)
                    
                    // Previous code (bottom)
                    VStack(spacing: 2) {
                        Text("Previous")
                            .font(.footnote)
                            .foregroundColor(.gray)
                        if isCodeFresh {
                            Text(currentCodeInfo.previousCode ?? "")
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.gray)
                                .id("prev_\(refreshID)")
                        } else {
                            Text(String(repeating: "•", count: currentCodeInfo.digits))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.gray)
                        }
                    }
                    .padding(.vertical, 2)
                } else {
                    // HOTP
                    VStack {
                        if isCodeFresh {
                            Text(currentCodeInfo.currentCode)
                                .font(.system(.title2, design: .monospaced))
                                .bold()
                                .id("hotp_\(refreshID)")
                        } else {
                            Text(String(repeating: "•", count: currentCodeInfo.digits))
                                .font(.system(.title2, design: .monospaced))
                                .foregroundColor(.gray)
                        }
                        
                        Button("Next Code") {
                            store.incrementHOTPCounter(currentCodeInfo)
                        }
                        .padding(.top, 8)
                        .disabled(!isCodeFresh)  // Disable button when code is stale
                    }
                }
            }
            .padding()
        }
        .onReceive(timer) { _ in
            // Request update more frequently in detail view for better UX
            store.requestUpdate()
            
            // Update our local state with the latest from the store
            if let updatedInfo = store.codeInfos.first(where: { $0.id == currentCodeInfo.id }) {
                currentCodeInfo = updatedInfo
                refreshID = UUID()
            }
        }
        .onAppear {
            // Immediately request an update when view appears
            store.requestUpdate()
            
            // Make sure we have the latest version from the store
            if let updatedInfo = store.codeInfos.first(where: { $0.id == currentCodeInfo.id }) {
                currentCodeInfo = updatedInfo
            }
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
                    .padding(.vertical, 8)
                }
            }

            List {
                if filteredCodeInfos.isEmpty {
                    if store.codeInfos.isEmpty {
                        Text("No authentication codes")
                            .foregroundColor(.gray)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding()
                    } else {
                        Text("No codes in this filter")
                            .foregroundColor(.gray)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding()
                    }
                } else {
                    ForEach(filteredCodeInfos) { codeInfo in
                        NavigationLink(destination: WatchOTPDetailView(store: store, codeInfo: codeInfo)) {
                            WatchOTPListRow(codeInfo: codeInfo, store: store)
                        }
                    }
                }
            }
        }
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
