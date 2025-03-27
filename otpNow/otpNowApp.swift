import SwiftUI
import CryptoKit
import WatchConnectivity
import AVFoundation
import AudioToolbox

// MARK: - Data Models

// Add this after the existing OTPAlgorithm enum

// Group model to categorize secrets
struct OTPGroup: Identifiable, Codable, Equatable {
    var id = UUID()
    var name: String
    var colorHex: String // Store color as hex string
    
    static func == (lhs: OTPGroup, rhs: OTPGroup) -> Bool {
        lhs.id == rhs.id &&
        lhs.name == rhs.name &&
        lhs.colorHex == rhs.colorHex
    }
}

// Update OTPSecret to include group
struct OTPSecret: Identifiable, Codable {
    var id = UUID()
    var name: String
    var secret: String
    var type: OTPType
    var counter: Int? // Only used for HOTP
    var digits: Int
    var algorithm: OTPAlgorithm
    var period: Int // Only used for TOTP
    var showOnWatch: Bool // Watch visibility
    var groupId: UUID? // New property for group association
    
    init(name: String, secret: String, type: OTPType, digits: Int = 6, algorithm: OTPAlgorithm = .sha1, period: Int = 30, counter: Int? = 0, showOnWatch: Bool = true, groupId: UUID? = nil) {
        self.name = name
        self.secret = secret
        self.type = type
        self.digits = digits
        self.algorithm = algorithm
        self.period = period
        self.counter = counter
        self.showOnWatch = showOnWatch
        self.groupId = groupId
    }
}

// Extension to convert hex string to Color
extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
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
    
    func toHex() -> String {
        guard let components = UIColor(self).cgColor.components else {
            return "000000"
        }
        
        let r = components[0]
        let g = components[1]
        let b = components[2]
        
        return String(
            format: "%02X%02X%02X",
            Int(r * 255),
            Int(g * 255),
            Int(b * 255)
        )
    }
}

// New structure for transferring code information without secrets
struct OTPCodeInfo: Identifiable, Codable, Equatable {
    var id: UUID // Same ID as the original secret
    var name: String
    var type: OTPType
    var digits: Int
    var currentCode: String
    var previousCode: String? // Only for TOTP
    var nextCode: String? // Only for TOTP
    var timeRemaining: Int? // Only for TOTP
    var period: Int? // Only for TOTP
    var counter: Int? // Only for HOTP
    var groupColorHex: String? // New property for group color
    var lastUpdated: Date = Date() // New property for timestamp
    
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

enum OTPType: String, Codable {
    case totp, hotp
}

enum OTPAlgorithm: String, Codable {
    case sha1, sha256, sha512
}

// MARK: - OTPAuth URL Parser

struct OTPAuthURL {
    var type: OTPType
    var label: String
    var issuer: String?
    var account: String?
    var secret: String
    var algorithm: OTPAlgorithm
    var digits: Int
    var period: Int?
    var counter: Int?
    
    static func parse(from url: URL) -> OTPAuthURL? {
        // Check scheme and host
        guard url.scheme == "otpauth" else {
            return nil
        }
        
        // Get type from host, defaulting to TOTP if unknown
        let type: OTPType
        if let host = url.host?.lowercased() {
            switch host {
            case "totp":
                type = .totp
            case "hotp":
                type = .hotp
            default:
                // Default to TOTP for unrecognized types
                return nil
            }
        } else {
            return nil
        }
        
        // Parse path component (label)
        var label = url.path
        if label.hasPrefix("/") {
            label.removeFirst()
        }
        
        // Try to extract issuer and account from the label (Format: issuer:account)
        var issuer: String?
        var account: String?
        
        if let colonIndex = label.firstIndex(of: ":") {
            issuer = String(label[..<colonIndex])
            account = String(label[label.index(after: colonIndex)...])
        } else {
            // No colon in the label, just use it as the account
            account = label
        }
        
        // Parse query parameters
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            return nil
        }
        
        // Extract parameters from query items
        var secret: String?
        var algorithmStr: String = "SHA1"
        var digits: Int = 6
        var period: Int = 30
        var counter: Int?
        
        for item in queryItems {
            switch item.name.lowercased() {
            case "secret":
                secret = item.value
            case "algorithm":
                algorithmStr = item.value ?? "SHA1"
            case "digits":
                digits = Int(item.value ?? "6") ?? 6
            case "period":
                period = Int(item.value ?? "30") ?? 30
            case "counter":
                if let counterStr = item.value, let counterValue = Int(counterStr) {
                    counter = counterValue
                }
            case "issuer":
                // If issuer is in the query parameters, it takes precedence
                issuer = item.value
            default:
                issuer = "Error!"
            }
            
        }
        
        // Secret is required
        guard let secretValue = secret, !secretValue.isEmpty else {
            return nil
        }
        
        // Convert algorithm string to OTPAlgorithm
        let algorithm: OTPAlgorithm
        switch algorithmStr.uppercased() {
        case "SHA1":
            algorithm = .sha1
        case "SHA256":
            algorithm = .sha256
        case "SHA512":
            algorithm = .sha512
        default:
            algorithm = .sha1
        }
        
        return OTPAuthURL(
            type: type,
            label: label,
            issuer: issuer,
            account: account,
            secret: secretValue,
            algorithm: algorithm,
            digits: digits,
            period: type == .totp ? period : nil,
            counter: type == .hotp ? counter : nil
        )
    }
}

// MARK: - Authentication Code Generator

class OTPGenerator {
    static func generateTOTP(for secret: OTPSecret, at time: TimeInterval? = nil) -> String? {
        guard let secretData = base32Decode(secret.secret) else {
            return nil
        }
        
        let counter = getTOTPCounter(for: secret, at: time)
        return generateOTP(with: secretData, counter: counter, digits: secret.digits, algorithm: secret.algorithm)
    }
    
    static func generateHOTP(for secret: OTPSecret, counter: Int? = nil) -> String? {
        guard let secretData = base32Decode(secret.secret),
              let counterValue = counter ?? secret.counter else {
            return nil
        }
        
        return generateOTP(with: secretData, counter: UInt64(counterValue), digits: secret.digits, algorithm: secret.algorithm)
    }
    
    private static func getTOTPCounter(for secret: OTPSecret, at time: TimeInterval? = nil) -> UInt64 {
        let timeInterval = time ?? Date().timeIntervalSince1970
        return UInt64(floor(timeInterval / TimeInterval(secret.period)))
    }
    
    private static func generateOTP(with secretData: Data, counter: UInt64, digits: Int, algorithm: OTPAlgorithm) -> String? {
        // Convert counter to big-endian data
        var counterBytes = counter.bigEndian
        let counterData = Data(bytes: &counterBytes, count: MemoryLayout<UInt64>.size)
        
        // Compute HMAC
        let hmac: Data
        switch algorithm {
        case .sha1:
            let hmacValue = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: SymmetricKey(data: secretData))
            hmac = Data(hmacValue)
        case .sha256:
            let hmacValue = HMAC<SHA256>.authenticationCode(for: counterData, using: SymmetricKey(data: secretData))
            hmac = Data(hmacValue)
        case .sha512:
            let hmacValue = HMAC<SHA512>.authenticationCode(for: counterData, using: SymmetricKey(data: secretData))
            hmac = Data(hmacValue)
        }
        
        // Dynamic truncation
        let hmacBytes = [UInt8](hmac)
        let offset = Int(hmacBytes[hmacBytes.count - 1] & 0x0f)
        
        let truncatedHash = ((UInt32(hmacBytes[offset]) & 0x7f) << 24) |
                            ((UInt32(hmacBytes[offset + 1]) & 0xff) << 16) |
                            ((UInt32(hmacBytes[offset + 2]) & 0xff) << 8) |
                            (UInt32(hmacBytes[offset + 3]) & 0xff)
        
        // Convert to OTP code
        let otpCode = truncatedHash % UInt32(pow(10, Double(digits)))
        return String(format: "%0*d", digits, otpCode)
    }
    
    // Base32 decoding function
    private static func base32Decode(_ string: String) -> Data? {
        let base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var result = Data()
        let cleanedString = string.uppercased()
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "=", with: "")
        
        var buffer = 0
        var bitsLeft = 0
        
        for char in cleanedString {
            guard let charValue = base32Chars.firstIndex(of: char) else {
                continue
            }
            
            let value = base32Chars.distance(from: base32Chars.startIndex, to: charValue)
            buffer = (buffer << 5) | value
            bitsLeft += 5
            
            if bitsLeft >= 8 {
                bitsLeft -= 8
                result.append(UInt8(buffer >> bitsLeft))
                buffer &= (1 << bitsLeft) - 1
            }
        }
        
        return result
    }
}

// MARK: - Store to manage OTP secrets and persistence

class OTPStore: ObservableObject {
    @Published var secrets: [OTPSecret] = []
    @Published var groups: [OTPGroup] = []
    private var watchUpdateTimer: Timer?
    
    private let saveKey = "otpSecrets"
    private let groupsKey = "otpGroups"
    
    init() {
        loadGroups()
        loadSecrets()
        startWatchUpdates()
        
        // Add default group if none exist
        if groups.isEmpty {
            let defaultColors = [
                "4A90E2", // Blue
                "7ED321", // Green
                "F5A623", // Orange
                "D0021B", // Red
                "9013FE"  // Purple
            ]
            
            groups.append(OTPGroup(name: "Personal", colorHex: defaultColors[0]))
            groups.append(OTPGroup(name: "Work", colorHex: defaultColors[1]))
            groups.append(OTPGroup(name: "Financial", colorHex: defaultColors[2]))
            saveGroups()
        }
    }
    
    deinit {
        stopWatchUpdates()
    }
    
    // Secret management
    func add(_ secret: OTPSecret) {
        secrets.append(secret)
        saveSecrets()
        sendToWatch()
    }
    
    func update(_ secret: OTPSecret) {
        if let index = secrets.firstIndex(where: { $0.id == secret.id }) {
            secrets[index] = secret
            saveSecrets()
            sendToWatch()
        }
    }
    
    func delete(_ secret: OTPSecret) {
        secrets.removeAll { $0.id == secret.id }
        saveSecrets()
        sendToWatch()
    }
    
    func incrementHOTPCounter(_ secret: OTPSecret) {
        if let index = secrets.firstIndex(where: { $0.id == secret.id }),
           secrets[index].type == .hotp,
           var counter = secrets[index].counter {
            secrets[index].counter = counter + 1
            saveSecrets()
            sendToWatch()
        }
    }
    
    // Group management
    func add(_ group: OTPGroup) {
        groups.append(group)
        saveGroups()
    }
    
    func update(_ group: OTPGroup) {
        if let index = groups.firstIndex(where: { $0.id == group.id }) {
            groups[index] = group
            saveGroups()
        }
    }
    
    func delete(_ group: OTPGroup) {
        // Remove group from secrets that use it
        for index in secrets.indices where secrets[index].groupId == group.id {
            secrets[index].groupId = nil
        }
        
        // Remove the group
        groups.removeAll { $0.id == group.id }
        
        saveGroups()
        saveSecrets()
    }
    
    func getGroup(for secret: OTPSecret) -> OTPGroup? {
        guard let groupId = secret.groupId else { return nil }
        return groups.first { $0.id == groupId }
    }
    
    // Persistence methods
    private func saveSecrets() {
        if let encoded = try? JSONEncoder().encode(secrets) {
            UserDefaults.standard.set(encoded, forKey: saveKey)
        }
    }
    
    private func loadSecrets() {
        if let data = UserDefaults.standard.data(forKey: saveKey),
           let decoded = try? JSONDecoder().decode([OTPSecret].self, from: data) {
            secrets = decoded
        }
    }
    
    private func saveGroups() {
        if let encoded = try? JSONEncoder().encode(groups) {
            UserDefaults.standard.set(encoded, forKey: groupsKey)
        }
    }
    
    private func loadGroups() {
        if let data = UserDefaults.standard.data(forKey: groupsKey),
           let decoded = try? JSONDecoder().decode([OTPGroup].self, from: data) {
            groups = decoded
        }
    }
    
    // MARK: - Watch Communication Methods
    
    // Update function in OTPStore to include timestamp when generating code info
    func generateCodeInfo(for secret: OTPSecret) -> OTPCodeInfo {
        var previousCode: String? = nil
        var nextCode: String? = nil
        var timeRemaining: Int? = nil
        var currentCode = "Error"
        
        if secret.type == .totp {
            currentCode = OTPGenerator.generateTOTP(for: secret) ?? "Error"
            previousCode = OTPGenerator.generateTOTP(for: secret, at: Date().timeIntervalSince1970 - TimeInterval(secret.period))
            nextCode = OTPGenerator.generateTOTP(for: secret, at: Date().timeIntervalSince1970 + TimeInterval(secret.period))
            
            // Calculate time remaining
            let seconds = Int(Date().timeIntervalSince1970) % secret.period
            timeRemaining = secret.period - seconds
        } else if secret.type == .hotp {
            currentCode = OTPGenerator.generateHOTP(for: secret) ?? "Error"
        }
        
        // Get group color if available
        var groupColorHex: String? = nil
        if let groupId = secret.groupId, let group = groups.first(where: { $0.id == groupId }) {
            groupColorHex = group.colorHex
        }
        
        // The lastUpdated field will be initialized with the current date automatically
        return OTPCodeInfo(
            id: secret.id,
            name: secret.name,
            type: secret.type,
            digits: secret.digits,
            currentCode: currentCode,
            previousCode: previousCode,
            nextCode: nextCode,
            timeRemaining: timeRemaining,
            period: secret.type == .totp ? secret.period : nil,
            counter: secret.type == .hotp ? secret.counter : nil,
            groupColorHex: groupColorHex
            // lastUpdated will default to current date
        )
    }
    
    // Generate code info for all secrets that are selected for the watch
    func generateAllCodeInfo() -> [OTPCodeInfo] {
        return secrets.filter { $0.showOnWatch }.map { generateCodeInfo(for: $0) }
    }
    
    // Toggle visibility on watch
    func toggleWatchVisibility(for secret: OTPSecret) {
        if let index = secrets.firstIndex(where: { $0.id == secret.id }) {
            secrets[index].showOnWatch.toggle()
            saveSecrets()
            sendToWatch()
        }
    }
    
    // Set visibility on watch
    func setWatchVisibility(for secret: OTPSecret, visible: Bool) {
        if let index = secrets.firstIndex(where: { $0.id == secret.id }) {
            secrets[index].showOnWatch = visible
            saveSecrets()
            sendToWatch()
        }
    }
    
    // Send current codes to the watch
    func sendToWatch() {
        guard WCSession.isSupported(), WCSession.default.activationState == .activated else {
            return
        }
        
        let codeInfos = generateAllCodeInfo()
        if let encoded = try? JSONEncoder().encode(codeInfos) {
            WCSession.default.transferUserInfo(["codeInfos": encoded])
        }
    }
    
    // Update codes on demand (called by timer or when requested by watch)
    func updateWatchCodes() {
        guard WCSession.isSupported(), WCSession.default.activationState == .activated && WCSession.default.isReachable else {
            return
        }
        
        let codeInfos = generateAllCodeInfo()
        if let encoded = try? JSONEncoder().encode(codeInfos) {
            WCSession.default.sendMessage(["codeInfos": encoded], replyHandler: nil) { error in
                print("Error sending codes to watch: \(error.localizedDescription)")
            }
        }
    }
    
    // Start periodic updates for the watch
    func startWatchUpdates() {
        watchUpdateTimer?.invalidate()
        watchUpdateTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.updateWatchCodes()
        }
    }
    
    // Stop periodic updates
    func stopWatchUpdates() {
        watchUpdateTimer?.invalidate()
        watchUpdateTimer = nil
    }
}

// MARK: - WatchConnectivity Session Delegate

class WatchSessionDelegate: NSObject, WCSessionDelegate, ObservableObject {
    @Published var connectionStatus: WCSessionActivationState = .notActivated
    weak var store: OTPStore?
    
    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        DispatchQueue.main.async {
            self.connectionStatus = activationState
        }
    }
    
    func sessionDidBecomeInactive(_ session: WCSession) {
        DispatchQueue.main.async {
            self.connectionStatus = .inactive
        }
    }
    
    func sessionDidDeactivate(_ session: WCSession) {
        DispatchQueue.main.async {
            self.connectionStatus = .notActivated
        }
        // Need to reactivate
        WCSession.default.activate()
    }
    
    func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        guard let store = self.store else { return }
        
        if let action = message["action"] as? String, action == "incrementCounter",
           let secretIdString = message["secretId"] as? String,
           let secretId = UUID(uuidString: secretIdString) {
            
            // Find the secret and increment its counter
            if let secretIndex = store.secrets.firstIndex(where: { $0.id == secretId }),
               store.secrets[secretIndex].type == .hotp {
                
                DispatchQueue.main.async {
                    store.incrementHOTPCounter(store.secrets[secretIndex])
                    store.updateWatchCodes() // Send updated code immediately
                }
            }
        } else if let action = message["action"] as? String, action == "requestUpdate" {
            // Watch is requesting an update of codes
            DispatchQueue.main.async {
                store.updateWatchCodes()
            }
        }
    }
}

// Group Management View
struct GroupManagementView: View {
    @Environment(\.presentationMode) var presentationMode
    @ObservedObject var store: OTPStore
    @State private var showingAddSheet = false
    
    var body: some View {
        NavigationView {
            List {
                ForEach(store.groups) { group in
                    HStack {
                        Circle()
                            .fill(Color(hex: group.colorHex))
                            .frame(width: 24, height: 24)
                        
                        Text(group.name)
                            .padding(.leading, 8)
                        
                        Spacer()
                        
                        // Count how many secrets use this group
                        let count = store.secrets.filter { $0.groupId == group.id }.count
                        Text("\(count) items")
                            .foregroundColor(.gray)
                            .font(.caption)
                    }
                    .contextMenu {
                        Button(action: {
                            // Open edit sheet for this group
                            showEditSheet(for: group)
                        }) {
                            Label("Edit", systemImage: "pencil")
                        }
                        
                        Button(role: .destructive, action: {
                            store.delete(group)
                        }) {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
                .onDelete { indexSet in
                    for index in indexSet {
                        store.delete(store.groups[index])
                    }
                }
            }
            .navigationTitle("Manage Groups")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: {
                        showingAddSheet = true
                    }) {
                        Image(systemName: "plus")
                    }
                }
                
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Done") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
            .sheet(isPresented: $showingAddSheet) {
                AddGroupView(store: store)
            }
        }
    }
    
    private func showEditSheet(for group: OTPGroup) {
        let editView = EditGroupView(store: store, group: group)
        let hostingController = UIHostingController(rootView: editView)
        
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let rootViewController = windowScene.windows.first?.rootViewController {
            rootViewController.present(hostingController, animated: true)
        }
    }
}

// Add Group View
struct AddGroupView: View {
    @Environment(\.presentationMode) var presentationMode
    @ObservedObject var store: OTPStore
    
    @State private var name = ""
    @State private var selectedColor = Color.blue
    
    // Predefined colors for selection
    let colorOptions: [Color] = [
        Color(hex: "4A90E2"), // Blue
        Color(hex: "7ED321"), // Green
        Color(hex: "F5A623"), // Orange
        Color(hex: "D0021B"), // Red
        Color(hex: "9013FE"), // Purple
        Color(hex: "50E3C2"), // Teal
        Color(hex: "B8E986"), // Light Green
        Color(hex: "BD10E0"), // Magenta
        Color(hex: "8B572A"), // Brown
        Color(hex: "9B9B9B")  // Gray
    ]
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Group Information")) {
                    TextField("Group Name", text: $name)
                    
                    VStack(alignment: .leading) {
                        Text("Group Color")
                            .font(.caption)
                            .foregroundColor(.gray)
                            .padding(.top, 8)
                        
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 44))], spacing: 10) {
                            ForEach(colorOptions, id: \.self) { color in
                                Circle()
                                    .fill(color)
                                    .frame(width: 30, height: 30)
                                    .overlay(
                                        Circle()
                                            .stroke(Color.primary, lineWidth: selectedColor == color ? 2 : 0)
                                    )
                                    .onTapGesture {
                                        selectedColor = color
                                    }
                            }
                        }
                        .padding(.vertical, 8)
                    }
                }
                
                Button("Save") {
                    saveGroup()
                }
                .disabled(name.isEmpty)
            }
            .navigationTitle("Add Group")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
        }
    }
    
    private func saveGroup() {
        let newGroup = OTPGroup(
            name: name,
            colorHex: selectedColor.toHex()
        )
        
        store.add(newGroup)
        presentationMode.wrappedValue.dismiss()
    }
}

// Edit Group View
struct EditGroupView: View {
    @Environment(\.presentationMode) var presentationMode
    @ObservedObject var store: OTPStore
    let group: OTPGroup
    
    @State private var name: String
    @State private var selectedColor: Color
    
    init(store: OTPStore, group: OTPGroup) {
        self.store = store
        self.group = group
        _name = State(initialValue: group.name)
        _selectedColor = State(initialValue: Color(hex: group.colorHex))
    }
    
    // Predefined colors for selection
    let colorOptions: [Color] = [
        Color(hex: "4A90E2"), // Blue
        Color(hex: "7ED321"), // Green
        Color(hex: "F5A623"), // Orange
        Color(hex: "D0021B"), // Red
        Color(hex: "9013FE"), // Purple
        Color(hex: "50E3C2"), // Teal
        Color(hex: "B8E986"), // Light Green
        Color(hex: "BD10E0"), // Magenta
        Color(hex: "8B572A"), // Brown
        Color(hex: "9B9B9B")  // Gray
    ]
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Group Information")) {
                    TextField("Group Name", text: $name)
                    
                    VStack(alignment: .leading) {
                        Text("Group Color")
                            .font(.caption)
                            .foregroundColor(.gray)
                            .padding(.top, 8)
                        
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 44))], spacing: 10) {
                            ForEach(colorOptions, id: \.self) { color in
                                Circle()
                                    .fill(color)
                                    .frame(width: 30, height: 30)
                                    .overlay(
                                        Circle()
                                            .stroke(Color.primary, lineWidth: selectedColor == color ? 2 : 0)
                                    )
                                    .onTapGesture {
                                        selectedColor = color
                                    }
                            }
                        }
                        .padding(.vertical, 8)
                    }
                }
                
                Button("Save") {
                    saveChanges()
                }
                .disabled(name.isEmpty)
            }
            .navigationTitle("Edit Group")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
        }
    }
    
    private func saveChanges() {
        var updatedGroup = group
        updatedGroup.name = name
        updatedGroup.colorHex = selectedColor.toHex()
        
        store.update(updatedGroup)
        presentationMode.wrappedValue.dismiss()
    }
}

// MARK: - QR Code Scanner

struct QRCodeScannerView: UIViewControllerRepresentable {
    @Binding var isShowing: Bool
    var completion: (String) -> Void
    
    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.delegate = context.coordinator
        return controller
    }
    
    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, QRScannerViewControllerDelegate {
        var parent: QRCodeScannerView
        
        init(_ parent: QRCodeScannerView) {
            self.parent = parent
        }
        
        func scannerDidCancel() {
            parent.isShowing = false
        }
        
        func scanner(_ scanner: QRScannerViewController, didScanCode code: String) {
            parent.completion(code)
            parent.isShowing = false
        }
    }
}

protocol QRScannerViewControllerDelegate: AnyObject {
    func scannerDidCancel()
    func scanner(_ scanner: QRScannerViewController, didScanCode code: String)
}

// Updated QRScannerViewController to start capture session on background thread
class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: QRScannerViewControllerDelegate?
    
    var captureSession: AVCaptureSession!
    var previewLayer: AVCaptureVideoPreviewLayer!
    private var isConfigured = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.backgroundColor = UIColor.black
        
        // Setup UI elements first
        setupCancelButton()
        
        // Initialize capture session but don't start it yet
        captureSession = AVCaptureSession()
        
        // We'll configure and start the session in viewWillAppear
    }
    
    private func setupCancelButton() {
        let cancelButton = UIButton(type: .system)
        cancelButton.setTitle("Cancel", for: .normal)
        cancelButton.setTitleColor(.white, for: .normal)
        cancelButton.addTarget(self, action: #selector(cancelButtonTapped), for: .touchUpInside)
        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(cancelButton)
        
        NSLayoutConstraint.activate([
            cancelButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20),
            cancelButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            cancelButton.heightAnchor.constraint(equalToConstant: 50),
            cancelButton.widthAnchor.constraint(equalToConstant: 100)
        ])
    }
    
    private func configureCaptureSession() {
        guard !isConfigured else { return }
        
        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video) else {
            failed()
            return
        }
        
        let videoInput: AVCaptureDeviceInput
        
        do {
            videoInput = try AVCaptureDeviceInput(device: videoCaptureDevice)
        } catch {
            failed()
            return
        }
        
        if captureSession.canAddInput(videoInput) {
            captureSession.addInput(videoInput)
        } else {
            failed()
            return
        }
        
        let metadataOutput = AVCaptureMetadataOutput()
        
        if captureSession.canAddOutput(metadataOutput) {
            captureSession.addOutput(metadataOutput)
            
            metadataOutput.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
            metadataOutput.metadataObjectTypes = [.qr]
        } else {
            failed()
            return
        }
        
        // Setup preview layer on main thread
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            
            self.previewLayer = AVCaptureVideoPreviewLayer(session: self.captureSession)
            self.previewLayer.frame = self.view.layer.bounds
            self.previewLayer.videoGravity = .resizeAspectFill
            self.view.layer.addSublayer(self.previewLayer)
            
            // Make sure the cancel button stays on top
            if let cancelButton = self.view.subviews.first(where: { $0 is UIButton }) {
                self.view.bringSubviewToFront(cancelButton)
            }
        }
        
        isConfigured = true
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        
        // Configure the session if needed
        if !isConfigured {
            configureCaptureSession()
        }
        
        // Start running on a background thread
        if captureSession?.isRunning == false {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.captureSession.startRunning()
            }
        }
    }
    
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        
        // Stop running on a background thread
        if captureSession?.isRunning == true {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.captureSession.stopRunning()
            }
        }
    }
    
    @objc func cancelButtonTapped() {
        delegate?.scannerDidCancel()
    }
    
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        // Stop capture session on background thread
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.captureSession.stopRunning()
        }
        
        if let metadataObject = metadataObjects.first {
            guard let readableObject = metadataObject as? AVMetadataMachineReadableCodeObject else { return }
            guard let stringValue = readableObject.stringValue else { return }
            AudioServicesPlaySystemSound(SystemSoundID(kSystemSoundID_Vibrate))
            
            // Check if it's an otpauth URL
            if stringValue.hasPrefix("otpauth://") {
                delegate?.scanner(self, didScanCode: stringValue)
            } else {
                // If not a valid otpauth URL, show an alert
                let alert = UIAlertController(
                    title: "Invalid QR Code",
                    message: "The scanned QR code is not a valid OTP authentication code.",
                    preferredStyle: .alert
                )
                alert.addAction(UIAlertAction(title: "OK", style: .default) { [weak self] _ in
                    // Resume scanning on background thread
                    DispatchQueue.global(qos: .userInitiated).async {
                        self?.captureSession.startRunning()
                    }
                })
                present(alert, animated: true)
            }
        }
    }
    
    func failed() {
        let alert = UIAlertController(
            title: "Scanning not supported",
            message: "Your device does not support scanning a code from an item. Please use a device with a camera.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default) { [weak self] _ in
            self?.delegate?.scannerDidCancel()
        })
        present(alert, animated: true)
    }
}

// MARK: - Toast Message View

// Toast message view for temporary notifications
struct ToastView: View {
    let message: String
    
    var body: some View {
        Text(message)
            .font(.subheadline.bold())
            .foregroundColor(.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                Capsule()
                    .fill(Color.black.opacity(0.75))
            )
            .shadow(color: Color.black.opacity(0.2), radius: 2, x: 0, y: 1)
            .transition(.move(edge: .bottom).combined(with: .opacity))
    }
}

// View modifier to add toast functionality
struct ToastModifier: ViewModifier {
    @Binding var isShowing: Bool
    let message: String
    let duration: TimeInterval
    
    func body(content: Content) -> some View {
        ZStack {
            content
            
            if isShowing {
                VStack {
                    Spacer()
                    
                    ToastView(message: message)
                        .padding(.bottom, 20)
                }
                .ignoresSafeArea()
                .onAppear {
                    DispatchQueue.main.asyncAfter(deadline: .now() + duration) {
                        withAnimation {
                            isShowing = false
                        }
                    }
                }
            }
        }
    }
}

// Extension to make it easier to use the toast
extension View {
    func toast(isShowing: Binding<Bool>, message: String, duration: TimeInterval = 2.0) -> some View {
        self.modifier(ToastModifier(isShowing: isShowing, message: message, duration: duration))
    }
}

// MARK: - Views

// Updated AddOTPSecretView with QR scan button at the top
struct AddOTPSecretView: View {
    @Environment(\.presentationMode) var presentationMode
    @ObservedObject var store: OTPStore
    
    @State private var name = ""
    @State private var secret = ""
    @State private var type = OTPType.totp
    @State private var digits = 6
    @State private var algorithm = OTPAlgorithm.sha1
    @State private var period = 30
    @State private var counter = 0
    @State private var showOnWatch = true
    @State private var selectedGroupId: UUID? = nil
    @State private var showingError = false
    @State private var errorMessage = ""
    @State private var showingScanner = false
    @State private var showingGroupSheet = false
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Secret Information")) {
                    // QR Code scan button moved to the top
                    Button(action: {
                        showingScanner = true
                    }) {
                        HStack {
                            Image(systemName: "qrcode.viewfinder")
                            Text("Scan QR Code")
                        }
                    }
                    
                    TextField("Account Name", text: $name)
                    TextField("Secret Key", text: $secret)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    
                    Picker("Type", selection: $type) {
                        Text("TOTP (Time-based)").tag(OTPType.totp)
                        Text("HOTP (Counter-based)").tag(OTPType.hotp)
                    }
                }
                
                Section(header: Text("Group")) {
                    HStack {
                        if let groupId = selectedGroupId, let group = store.groups.first(where: { $0.id == groupId }) {
                            HStack {
                                Circle()
                                    .fill(Color(hex: group.colorHex))
                                    .frame(width: 20, height: 20)
                                
                                Text(group.name)
                                    .padding(.leading, 4)
                            }
                        } else {
                            Text("None")
                                .foregroundColor(.gray)
                        }
                        
                        Spacer()
                        
                        Button("Select") {
                            showingGroupSheet = true
                        }
                    }
                }
                
                Section(header: Text("Advanced Settings")) {
                    Picker("Digits", selection: $digits) {
                        Text("6").tag(6)
                        Text("7").tag(7)
                        Text("8").tag(8)
                    }
                    
                    Picker("Algorithm", selection: $algorithm) {
                        Text("SHA-1").tag(OTPAlgorithm.sha1)
                        Text("SHA-256").tag(OTPAlgorithm.sha256)
                        Text("SHA-512").tag(OTPAlgorithm.sha512)
                    }
                    
                    if type == .totp {
                        Picker("Period (seconds)", selection: $period) {
                            Text("30").tag(30)
                            Text("60").tag(60)
                            Text("90").tag(90)
                        }
                    } else {
                        Stepper("Initial Counter: \(counter)", value: $counter, in: 0...1000000)
                    }
                    
                    Toggle("Show on Apple Watch", isOn: $showOnWatch)
                }
                
                Button("Save") {
                    saveSecret()
                }
            }
            .navigationTitle("Add Secret")
            .sheet(isPresented: $showingScanner) {
                QRCodeScannerView(isShowing: $showingScanner) { code in
                    processScannedCode(code)
                }
            }
            .sheet(isPresented: $showingGroupSheet) {
                GroupSelectionView(selectedGroupId: $selectedGroupId, store: store)
            }
            .alert(isPresented: $showingError) {
                Alert(title: Text("Error"), message: Text(errorMessage), dismissButton: .default(Text("OK")))
            }
        }
    }
    
    private func processScannedCode(_ code: String) {
        guard let url = URL(string: code),
              let otpAuth = OTPAuthURL.parse(from: url) else {
            errorMessage = "Invalid QR code format"
            showingError = true
            return
        }
        
        // Populate form fields from the parsed data
        type = otpAuth.type
        secret = otpAuth.secret
        digits = otpAuth.digits
        algorithm = otpAuth.algorithm
        
        if let account = otpAuth.account {
            if let issuer = otpAuth.issuer, !issuer.isEmpty {
                name = "\(issuer): \(account)"
            } else {
                name = account
            }
        } else if let issuer = otpAuth.issuer {
            name = issuer
        } else {
            name = otpAuth.label
        }
        
        if let periodValue = otpAuth.period {
            period = periodValue
        }
        
        if let counterValue = otpAuth.counter {
            counter = counterValue
        }
    }
    
    private func saveSecret() {
        guard !name.isEmpty else {
            errorMessage = "Please enter an account name"
            showingError = true
            return
        }
        
        guard !secret.isEmpty else {
            errorMessage = "Please enter a secret key"
            showingError = true
            return
        }
        
        let newSecret = OTPSecret(
            name: name,
            secret: secret,
            type: type,
            digits: digits,
            algorithm: algorithm,
            period: period,
            counter: type == .hotp ? counter : nil,
            showOnWatch: showOnWatch,
            groupId: selectedGroupId
        )
        
        // Verify that we can generate a code with this secret
        switch type {
        case .totp:
            guard OTPGenerator.generateTOTP(for: newSecret) != nil else {
                errorMessage = "Invalid secret key. Please check and try again."
                showingError = true
                return
            }
        case .hotp:
            guard OTPGenerator.generateHOTP(for: newSecret) != nil else {
                errorMessage = "Invalid secret key. Please check and try again."
                showingError = true
                return
            }
        }
        
        store.add(newSecret)
        presentationMode.wrappedValue.dismiss()
    }
}

// Updated EditOTPSecretView with group selection
struct EditOTPSecretView: View {
    @Environment(\.presentationMode) var presentationMode
    @ObservedObject var store: OTPStore
    let secret: OTPSecret
    
    @State private var name: String
    @State private var showOnWatch: Bool
    @State private var selectedGroupId: UUID?
    @State private var showingGroupSheet = false
    
    init(store: OTPStore, secret: OTPSecret) {
        self.store = store
        self.secret = secret
        _name = State(initialValue: secret.name)
        _showOnWatch = State(initialValue: secret.showOnWatch)
        _selectedGroupId = State(initialValue: secret.groupId)
    }
    
    var body: some View {
        Form {
            Section(header: Text("Secret Information")) {
                TextField("Account Name", text: $name)
            }
            
            Section(header: Text("Group")) {
                HStack {
                    if let groupId = selectedGroupId, let group = store.groups.first(where: { $0.id == groupId }) {
                        HStack {
                            Circle()
                                .fill(Color(hex: group.colorHex))
                                .frame(width: 20, height: 20)
                            
                            Text(group.name)
                                .padding(.leading, 4)
                        }
                    } else {
                        Text("None")
                            .foregroundColor(.gray)
                    }
                    
                    Spacer()
                    
                    Button("Select") {
                        showingGroupSheet = true
                    }
                }
            }
            
            Section {
                Toggle("Show on Apple Watch", isOn: $showOnWatch)
            }
            
            Section(footer: Text("Only the label, group, and watch visibility can be edited. For security reasons, the secret key and other parameters cannot be changed.")) {
                // Empty section, just for the footer
            }
        }
        .navigationTitle("Edit Secret")
        .sheet(isPresented: $showingGroupSheet) {
            GroupSelectionView(selectedGroupId: $selectedGroupId, store: store)
        }
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Save") {
                    saveChanges()
                }
            }
            
            ToolbarItem(placement: .navigationBarLeading) {
                Button("Cancel") {
                    presentationMode.wrappedValue.dismiss()
                }
            }
        }
    }
    
    private func saveChanges() {
        var updatedSecret = secret
        updatedSecret.name = name
        updatedSecret.showOnWatch = showOnWatch
        updatedSecret.groupId = selectedGroupId
        
        store.update(updatedSecret)
        presentationMode.wrappedValue.dismiss()
    }
}

// Group Selection View
struct GroupSelectionView: View {
    @Environment(\.presentationMode) var presentationMode
    @Binding var selectedGroupId: UUID?
    @ObservedObject var store: OTPStore
    @State private var showingAddGroup = false
    
    var body: some View {
        NavigationView {
            List {
                // Option for no group
                Button(action: {
                    selectedGroupId = nil
                    presentationMode.wrappedValue.dismiss()
                }) {
                    HStack {
                        Text("None")
                        Spacer()
                        if selectedGroupId == nil {
                            Image(systemName: "checkmark")
                        }
                    }
                }
                
                // List all available groups
                ForEach(store.groups) { group in
                    Button(action: {
                        selectedGroupId = group.id
                        presentationMode.wrappedValue.dismiss()
                    }) {
                        HStack {
                            Circle()
                                .fill(Color(hex: group.colorHex))
                                .frame(width: 20, height: 20)
                            
                            Text(group.name)
                                .padding(.leading, 4)
                            
                            Spacer()
                            
                            if selectedGroupId == group.id {
                                Image(systemName: "checkmark")
                            }
                        }
                    }
                }
            }
            .navigationTitle("Select Group")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: {
                        showingAddGroup = true
                    }) {
                        Image(systemName: "plus")
                    }
                }
                
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
            .sheet(isPresented: $showingAddGroup) {
                AddGroupView(store: store)
            }
        }
    }
}

// Time remaining indicator
struct TimeRemainingView: View {
    let period: Int
    @State private var timeRemaining = 30
    @State private var refreshToggle = false
    
    let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(lineWidth: 3)
                .opacity(0.3)
                .foregroundColor(.gray)
            
            Circle()
                .trim(from: 0.0, to: CGFloat(timeRemaining) / CGFloat(period))
                .stroke(style: StrokeStyle(lineWidth: 3, lineCap: .round, lineJoin: .round))
                .foregroundColor(timeRemaining > 5 ? .blue : .red)
                .rotationEffect(.degrees(-90))
                .animation(.linear, value: timeRemaining)
            
            Text("\(timeRemaining)")
                .font(.caption)
                .bold()
        }
        .frame(width: 30, height: 30)
        .id("circle_\(refreshToggle)") // Force refresh of the entire view
        .onReceive(timer) { _ in
            updateTimeRemaining()
        }
        .onAppear {
            updateTimeRemaining()
        }
    }
    
    private func updateTimeRemaining() {
        let seconds = Int(Date().timeIntervalSince1970) % period
        timeRemaining = period - seconds
        refreshToggle.toggle() // Force view refresh
    }
}

// Updated OTPCodeView to display group color
struct OTPCodeView: View {
    @ObservedObject var store: OTPStore
    let secret: OTPSecret
    var onEdit: ((OTPSecret) -> Void)? = nil
    
    @State private var refreshToggle = false
    @State private var showingToast = false
    let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                
                Text(secret.name)
                    .font(.headline)
                
                if secret.showOnWatch {
                    Image(systemName: "applewatch")
                        .foregroundColor(.blue)
                        .font(.caption)
                        .padding(.trailing, 4)
                }
                Spacer()
                
            }
            
            HStack {
                if secret.type == .totp {
                    HStack(spacing: 4) {
                        Group {
                            Text("-1:")
                                .foregroundColor(.gray)
                            Text(pastCode)
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.gray)
                                .id("past_\(refreshToggle)") // Force refresh
                        }
                        
                        Group {
                            Text("0:")
                                .bold()
                            Text(currentCode)
                                .font(.system(.body, design: .monospaced))
                                .bold()
                                .id("current_\(refreshToggle)") // Force refresh
                        }
                        
                        Group {
                            Text("+1:")
                                .foregroundColor(.gray)
                            Text(futureCode)
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.gray)
                                .id("future_\(refreshToggle)") // Force refresh
                        }
                    }
                    
                    Spacer()
                    
                    if secret.type == .totp {
                        TimeRemainingView(period: secret.period)
                            .id("circle_\(refreshToggle)") // Force refresh of the circle when codes update
                    }
                } else { // HOTP
                    Text(currentHOTPCode)
                        .font(.system(.title3, design: .monospaced))
                        .bold()
                        .id("hotp_\(refreshToggle)") // Force refresh
                    
                    Spacer()
                    
                    Button(action: {
                        store.incrementHOTPCounter(secret)
                        refreshToggle.toggle() // Force refresh
                    }) {
                        Image(systemName: "arrow.clockwise")
                            .font(.title3)
                    }
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(backgroundColor)
        )
        .cornerRadius(12)
        .contentShape(Rectangle()) // Make entire area tappable
        .onTapGesture {
            // Copy code to clipboard
            let codeToCopy = secret.type == .totp ? currentCode : currentHOTPCode
            UIPasteboard.general.string = codeToCopy
            
            // Give haptic feedback
            let generator = UINotificationFeedbackGenerator()
            generator.notificationOccurred(.success)
            
            // Show toast notification
            withAnimation {
                showingToast = true
            }
        }
        .contextMenu {
            contextMenu()
        }
        .onReceive(timer) { _ in
            if secret.type == .totp {
                // Force refresh of TOTP codes
                refreshToggle.toggle()
            }
        }
        .toast(isShowing: $showingToast, message: "Code Copied to Clipboard", duration: 1.5)
    }
    
    // Background color based on group
    private var backgroundColor: Color {
        if let group = store.getGroup(for: secret) {
            // Use a lighter version of the group color for the background
            let baseColor = Color(hex: group.colorHex)
            return baseColor.opacity(0.15)
        } else {
            // Default background if no group assigned
            return Color(.secondarySystemBackground)
        }
    }
    
    private var currentCode: String {
        guard let code = OTPGenerator.generateTOTP(for: secret) else {
            return "Invalid"
        }
        return code
    }
    
    private var pastCode: String {
        guard let code = OTPGenerator.generateTOTP(for: secret, at: Date().timeIntervalSince1970 - TimeInterval(secret.period)) else {
            return "Invalid"
        }
        return code
    }
    
    private var futureCode: String {
        guard let code = OTPGenerator.generateTOTP(for: secret, at: Date().timeIntervalSince1970 + TimeInterval(secret.period)) else {
            return "Invalid"
        }
        return code
    }
    
    private var currentHOTPCode: String {
        guard let code = OTPGenerator.generateHOTP(for: secret) else {
            return "Invalid"
        }
        return code
    }
    
    @ViewBuilder
    func contextMenu() -> some View {
        // Add Edit option
        if let editAction = onEdit {
            Button(action: {
                editAction(secret)
            }) {
                Label("Edit", systemImage: "pencil")
            }
        }
        
        Button(action: {
            store.toggleWatchVisibility(for: secret)
        }) {
            Label(
                secret.showOnWatch ? "Hide from Watch" : "Show on Watch",
                systemImage: secret.showOnWatch ? "applewatch.slash" : "applewatch"
            )
        }
        
        Divider()
        
        Button(role: .destructive, action: {
            // Find the index of this secret in the store
            if let index = store.secrets.firstIndex(where: { $0.id == secret.id }) {
                store.delete(store.secrets[index])
            }
        }) {
            Label("Delete", systemImage: "trash")
        }
    }
}

// Apple Watch management view
struct WatchManagementView: View {
    @Environment(\.presentationMode) var presentationMode
    @ObservedObject var store: OTPStore
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Codes Shown on Apple Watch")) {
                    ForEach(store.secrets) { secret in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(secret.name)
                                    .font(.headline)
                                
                                if secret.type == .totp {
                                    Text("TOTP")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                } else {
                                    Text("HOTP")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                            }
                            
                            Spacer()
                            
                            Toggle("", isOn: Binding(
                                get: { secret.showOnWatch },
                                set: { newValue in
                                    store.setWatchVisibility(for: secret, visible: newValue)
                                }
                            ))
                        }
                    }
                }
                
                Section(footer: Text("Selected codes will be securely transferred to your Apple Watch. Only the generated codes are transferred, not the secret keys.")) {
                    Button(action: {
                        // Select all
                        for secret in store.secrets {
                            store.setWatchVisibility(for: secret, visible: true)
                        }
                    }) {
                        Text("Select All")
                    }
                    
                    Button(action: {
                        // Deselect all
                        for secret in store.secrets {
                            store.setWatchVisibility(for: secret, visible: false)
                        }
                    }) {
                        Text("Deselect All")
                    }
                }
            }
            .navigationTitle("Apple Watch Codes")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
        }
    }
}

// Updated OTPListView with group management
// Updated OTPListView with simplified flow
struct OTPListView: View {
    @ObservedObject var store: OTPStore
    @State private var showingAddSheet = false
    @State private var showingWatchSheet = false
    @State private var showingGroupsSheet = false
    @State private var showingError = false
    @State private var errorMessage = ""
    
    struct EditState: Identifiable {
        var id = UUID()
        var secret: OTPSecret
    }
    @State private var editState: EditState?
    
    // State for filtering by group
    @State private var selectedFilterGroup: UUID? = nil
    
    var body: some View {
        NavigationView {
            VStack {
                // Add group filter chips if there are groups
                if !store.groups.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            // "All" filter
                            FilterChip(
                                isSelected: selectedFilterGroup == nil,
                                label: "All",
                                color: .gray
                            ) {
                                selectedFilterGroup = nil
                            }
                            
                            // Group filters
                            ForEach(store.groups) { group in
                                FilterChip(
                                    isSelected: selectedFilterGroup == group.id,
                                    label: group.name,
                                    color: Color(hex: group.colorHex)
                                ) {
                                    selectedFilterGroup = group.id
                                }
                            }
                        }
                        .padding(.horizontal)
                    }
                    .padding(.vertical, 8)
                }
                
                List {
                    ForEach(filteredSecrets) { secret in
                        OTPCodeView(
                            store: store,
                            secret: secret,
                            onEdit: { secret in
                                // Force a slight delay to ensure clean sheet presentation
                                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                                    self.editState = EditState(secret: secret)
                                }
                            }
                        )
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 4, trailing: 16))
                    }
                    .onDelete(perform: deleteSecrets)
                }
                .listStyle(PlainListStyle())
            }
            .navigationTitle("otpNow")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    // Simplified - just show the add button without a menu
                    Button(action: {
                        showingAddSheet = true
                    }) {
                        Image(systemName: "plus")
                    }
                }
                
                ToolbarItem(placement: .navigationBarLeading) {
                    EditButton()
                }
                
                ToolbarItem(placement: .bottomBar) {
                    HStack {
                        Button(action: { showingGroupsSheet = true }) {
                            Label("Manage Groups", systemImage: "folder")
                        }
                        
                        Spacer()
                        
                        Button(action: { showingWatchSheet = true }) {
                            Label("Apple Watch", systemImage: "applewatch")
                        }
                    }
                }
            }
            .sheet(isPresented: $showingAddSheet) {
                AddOTPSecretView(store: store)
            }
            .sheet(isPresented: $showingWatchSheet) {
                WatchManagementView(store: store)
            }
            .sheet(isPresented: $showingGroupsSheet) {
                GroupManagementView(store: store)
            }
            .sheet(item: $editState) { state in
                NavigationView {
                    EditOTPSecretView(store: store, secret: state.secret)
                }
            }
            .alert(isPresented: $showingError) {
                Alert(title: Text("Error"), message: Text(errorMessage), dismissButton: .default(Text("OK")))
            }
        }
    }
    
    // Filter secrets based on selected group
    private var filteredSecrets: [OTPSecret] {
        if let groupId = selectedFilterGroup {
            return store.secrets.filter { $0.groupId == groupId }
        } else {
            return store.secrets
        }
    }
    
    private func deleteSecrets(at offsets: IndexSet) {
        let secretsToDelete = offsets.map { filteredSecrets[$0] }
        for secret in secretsToDelete {
            store.delete(secret)
        }
    }
}

// Filter chip view for group filtering
struct FilterChip: View {
    let isSelected: Bool
    let label: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if isSelected {
                    Image(systemName: "checkmark")
                        .font(.caption)
                }
                
                Text(label)
                    .font(.subheadline)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(
                Capsule()
                    .fill(isSelected ? color.opacity(0.2) : Color(.systemGray5))
            )
            .overlay(
                Capsule()
                    .stroke(isSelected ? color : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
}

// Main app entry point
@main
struct AuthenticatorApp: App {
    @StateObject private var store = OTPStore()
    @StateObject private var sessionDelegate = WatchSessionDelegate()
    
    var body: some Scene {
        WindowGroup {
            OTPListView(store: store)
                .onAppear {
                    // Setup WatchConnectivity
                    if WCSession.isSupported() {
                        let session = WCSession.default
                        session.delegate = sessionDelegate
                        session.activate()
                        // Connect the store to the session delegate
                        sessionDelegate.store = store
                    }
                }
                .onDisappear {
                    store.stopWatchUpdates()
                }
        }
    }
}
