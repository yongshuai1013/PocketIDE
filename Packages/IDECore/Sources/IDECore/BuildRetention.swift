import Foundation

/// Bounds retained files, not compiler CPU/memory or native diagnostic allocation.
enum BuildRetention {
    private static let lock = NSLock()
    static func serialized<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    static let maximumBuilds = 10
    static let maximumBytes: UInt64 = 64 * 1024 * 1024
    static let maximumLogBytes = 64 * 1024
    private static let marker = "\n[build log truncated]\n"

    static func boundedLog(_ text: String) -> String {
        guard text.utf8.count > maximumLogBytes else { return text }
        let budget = maximumLogBytes - marker.utf8.count
        var prefix = Array(text.utf8.prefix(budget / 2))
        var suffix = Array(text.utf8.suffix(budget - budget / 2))
        while String(bytes: prefix, encoding: .utf8) == nil { prefix.removeLast() }
        while String(bytes: suffix, encoding: .utf8) == nil { suffix.removeFirst() }
        return String(decoding: prefix, as: UTF8.self) + marker + String(decoding: suffix, as: UTF8.self)
    }

    static func prepare(_ configuration: NativeCConfiguration) throws {
        let fm = FileManager.default
        let builds = configuration.buildsURL.standardizedFileURL
        // Resolve parent aliases (e.g. Apple's /var -> /private/var), but never
        // accept a redirected Builds directory itself.
        if let attrs = try? fm.attributesOfItem(atPath: builds.path),
           attrs[.type] as? FileAttributeType == .typeSymbolicLink {
            throw NativeCError.invalidConfiguration("Builds directory must not be a symlink")
        }
        let canonical = builds.resolvingSymlinksInPath()
        for resource in [configuration.sdkURL, configuration.resourceURL] {
            let path = resource.standardizedFileURL.resolvingSymlinksInPath().path
            guard !contains(canonical.path, path), !contains(path, canonical.path) else {
                throw NativeCError.invalidConfiguration("Build history must not overlap SDK or compiler resources")
            }
        }
        try fm.createDirectory(at: builds, withIntermediateDirectories: true)
        try prune(builds, keeping: nil, reserveSlot: true)
    }

    static func contains(_ parent: String, _ child: String) -> Bool {
        child == parent || child.hasPrefix(parent == "/" ? "/" : parent + "/")
    }

    static func checkChild(_ url: URL, of root: URL) throws {
        let canonicalRoot = root.standardizedFileURL.resolvingSymlinksInPath()
        let canonical = url.standardizedFileURL.resolvingSymlinksInPath()
        guard contains(canonicalRoot.path, canonical.path), canonical != canonicalRoot else {
            throw NativeCError.invalidConfiguration("Build output escaped its canonical directory")
        }
        if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           attrs[.type] as? FileAttributeType == .typeSymbolicLink {
            throw NativeCError.invalidArtifact("\(url.path): symlink output rejected")
        }
    }

    static func prune(_ builds: URL, keeping current: URL?, reserveSlot: Bool = false) throws {
        let fm = FileManager.default
        var entries = [(url: URL, date: Date, bytes: UInt64)]()
        // Only UUID directories owned by this backend are eligible. Do not follow links.
        for url in try fm.contentsOfDirectory(at: builds, includingPropertiesForKeys: nil) {
            guard UUID(uuidString: url.lastPathComponent) != nil else { continue }
            let attrs = try fm.attributesOfItem(atPath: url.path)
            guard attrs[.type] as? FileAttributeType == .typeDirectory else { continue }
            entries.append((url, attrs[.modificationDate] as? Date ?? .distantPast, try diskBytes(url)))
        }
        if let current = current, let entry = entries.first(where: { $0.url.standardizedFileURL.path == current.standardizedFileURL.path }), entry.bytes > maximumBytes {
            throw NativeCError.invalidArtifact("Build exceeds 64 MiB retained-artifact limit")
        }
        entries.sort { $0.date == $1.date ? $0.url.path < $1.url.path : $0.date < $1.date }
        var total = entries.reduce(UInt64(0)) { $0 + $1.bytes }
        var count = entries.count
        for entry in entries where entry.url.standardizedFileURL.path != current?.standardizedFileURL.path {
            if count <= maximumBuilds - (reserveSlot ? 1 : 0) && total <= maximumBytes { break }
            try fm.removeItem(at: entry.url)
            count -= 1
            total -= entry.bytes
        }
    }

    static func checkCurrentSize(_ directory: URL) throws {
        guard try diskBytes(directory) <= maximumBytes else {
            throw NativeCError.invalidArtifact("Build exceeds 64 MiB retained-artifact limit")
        }
    }

    private static func diskBytes(_ directory: URL) throws -> UInt64 {
        let fm = FileManager.default
        var total: UInt64 = 0
        for child in try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
            let attrs = try fm.attributesOfItem(atPath: child.path)
            if attrs[.type] as? FileAttributeType == .typeDirectory {
                total += try diskBytes(child)
            } else { total += (attrs[.size] as? NSNumber)?.uint64Value ?? 0 }
        }
        return total
    }
}
