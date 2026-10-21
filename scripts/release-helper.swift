// scripts/release's and scripts/ship's JSON and appcast checks (Foundation and CryptoKit, run as
// `swift scripts/release-helper.swift ...`):
//
//     catalog CATALOG ID...               per ID, one line: "<id> <sha1> <bytes> <url> <mirror url>..." from the
//                                         firmware catalog's source
//     release BUILD BUNDLE_ID FILE...     the release of BUILD: prints "<id> <downloadURL>". FILEs are JSON, tried in
//                                         order: `amore release --format json`'s output, then the amore CLI's cached
//                                         API answers (the app's details, whose releases carry the full id that
//                                         `amore releases list` truncates); a cached answer counts only for BUNDLE_ID.
//     appcast APPCAST BUILD KEY DMG NOTES  APPCAST's item for BUILD carries NOTES as its <description> (Amore renders
//                                         the Markdown as HTML) and an edSignature of DMG valid for KEY (SUPublicEDKey).
//
// Exit 0 with the answer, or 1 with why on stderr.
import CryptoKit
import Foundation

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(1)
}

/// A file's JSON, or the JSON after whatever a command printed before it.
func json(_ path: String) -> Any? {
    guard let data = FileManager.default.contents(atPath: path) else { return nil }
    if let value = try? JSONSerialization.jsonObject(with: data) { return value }
    guard let start = data.firstIndex(where: { $0 == UInt8(ascii: "{") || $0 == UInt8(ascii: "[") }) else { return nil }
    return try? JSONSerialization.jsonObject(with: data[start...])
}

/// Every object under `value` that is the release of `build`.
func releases(_ value: Any, build: Int) -> [[String: Any]] {
    if let object = value as? [String: Any] {
        let here = (object["bundleVersion"] as? NSNumber)?.intValue ?? Int(object["bundleVersion"] as? String ?? "")
        let match = here == build && object["id"] is String && object["downloadURL"] is String
        return (match ? [object] : []) + object.values.flatMap { releases($0, build: build) }
    }
    if let array = value as? [Any] { return array.flatMap { releases($0, build: build) } }
    return []
}

/// Words, for comparing Markdown with the HTML Amore makes of it: tags, entities' leftovers, punctuation and the
/// apostrophe's curl drop out, and a Markdown link keeps its text, not its URL (which HTML keeps in a tag).
func words(_ text: String) -> [String] {
    text.replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
        .replacingOccurrences(of: #"\]\([^)]*\)"#, with: " ", options: .regularExpression)
        .components(separatedBy: CharacterSet.alphanumerics.inverted)
        .filter { !$0.isEmpty }
}

let args = CommandLine.arguments.dropFirst()
switch args.first {
case "catalog" where args.count >= 3:
    let a = Array(args)
    guard let catalog = json(a[1]) as? [String: Any], let entries = catalog["entries"] as? [[String: Any]] else {
        die("catalog: \(a[1]) has no entries")
    }
    for id in a[2...] {
        guard let source = entries.first(where: { $0["id"] as? String == id })?["source"] as? [String: Any],
            let sha1 = source["sha1"] as? String, let url = source["url"] as? String
        else { die("catalog: no IPSW source for \(id)") }
        let mirrors = (source["mirrors"] as? [[String: Any]] ?? []).compactMap { $0["url"] as? String }
        print(([id, sha1, "\((source["bytes"] as? NSNumber)?.intValue ?? 0)", url] + mirrors).joined(separator: " "))
    }

case "release" where args.count >= 4:
    let a = Array(args)
    guard let build = Int(a[1]) else { die("release: \(a[1]) is not a build number") }
    for (index, path) in a[3...].enumerated() {
        guard let value = json(path) else { continue }
        // The upload's own answer names no app; a cached answer must be this app's.
        if index > 0, (value as? [String: Any])?["bundleIdentifier"] as? String != a[2] { continue }
        if let found = releases(value, build: build).first {
            print("\(found["id"]!) \(found["downloadURL"]!)")
            exit(0)
        }
    }
    die("no release of build \(build) in \(a[3...].joined(separator: ", "))")

case "appcast" where args.count == 6:
    let a = Array(args)
    guard let feed = FileManager.default.contents(atPath: a[1]), let xml = try? XMLDocument(data: feed) else {
        die("appcast: \(a[1]) is not XML")
    }
    let items = (try? xml.nodes(forXPath: "//item")) ?? []
    guard
        let item = items.first(where: {
            (try? $0.nodes(forXPath: "*[local-name()='version']").first?.stringValue) == a[2]
        }) as? XMLElement
    else { die("appcast: no item for build \(a[2])") }
    let description = item.elements(forName: "description").first?.stringValue ?? ""
    guard let notes = try? String(contentsOfFile: a[5], encoding: .utf8) else { die("appcast: can't read \(a[5])") }
    // ponytail: compares words, not markup; Markdown Amore renders differently (an autolink, an image) reads as different.
    let have = words(description).joined(separator: " ")
    let want = words(notes).joined(separator: " ")
    guard !want.isEmpty, have.contains(want) else {
        die("appcast: build \(a[2])'s <description> is not the notes (\(have.prefix(120))…)")
    }
    guard let enclosure = item.elements(forName: "enclosure").first,
        let signature = enclosure.attributes?.first(where: { $0.localName == "edSignature" })?.stringValue,
        let signatureData = Data(base64Encoded: signature)
    else { die("appcast: build \(a[2]) has no edSignature") }
    guard let keyData = Data(base64Encoded: a[3]),
        let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData)
    else { die("appcast: \(a[3]) is not an Ed25519 public key") }
    guard let dmg = FileManager.default.contents(atPath: a[4]) else { die("appcast: can't read \(a[4])") }
    guard key.isValidSignature(signatureData, for: dmg) else {
        die("appcast: build \(a[2])'s edSignature does not verify \(a[4]) with SUPublicEDKey")
    }
    print("appcast: build \(a[2]) carries the notes and a valid edSignature")

default:
    die(
        "usage: release-helper.swift catalog CATALOG ID... | release BUILD BUNDLE_ID FILE... | appcast APPCAST BUILD KEY DMG NOTES"
    )
}
