import Foundation
import ReleaseChecks
import Testing

/// The checkout stays formatted and lint-clean: `scripts/format --check` over every tracked file.
struct RepositoryFormatTests {
    @Test func everyTrackedFileIsFormattedAndLintClean() throws {
        let repository = URL(fileURLWithPath: #filePath).appendingPathComponent("../../../../..").standardized
        let check = try Shell.run(["/bin/bash", "scripts/format", "--check"], directory: repository)
        #expect(check.succeeded, "scripts/format these; fix what lint names:\n\(check.output)\(check.error)")
    }
}
