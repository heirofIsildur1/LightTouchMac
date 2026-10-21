#!/bin/bash
# scripts/ship's and scripts/release's logic that needs no Apple service: the next free tag, the notes check, the
# notary config (environment, file, mode, partial keys), filling the IPSW cache (a local clone, a wrong copy refused,
# a download checked), pruning old archives, the argument checks both scripts make before any work, and
# release-helper.swift's catalog, release-id and appcast checks (a real Ed25519 signature, a tampered DMG).
# Prints ok/FAIL per check; exits 1 on any FAIL.
#     tests/scripts/ship.sh
set -uo pipefail
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/ltm-ship-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
T="$(cd "$T" && pwd -P)"
failed=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; failed=1; fi; }
source "$SRC/scripts/ship"
HELPER=(swift "$SRC/scripts/release-helper.swift")

# tags
check "a free date is the bare tag" '[[ "$(next_tag v1.0-2026.10.21)" == v1.0-2026.10.21 ]]'
check "a taken date gets b" '[[ "$(next_tag v1.0-2026.10.21 v1.0-2026.10.21)" == v1.0-2026.10.21b ]]'
check "b taken gets c" '[[ "$(next_tag v1.0-2026.10.21 v1.0-2026.10.21b v1.0-2026.10.21)" == v1.0-2026.10.21c ]]'
check "another date's tag doesn't count" '[[ "$(next_tag v1.0-2026.10.21 v1.0-2026.10.20)" == v1.0-2026.10.21 ]]'

# notes
printf '## What'\''s new\n- Cover Flow shows album art.\n' > "$T/notes.md"
printf ' \n\t\n' > "$T/blank.md"
printf '## What'\''s new\n- TODO: the headline\n' > "$T/todo.md"
check "good notes pass" '[[ -z "$(notes_problem "$T/notes.md")" ]]'
check "missing notes fail" '[[ "$(notes_problem "$T/nope.md")" == "no notes at"* ]]'
check "blank notes fail" '[[ "$(notes_problem "$T/blank.md")" == *"are empty" ]]'
check "template text fails" '[[ "$(notes_problem "$T/todo.md")" == *"template text (line 2:"* ]]'

# notary config, each in a clean environment
touch "$T/key.p8"
nc() { env -i HOME="$T/home" PATH="$PATH" LTM_NOTARY_CONFIG="$T/notary.env" "$@" bash -c \
    'source "$1"; notary_config || exit 1; echo "$NOTARY_FROM|${NOTARY[*]}|${LTM_SIGN_IDENTITY:-}"' _ "$SRC/scripts/release-common.sh"; }
mkdir -p "$T/home"
check "nothing configured is the keychain profile" '[[ "$(nc)" == "keychain|--keychain-profile ltm-notary|" ]]'
check "the environment's key" '[[ "$(nc LTM_NOTARY_KEY="$T/key.p8" LTM_NOTARY_KEY_ID=K LTM_NOTARY_ISSUER=I)" == "the environment|--key $T/key.p8 --key-id K --issuer I|" ]]'
check "a partial key is refused" '[[ "$(nc LTM_NOTARY_KEY_ID=K)" == *"go together"* ]]'
check "a missing .p8 is refused" '[[ "$(nc LTM_NOTARY_KEY="$T/none.p8" LTM_NOTARY_KEY_ID=K LTM_NOTARY_ISSUER=I)" == *"no readable file" ]]'
cp "$T/key.p8" "$T/home/key.p8"
printf 'export LTM_NOTARY_KEY="~/key.p8"\nLTM_NOTARY_KEY_ID=FILEKEY\n# a comment\nLTM_NOTARY_ISSUER='\''FILEISS'\''\nLTM_SIGN_IDENTITY=Developer ID Application: X (T)\n' > "$T/notary.env"
chmod 644 "$T/notary.env"
check "a config file others can read is refused" '[[ "$(nc)" == *"must be mode 600"* ]]'
chmod 600 "$T/notary.env"
check "the config file's key, quotes and ~ undone" '[[ "$(nc)" == "$T/notary.env|--key $T/home/key.p8 --key-id FILEKEY --issuer FILEISS|Developer ID Application: X (T)" ]]'
check "the environment wins over the file" '[[ "$(nc LTM_NOTARY_KEY_ID=ENVKEY)" == *"--key-id ENVKEY --issuer FILEISS"* ]]'
printf 'LTM_NOTARY_KEY=$HOME/key.p8\nLTM_NOTARY_KEY_ID=K\nLTM_NOTARY_ISSUER=I\n' > "$T/notary.env"
check "a config path from \$HOME" '[[ "$(nc)" == *"|--key $T/home/key.p8 --key-id K "* ]]'

# IPSWs
BUILT_IN=n72ap-7E18
mkdir -p "$T/ipsw/a/b" "$T/cache" "$T/srv"
printf 'right ipsw' > "$T/ipsw/a/b/real.ipsw"
printf 'wrong ipsw' > "$T/ipsw/a/decoy.ipsw"
SHA="$(shasum -a 1 "$T/ipsw/a/b/real.ipsw" | cut -d' ' -f1)"
check "a local copy with the SHA-1 is cloned in" 'LTM_IPSW_DIRS="$T/nowhere:$T/ipsw" fill_ipsw "$T/cache" x-1 "$SHA" 10 >/dev/null && cmp -s "$T/cache/$SHA.ipsw" "$T/ipsw/a/b/real.ipsw"'
check "one in the cache is left alone" '[[ "$(LTM_IPSW_DIRS=/none fill_ipsw "$T/cache" x-1 "$SHA" 10)" == "x-1: in the cache" ]]'
rm "$T/cache/$SHA.ipsw"
mv "$T/ipsw/a/b/real.ipsw" "$T/srv/real.ipsw"
check "a same-size copy with another SHA-1 is refused, and so is a bad download" \
    '! LTM_IPSW_DIRS="$T/ipsw" fill_ipsw "$T/cache" x-1 "$SHA" 10 "file://$T/ipsw/a/decoy.ipsw" >/dev/null && [[ -z "$(ls "$T/cache")" ]]'
check "a download with the SHA-1 is taken, after a dead URL" \
    'LTM_IPSW_DIRS="$T/ipsw" fill_ipsw "$T/cache" x-1 "$SHA" 10 "file://$T/none.ipsw" "file://$T/srv/real.ipsw" >/dev/null && cmp -s "$T/cache/$SHA.ipsw" "$T/srv/real.ipsw"'
rm "$T/cache/$SHA.ipsw"
check "LTM_BUILT_IN_IPSW counts for the built-in iPod" 'LTM_BUILT_IN_IPSW="$T/srv/real.ipsw" LTM_IPSW_DIRS=/none fill_ipsw "$T/cache" n72ap-7E18 "$SHA" 10 >/dev/null'
check "the catalog's line for the built-in iPod" \
    '"${HELPER[@]}" catalog "$SRC/LightTouchMac/Resources/firmware-catalog.json" n72ap-7E18 | grep -qE "^n72ap-7E18 [0-9a-f]{40} [0-9]+ https://"'

# pruning
mkdir -p "$T/rel"
for n in 1 2 3; do mkdir -p "$T/rel/release-$n.xcarchive" "$T/rel/release-$n-export"; touch -t 20260101000$n "$T/rel/release-$n.xcarchive"; done
check "a dry prune removes nothing" 'prune_releases "$T/rel" 2 1 | grep -q "remove $T/rel/release-1.xcarchive" && [[ -d "$T/rel/release-1-export" ]]'
check "a prune keeps the newest two" 'prune_releases "$T/rel" 2 0 >/dev/null && [[ ! -e "$T/rel/release-1.xcarchive" && ! -e "$T/rel/release-1-export" && -d "$T/rel/release-2.xcarchive" && -d "$T/rel/release-3.xcarchive" ]]'

# arguments, refused before any work (exit 2)
mkdir -p "$T/X.xcarchive"
# (no notary config of this Mac's: an argument let through would reach the export of an empty archive, exit 1)
refused() { out="$(LTM_NOTARY_CONFIG="${LTM_NOTARY_CONFIG:-/none}" "$@" 2>&1)"; [[ $? == 2 && "$out" == FAIL* ]]; }
check "ship needs --notes" 'refused "$SRC/scripts/ship"'
check "ship refuses empty notes" 'refused "$SRC/scripts/ship" --notes "$T/blank.md"'
check "release --amore needs --notes" 'refused "$SRC/scripts/release" "$T/X.xcarchive" --amore'
check "release --amore refuses template notes" 'refused "$SRC/scripts/release" "$T/X.xcarchive" --amore --notes "$T/todo.md"'
check "release --publish needs --amore" 'refused "$SRC/scripts/release" "$T/X.xcarchive" --publish'
check "release refuses a partial key" 'LTM_NOTARY_CONFIG=/none LTM_NOTARY_KEY_ID=K refused "$SRC/scripts/release" "$T/X.xcarchive" --dry-run'

# the Amore release's id: the upload's answer first, else this app's cached details
printf 'Uploading…\n{"release":{"bundleVersion":1601,"id":"AAAAAAAA-0000-0000-0000-000000000001","downloadURL":"https://cdn/x.dmg"}}\n' > "$T/upload.json"
printf '{"bundleIdentifier":"other.app","releases":[{"bundleVersion":1601,"id":"BAD","downloadURL":"https://cdn/bad.dmg"}]}' > "$T/other.json"
printf '{"bundleIdentifier":"gold.samhenri.LightTouchMac","releases":[{"bundleVersion":1600,"id":"OLD","downloadURL":"u"},{"bundleVersion":1601,"id":"CACHED","downloadURL":"https://cdn/c.dmg"}]}' > "$T/details.json"
check "the id from the upload's answer" '[[ "$("${HELPER[@]}" release 1601 gold.samhenri.LightTouchMac "$T/upload.json" "$T/details.json")" == "AAAAAAAA-0000-0000-0000-000000000001 https://cdn/x.dmg" ]]'
check "else from this app's cache, not another app's" '[[ "$("${HELPER[@]}" release 1601 gold.samhenri.LightTouchMac "$T/blank.md" "$T/other.json" "$T/details.json")" == "CACHED https://cdn/c.dmg" ]]'

# the appcast: notes as HTML and an edSignature made here
printf 'disk image' > "$T/cdn.dmg"
cat > "$T/sign.swift" << 'EOF'
import CryptoKit
import Foundation
let key = Curve25519.Signing.PrivateKey()
let data = FileManager.default.contents(atPath: CommandLine.arguments[1])!
print(key.publicKey.rawRepresentation.base64EncodedString(), try! key.signature(for: data).base64EncodedString())
EOF
read -r PUB SIG < <(swift "$T/sign.swift" "$T/cdn.dmg")
appcast() {
    printf '<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item><sparkle:version>1601</sparkle:version><description>%s</description><enclosure url="https://cdn/x.dmg" sparkle:edSignature="%s" length="10"/></item></channel></rss>' "$1" "$SIG" > "$T/appcast.xml"
}
appcast '&lt;h2&gt;What’s new&lt;/h2&gt;&lt;ul&gt;&lt;li&gt;Cover Flow shows album art.&lt;/li&gt;&lt;/ul&gt;'
check "an appcast item with the notes and a valid signature" '"${HELPER[@]}" appcast "$T/appcast.xml" 1601 "$PUB" "$T/cdn.dmg" "$T/notes.md" >/dev/null'
check "another build has no item" '! "${HELPER[@]}" appcast "$T/appcast.xml" 1602 "$PUB" "$T/cdn.dmg" "$T/notes.md" 2>/dev/null'
printf 'disk imagE' > "$T/tampered.dmg"
check "a DMG the signature isn't for fails" '! "${HELPER[@]}" appcast "$T/appcast.xml" 1601 "$PUB" "$T/tampered.dmg" "$T/notes.md" 2>/dev/null'
appcast ''
check "an empty description fails" '! "${HELPER[@]}" appcast "$T/appcast.xml" 1601 "$PUB" "$T/cdn.dmg" "$T/notes.md" 2>/dev/null'
exit $failed
