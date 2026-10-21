# Sourced by scripts/release and scripts/ship: the notes check and notarytool's credentials (never printed).
#
# notes_problem FILE: why FILE can't be a release's notes (missing, empty, template text left in), or nothing.
notes_problem() {
    [[ -f "$1" && -r "$1" ]] || { echo "no notes at $1"; return; }
    grep -q '[^[:space:]]' "$1" || { echo "the notes at $1 are empty"; return; }
    local left
    left="$(grep -n -i -E 'TODO|TBD|FIXME|XXX|lorem ipsum|<!--|\{\{|\[(insert|placeholder)' "$1" | head -1)" || true
    [[ -z "$left" ]] || echo "the notes at $1 still have template text (line $left)"
}

# An App Store Connect API key when one is configured: LTM_NOTARY_KEY (the .p8's path), LTM_NOTARY_KEY_ID and
# LTM_NOTARY_ISSUER from the environment, else from ~/.config/lighttouch/notary.env (LTM_NOTARY_CONFIG moves it;
# KEY=value lines, ~ or $HOME allowed at the start of a path, mode 600; it may also set LTM_SIGN_IDENTITY). With none
# configured, the ltm-notary keychain profile.
#
# notary_config: sets NOTARY (notarytool's arguments) and NOTARY_FROM (where they came from: "the environment", the
# file, or "keychain"), or prints why not and returns 1.
notary_config() {
    local config="${LTM_NOTARY_CONFIG:-$HOME/.config/lighttouch/notary.env}" k v
    NOTARY_FROM="the environment"
    if [[ -f "$config" ]]; then
        [[ "$(stat -f %Lp "$config")" == 600 ]] || { echo "$config must be mode 600 (chmod 600)"; return 1; }
        while IFS='=' read -r k v || [[ -n "$k" ]]; do
            k="${k#export }"
            case "$k" in LTM_NOTARY_KEY | LTM_NOTARY_KEY_ID | LTM_NOTARY_ISSUER | LTM_SIGN_IDENTITY) ;; *) continue ;; esac
            [[ -n "${!k:-}" ]] && continue
            v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
            v="${v/#\~/$HOME}"; v="${v/#\$\{HOME\}/$HOME}"
            printf -v "$k" '%s' "${v/#\$HOME/$HOME}"
            NOTARY_FROM="$config"
        done < "$config"
    fi
    if [[ -z "${LTM_NOTARY_KEY:-}${LTM_NOTARY_KEY_ID:-}${LTM_NOTARY_ISSUER:-}" ]]; then
        NOTARY=(--keychain-profile ltm-notary); NOTARY_FROM=keychain
        return 0
    fi
    [[ -n "${LTM_NOTARY_KEY:-}" && -n "${LTM_NOTARY_KEY_ID:-}" && -n "${LTM_NOTARY_ISSUER:-}" ]] \
        || { echo "LTM_NOTARY_KEY, LTM_NOTARY_KEY_ID and LTM_NOTARY_ISSUER go together (from $NOTARY_FROM)"; return 1; }
    [[ -f "$LTM_NOTARY_KEY" && -r "$LTM_NOTARY_KEY" ]] || { echo "LTM_NOTARY_KEY names no readable file"; return 1; }
    NOTARY=(--key "$LTM_NOTARY_KEY" --key-id "$LTM_NOTARY_KEY_ID" --issuer "$LTM_NOTARY_ISSUER")
}
