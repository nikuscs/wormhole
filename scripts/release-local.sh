#!/usr/bin/env bash
set -euo pipefail

readonly DIST_VERSION=0.32.0
readonly MAC_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
readonly LINUX_TARGETS=(aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu)

usage() {
    cat >&2 <<'EOF'
usage:
  scripts/release-local.sh build patch|minor|major [--unsigned] [--skip-gate]
  scripts/release-local.sh publish vX.Y.Z [--yes]

build creates and validates every release artifact before preserving an unpushed
release commit under refs/wormhole-release/vX.Y.Z. By default it signs and
notarizes macOS archives. --unsigned is for build validation only and cannot be
published. publish fast-forwards main to the exact commit that was built, creates
and atomically pushes the tag, runs make signoff, creates the GitHub release, and
updates the Homebrew tap.
EOF
    exit 2
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

repo_root() {
    local script_dir
    script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    git -C "$script_dir/.." rev-parse --show-toplevel 2>/dev/null \
        || fail "release script is not inside the Wormhole repository"
}

current_version() {
    sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -1
}

validate_tag() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid release tag: $1"
}

require_clean_main() {
    [[ "$(git -C "$ROOT" branch --show-current)" == main ]] || fail "release commands must run from main"
    [[ -z "$(git -C "$ROOT" status --porcelain)" ]] || fail "working tree must be clean"
}

require_synced_main() {
    git -C "$ROOT" fetch origin main --tags
    local head remote
    head=$(git -C "$ROOT" rev-parse HEAD)
    remote=$(git -C "$ROOT" rev-parse origin/main)
    [[ "$head" == "$remote" ]] || fail "main must exactly match origin/main"
}

release_ref() {
    printf 'refs/wormhole-release/%s\n' "$1"
}

release_dir() {
    printf '%s/target/release-local/%s\n' "$ROOT" "$1"
}

update_release_files() {
    local worktree=$1 version=$2
    VERSION="$version" WORKTREE="$worktree" python3 - <<'PY'
import datetime
import json
import os
import re
from pathlib import Path

root = Path(os.environ["WORKTREE"])
version = os.environ["VERSION"]
cargo = root / "Cargo.toml"
cargo.write_text(
    re.sub(r'(?m)^version = "[^"]+"$', f'version = "{version}"', cargo.read_text(), count=1)
)

changelog = root / "CHANGELOG.md"
text = changelog.read_text()
heading = f"## [Unreleased]\n\n## [{version}] - {datetime.date.today().isoformat()}"
if "## [Unreleased]" not in text:
    raise SystemExit("CHANGELOG.md has no Unreleased heading")
text = text.replace("## [Unreleased]", heading, 1)
text = re.sub(
    r"(?m)^\[Unreleased\]: .*$",
    f"[Unreleased]: https://github.com/nikuscs/wormhole/compare/v{version}...HEAD",
    text,
    count=1,
)
link = f"[{version}]: https://github.com/nikuscs/wormhole/releases/tag/v{version}"
if link not in text:
    text = text.rstrip() + f"\n{link}\n"
changelog.write_text(text)

for relative in (
    "crates/wormhole-cli/tests/fixtures/local-api.openapi.json",
    "crates/wormholed/tests/fixtures/admin-api.openapi.json",
):
    fixture = root / relative
    document = json.loads(fixture.read_text())
    document["info"]["version"] = version
    fixture.write_text(json.dumps(document, indent=2) + "\n")
PY
}

run_gate() {
    local worktree=$1
    make -C "$worktree" fmt lint size build test e2e shell policy
}

install_build_targets() {
    rustup target add "${MAC_TARGETS[@]}" wasm32-unknown-unknown
}

build_macos_target() {
    local worktree=$1 tag=$2 target=$3
    local manifest="$worktree/target/distrib/${target}-dist-manifest.json"
    local pending="$worktree/${target}-dist-manifest.pending.json"
    (
        cd "$worktree"
        dist build --tag="$tag" --force-tag --artifacts=local --target="$target" \
            --print=linkage --output-format=json > "$pending"
    )
    mv "$pending" "$manifest"
}

codesign_args() {
    CODESIGN_ARGS=(--force --options runtime --timestamp --sign "$SIGNING_IDENTITY")
    if [[ -n "${WORMHOLE_SIGNING_KEYCHAIN:-}" ]]; then
        CODESIGN_ARGS=(--keychain "$WORMHOLE_SIGNING_KEYCHAIN" "${CODESIGN_ARGS[@]}")
    fi
}

notarytool_args() {
    local profile=$1
    NOTARYTOOL_ARGS=(--keychain-profile "$profile")
    if [[ -n "${WORMHOLE_SIGNING_KEYCHAIN:-}" ]]; then
        NOTARYTOOL_ARGS+=(--keychain "$WORMHOLE_SIGNING_KEYCHAIN")
    fi
}

find_signing_identity() {
    local keychain_args=()
    if [[ -n "${WORMHOLE_CODESIGN_IDENTITY:-}" ]]; then
        SIGNING_IDENTITY=$WORMHOLE_CODESIGN_IDENTITY
    else
        if [[ -n "${WORMHOLE_SIGNING_KEYCHAIN:-}" ]]; then
            keychain_args=("$WORMHOLE_SIGNING_KEYCHAIN")
        fi
        SIGNING_IDENTITY=$(security find-identity -v -p codesigning "${keychain_args[@]}" \
            | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)
    fi
    [[ -n "$SIGNING_IDENTITY" ]] || fail "Developer ID Application certificate not found"
    codesign_args
}

update_archive_checksum() {
    local archive=$1 manifest=$2 checksum
    checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
    printf '%s  %s\n' "$checksum" "$(basename "$archive")" > "$archive.sha256"
    jq --arg name "$(basename "$archive")" --arg checksum "$checksum" \
        '.artifacts[$name].checksums.sha256 = $checksum' "$manifest" > "$manifest.updated"
    mv "$manifest.updated" "$manifest"
}

sign_and_notarize_archive() {
    local archive=$1 manifest=$2 profile=$3 dir binary
    dir=$(mktemp -d)
    ditto -x -k "$archive" "$dir"
    while IFS= read -r binary; do
        codesign "${CODESIGN_ARGS[@]}" "$binary"
        codesign --verify --strict --verbose=2 "$binary"
    done < <(find "$dir" -type f \( -name wormhole -o -name wormholed \))
    rm "$archive"
    (cd "$dir" && zip -qry "$archive" .)
    notarytool_args "$profile"
    local submission
    submission=$(xcrun notarytool submit "$archive" "${NOTARYTOOL_ARGS[@]}" \
        --wait --output-format json)
    if ! jq -e '.status == "Accepted"' <<< "$submission" >/dev/null; then
        printf '%s\n' "$submission" >&2
        fail "Apple rejected notarization for $(basename "$archive")"
    fi
    jq -r '"notarization accepted: \(.id)"' <<< "$submission"
    rm -rf "$dir"
    update_archive_checksum "$archive" "$manifest"
}

sign_macos_target() {
    local worktree=$1 target=$2 profile=$3
    local manifest="$worktree/target/distrib/${target}-dist-manifest.json"
    local archive found=0
    for archive in "$worktree"/target/distrib/*-"$target".zip; do
        [[ -f "$archive" ]] || continue
        found=1
        sign_and_notarize_archive "$archive" "$manifest" "$profile"
    done
    [[ "$found" == 1 ]] || fail "no macOS archives found for $target"
}

linux_platform() {
    case "$1" in
        aarch64-unknown-linux-gnu) printf 'linux/arm64\n' ;;
        x86_64-unknown-linux-gnu) printf 'linux/amd64\n' ;;
        *) fail "unsupported Linux target: $1" ;;
    esac
}

build_linux_target() {
    local worktree=$1 tag=$2 target=$3 git_common=$4
    local platform manifest command
    platform=$(linux_platform "$target")
    manifest="$worktree/${target}-dist-manifest.pending.json"
    command="set -euo pipefail
export CARGO_HOME=/tmp/cargo-home
export PATH=\"\$CARGO_HOME/bin:\$PATH\"
git config --global --add safe.directory '$worktree'
curl --proto '=https' --tlsv1.2 -LsSf 'https://github.com/axodotdev/cargo-dist/releases/download/v$DIST_VERSION/cargo-dist-installer.sh' | sh >&2
mkdir -p target/distrib
dist build --tag='$tag' --force-tag --artifacts=local --target='$target' --print=linkage --output-format=json
chmod -R a+rwX target"
    docker run --rm --platform "$platform" \
        -v "$worktree:$worktree" -v "$git_common:$git_common:ro" -w "$worktree" \
        "rust:1.97-bookworm" bash -c "$command" > "$manifest"
    mv "$manifest" "$worktree/target/distrib/${target}-dist-manifest.json"
}

build_global_artifacts() {
    local worktree=$1 tag=$2 version=$3
    (
        cd "$worktree"
        dist build --tag="$tag" --force-tag --artifacts=global --output-format=json \
            > global-dist-manifest.pending.json
        mv global-dist-manifest.pending.json target/distrib/global-dist-manifest.json
        install -m 0755 scripts/wormholed-bootstrap.sh target/distrib/wormholed-bootstrap.sh
        npm ci --prefix crates/wormholed-cloudflare
        npm run build --prefix crates/wormholed-cloudflare
        python3 scripts/package-cloudflare-worker.py \
            --version "$version" --output-dir target/distrib
        python3 scripts/generate-release-notes.py \
            --version "$version" --changelog CHANGELOG.md --output target/distrib/release-notes.md
        python3 scripts/generate-homebrew-formula.py \
            --version "$version" --artifacts target/distrib --output target/distrib/wormhole.rb
    )
}

verify_expected_artifacts() {
    local distrib=$1 target app
    for target in "${MAC_TARGETS[@]}" "${LINUX_TARGETS[@]}"; do
        for app in wormhole-cli wormholed; do
            [[ -f "$distrib/$app-$target.zip" ]] || fail "missing artifact: $app-$target.zip"
            [[ -f "$distrib/$app-$target.zip.sha256" ]] || fail "missing checksum: $app-$target.zip.sha256"
        done
    done
    for artifact in wormhole-cli-installer.sh wormholed-installer.sh wormhole-cli.rb wormholed.rb \
        release-notes.md source.tar.gz source.tar.gz.sha256 wormhole.rb wormholed-bootstrap.sh \
        wormholed-cloudflare-worker.tar.gz wormholed-cloudflare-worker.tar.gz.sha256; do
        [[ -f "$distrib/$artifact" ]] || fail "missing artifact: $artifact"
    done
    local checksum
    for checksum in "$distrib"/*.sha256; do
        (cd "$distrib" && shasum -a 256 -c "$(basename "$checksum")")
    done
}

copy_release_outputs() {
    local distrib=$1 output=$2 path
    rm -rf "$output"
    mkdir -p "$output"
    while IFS= read -r path; do
        cp "$path" "$output/"
    done < <(find "$distrib" -maxdepth 1 -type f -print)
}

cleanup_release_worktree() {
    if [[ -n "${CLEANUP_WORKTREE:-}" ]]; then
        git -C "$ROOT" worktree remove --force "$CLEANUP_WORKTREE" >/dev/null 2>&1 || true
    fi
    if [[ -n "${CLEANUP_STAGE:-}" ]]; then
        rm -rf "$CLEANUP_STAGE" >/dev/null 2>&1 || true
    fi
    CLEANUP_WORKTREE=
    CLEANUP_STAGE=
}

write_state() {
    local output=$1 tag=$2 version=$3 bump=$4 source_sha=$5 release_sha=$6 signed=$7
    jq -n --arg tag "$tag" --arg version "$version" --arg bump "$bump" \
        --arg source_sha "$source_sha" --arg release_sha "$release_sha" \
        --argjson signed "$signed" \
        '{schema: 1, tag: $tag, version: $version, bump: $bump, source_sha: $source_sha,
          release_sha: $release_sha, signed_and_notarized: $signed}' > "$output/release-state.json"
}

build_release() {
    [[ $# -ge 1 ]] || usage
    local bump=$1 unsigned=false skip_gate=false option
    shift
    for option in "$@"; do
        case "$option" in
            --unsigned) unsigned=true ;;
            --skip-gate) skip_gate=true ;;
            *) usage ;;
        esac
    done
    [[ "$bump" =~ ^(patch|minor|major)$ ]] || usage

    require_command cargo
    require_command dist
    require_command docker
    require_command jq
    require_command npm
    require_command python3
    require_command rustup
    require_clean_main
    require_synced_main

    local current version tag ref output source_sha stage worktree git_common release_sha profile
    current=$(current_version)
    version=$("$ROOT/scripts/calculate-version.sh" "$current" "$bump")
    if [[ "$current" == 0.0.0 && "$version" != 0.1.0 ]]; then
        fail "the first release must be v0.1.0; use a minor bump"
    fi
    tag="v$version"
    ref=$(release_ref "$tag")
    output=$(release_dir "$tag")
    source_sha=$(git -C "$ROOT" rev-parse HEAD)
    git -C "$ROOT" show-ref --verify --quiet "$ref" && fail "local release already built: $tag"
    [[ -z "$(git -C "$ROOT" tag --list "$tag")" ]] || fail "tag already exists locally: $tag"
    [[ -z "$(git -C "$ROOT" ls-remote --tags origin "refs/tags/$tag")" ]] || fail "tag already exists on origin: $tag"

    profile=${WORMHOLE_NOTARY_PROFILE:-wormhole-release}
    if [[ "$unsigned" == false ]]; then
        require_command security
        require_command codesign
        require_command xcrun
        find_signing_identity
        notarytool_args "$profile"
        xcrun notarytool history "${NOTARYTOOL_ARGS[@]}" >/dev/null
    fi

    stage=$(mktemp -d)
    worktree="$stage/source"
    CLEANUP_STAGE=$stage
    CLEANUP_WORKTREE=$worktree
    trap cleanup_release_worktree EXIT
    git -C "$ROOT" worktree add --detach "$worktree" "$source_sha"
    update_release_files "$worktree" "$version"
    (cd "$worktree" && cargo check --workspace)
    git -C "$worktree" add Cargo.toml Cargo.lock CHANGELOG.md \
        crates/wormhole-cli/tests/fixtures/local-api.openapi.json \
        crates/wormholed/tests/fixtures/admin-api.openapi.json
    git -C "$worktree" diff --cached --check
    git -C "$worktree" -c commit.gpgsign=false commit -m "chore: release $tag [skip ci]"
    release_sha=$(git -C "$worktree" rev-parse HEAD)

    if [[ "$skip_gate" == false ]]; then
        run_gate "$worktree"
    fi
    install_build_targets
    mkdir -p "$worktree/target/distrib"
    local target
    for target in "${MAC_TARGETS[@]}"; do
        build_macos_target "$worktree" "$tag" "$target"
        if [[ "$unsigned" == false ]]; then
            sign_macos_target "$worktree" "$target" "$profile"
        fi
    done

    git_common=$(cd "$(git -C "$ROOT" rev-parse --git-common-dir)" && pwd)
    for target in "${LINUX_TARGETS[@]}"; do
        build_linux_target "$worktree" "$tag" "$target" "$git_common"
    done
    build_global_artifacts "$worktree" "$tag" "$version"
    verify_expected_artifacts "$worktree/target/distrib"
    copy_release_outputs "$worktree/target/distrib" "$output"
    write_state "$output" "$tag" "$version" "$bump" "$source_sha" "$release_sha" "$([[ "$unsigned" == false ]] && printf true || printf false)"
    git -C "$ROOT" update-ref "$ref" "$release_sha"
    printf 'built %s from %s\nartifacts: %s\nrelease ref: %s\n' "$tag" "$source_sha" "$output" "$ref"
    if [[ "$unsigned" == true ]]; then
        printf 'unsigned validation build: publish is disabled\n'
    else
        printf 'publish with: scripts/release-local.sh publish %s\n' "$tag"
    fi
    cleanup_release_worktree
    trap - EXIT
}

verify_release_state() {
    local state=$1 tag=$2
    jq -e --arg tag "$tag" \
        '.schema == 1 and .tag == $tag and .signed_and_notarized == true' "$state" >/dev/null \
        || fail "release state is missing, mismatched, or unsigned"
}

update_homebrew_tap() {
    local tag=$1 output=$2
    local tap=${WORMHOLE_HOMEBREW_TAP:-$HOME/projects/homebrew-tap}
    [[ -d "$tap/.git" ]] || fail "Homebrew tap repository not found: $tap"
    [[ "$(git -C "$tap" branch --show-current)" == main ]] \
        || fail "Homebrew tap must be on main"
    [[ -z "$(git -C "$tap" status --porcelain)" ]] \
        || fail "Homebrew tap working tree must be clean"
    git -C "$tap" fetch origin main
    [[ "$(git -C "$tap" rev-parse HEAD)" == "$(git -C "$tap" rev-parse origin/main)" ]] \
        || fail "Homebrew tap main must exactly match origin/main"
    install -m 0644 "$output/wormhole.rb" "$tap/Formula/wormhole.rb"
    git -C "$tap" diff --check
    ! git -C "$tap" diff --quiet -- Formula/wormhole.rb \
        || fail "generated Homebrew formula did not change"
    git -C "$tap" add Formula/wormhole.rb
    git -C "$tap" commit -m "Update Wormhole to $tag"
    git -C "$tap" push origin main
}

publish_release() {
    [[ $# -ge 1 ]] || usage
    local tag=$1 assume_yes=false
    shift
    [[ $# -le 1 ]] || usage
    if [[ $# == 1 ]]; then
        [[ "$1" == --yes ]] || usage
        assume_yes=true
    fi
    validate_tag "$tag"
    require_command gh
    require_command jq
    require_clean_main
    require_synced_main

    local output state ref source_sha release_sha answer checksum path
    output=$(release_dir "$tag")
    state="$output/release-state.json"
    ref=$(release_ref "$tag")
    [[ -f "$state" ]] || fail "no local build state for $tag"
    verify_release_state "$state" "$tag"
    source_sha=$(jq -r .source_sha "$state")
    release_sha=$(jq -r .release_sha "$state")
    [[ "$(git -C "$ROOT" rev-parse HEAD)" == "$source_sha" ]] || fail "main changed after artifacts were built; rebuild the release"
    [[ "$(git -C "$ROOT" rev-parse "$ref")" == "$release_sha" ]] || fail "local release ref does not match built commit"
    [[ -z "$(git -C "$ROOT" tag --list "$tag")" ]] || fail "tag already exists locally: $tag"
    [[ -z "$(git -C "$ROOT" ls-remote --tags origin "refs/tags/$tag")" ]] || fail "tag already exists on origin: $tag"
    gh release view "$tag" >/dev/null 2>&1 && fail "GitHub release already exists: $tag"
    for checksum in "$output"/*.sha256; do
        (cd "$output" && shasum -a 256 -c "$(basename "$checksum")")
    done

    if [[ "$assume_yes" == false ]]; then
        printf 'Publish %s, push main and its tag, attest it, and create the GitHub release? [y/N] ' "$tag" >&2
        read -r answer
        [[ "$answer" == y || "$answer" == Y ]] || fail "publish cancelled"
    fi

    git -C "$ROOT" merge --ff-only "$release_sha"
    git -C "$ROOT" tag -a "$tag" -m "Release $tag"
    git -C "$ROOT" push --atomic origin HEAD:main "$tag"
    make -C "$ROOT" signoff

    set --
    while IFS= read -r path; do
        set -- "$@" "$path"
    done < <(find "$output" -maxdepth 1 -type f ! -name '*.json' ! -name '*-dist-manifest*' \
        ! -name 'release-notes.md' -print | sort)
    [[ $# -gt 0 ]] || fail "no release assets found"
    gh release create "$tag" --verify-tag --title "Wormhole $tag" \
        --notes-file "$output/release-notes.md" "$@"
    update_homebrew_tap "$tag" "$output"
    git -C "$ROOT" update-ref -d "$ref"
    printf 'published %s\n' "$tag"
}

ROOT=$(repo_root)
cd "$ROOT"
[[ $# -ge 1 ]] || usage
command=$1
shift
case "$command" in
    build) build_release "$@" ;;
    publish) publish_release "$@" ;;
    *) usage ;;
esac
