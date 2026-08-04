#!/usr/bin/env bash
set -euo pipefail

VERSION=${1:?usage: update-release-files.sh VERSION [ROOT]}
ROOT=${2:-$(cd "$(dirname "$0")/.." && pwd)}
TODAY=$(date +%F)

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'invalid version: %s\n' "$VERSION" >&2
  exit 2
}

VERSION="$VERSION" perl -0pi -e '
  my $count = s/^version = "[^"]+"$/version = "$ENV{VERSION}"/m;
  die "workspace version not found\n" unless $count == 1;
' "$ROOT/Cargo.toml"

VERSION="$VERSION" TODAY="$TODAY" perl -0pi -e '
  my $heading = "## [Unreleased]\n\n## [$ENV{VERSION}] - $ENV{TODAY}";
  my $count = s/^## \[Unreleased\]$/$heading/m;
  die "CHANGELOG.md has no Unreleased heading\n" unless $count == 1;
  my $compare = "[Unreleased]: https://github.com/nikuscs/wormhole/compare/v$ENV{VERSION}...HEAD";
  $count = s/^\[Unreleased\]: .*?$/$compare/m;
  die "CHANGELOG.md has no Unreleased link\n" unless $count == 1;
  my $link = "[$ENV{VERSION}]: https://github.com/nikuscs/wormhole/releases/tag/v$ENV{VERSION}";
  unless (index($_, $link) >= 0) {
    s/\s*\z/\n/;
    $_ .= "$link\n";
  }
' "$ROOT/CHANGELOG.md"

for relative in \
  crates/wormhole-cli/tests/fixtures/local-api.openapi.json \
  crates/wormholed/tests/fixtures/admin-api.openapi.json; do
  fixture="$ROOT/$relative"
  temporary="$fixture.tmp"
  jq --arg version "$VERSION" '.info.version = $version' "$fixture" >"$temporary"
  mv "$temporary" "$fixture"
done
