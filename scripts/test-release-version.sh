#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ "$("$root/scripts/calculate-version.sh" 0.0.0 minor)" = "0.1.0" ]
[ "$("$root/scripts/calculate-version.sh" 1.2.3 patch)" = "1.2.4" ]
[ "$("$root/scripts/calculate-version.sh" 1.2.3 major)" = "2.0.0" ]
before=$(cksum "$root/Cargo.toml" "$root/Cargo.lock" "$root/CHANGELOG.md")
"$root/scripts/calculate-version.sh" 0.0.0 minor >/dev/null
after=$(cksum "$root/Cargo.toml" "$root/Cargo.lock" "$root/CHANGELOG.md")
[ "$before" = "$after" ]
