#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: calculate-version.sh CURRENT patch|minor|major" >&2
  exit 2
fi

current=$1
bump=$2
old_ifs=$IFS
IFS=.
# shellcheck disable=SC2086 # Intentional splitting on dots after replacing IFS.
set -- $current
IFS=$old_ifs
[ "$#" -eq 3 ] || { echo "invalid version: $current" >&2; exit 2; }
major=$1
minor=$2
patch=$3
case "$major.$minor.$patch" in
  *[!0-9.]*|.*|*..*|*.) echo "invalid version: $current" >&2; exit 2 ;;
esac
case "$bump" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
  *) echo "invalid bump: $bump" >&2; exit 2 ;;
esac
printf '%s.%s.%s\n' "$major" "$minor" "$patch"
