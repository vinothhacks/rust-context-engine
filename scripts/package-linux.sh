#!/usr/bin/env bash
set -euo pipefail

binary=${1:?Usage: package-linux.sh <context-engine> <output-directory> [release-tag]}
output=${2:?Missing output directory}
test "$(uname -sm)" = "Linux x86_64"
version=$("$binary" --version)
if [[ ! $version =~ ^context-engine\ ([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?)$ ]]; then
  echo "Unexpected context-engine --version output" >&2
  exit 1
fi
version_tag="v${BASH_REMATCH[1]}"
if [[ $# -ge 3 && $3 != "$version_tag" ]]; then
  echo "Tag $3 does not match binary version $version_tag" >&2
  exit 1
fi

name="context-engine-$version_tag-x86_64-unknown-linux-gnu"
archive="$name.tar.gz"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p -- "$output" "$scratch/staged/$name" "$scratch/extracted"
cp -- "$binary" "$scratch/staged/$name/context-engine"
cp LICENSE-APACHE LICENSE-MIT NOTICE README.md "$scratch/staged/$name/"
tar -C "$scratch/staged" -czf "$output/$archive" "$name"
(
  cd "$output"
  sha256sum -- "$archive" > SHA256SUMS
  sha256sum --check --strict SHA256SUMS
  cat SHA256SUMS
)
tar -C "$scratch/extracted" -xzf "$output/$archive"
python3 scripts/verify-binary.py "$scratch/extracted/$name/context-engine"
