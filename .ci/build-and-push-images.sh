#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 2 ]]; then
	>&2 echo "Usage: $0 <image name> <tag1> ..."
	exit 1
fi

image_name="$1"
tags=("${@:2}")
work="$(mktemp -d -t attic-images.XXXXXXXXXX)"
trap 'rm -rf "$work"' EXIT

nix build .#attic-server-image .#attic-server-image-aarch64 \
	--no-link -L --print-out-paths >"$work/outputs"

index=0
while IFS= read -r output; do
	source_image="oci-archive:${output}"
	platform="$(skopeo inspect "$source_image" | jq '{os: .Os, architecture: .Architecture}')"
	skopeo --insecure-policy copy --preserve-digests \
		"$source_image" "oci:$work/layout:platform-$index"
	jq --arg ref "platform-$index" --argjson platform "$platform" \
		'.manifests[] | select(.annotations["org.opencontainers.image.ref.name"] == $ref) | del(.annotations) | .platform = $platform' \
		"$work/layout/index.json" >"$work/manifest-$index.json"
	index=$((index + 1))
done <"$work/outputs"

jq -s '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: .}' \
	"$work"/manifest-*.json >"$work/index.json"
digest="$(sha256sum "$work/index.json" | cut -d ' ' -f 1)"
size="$(wc -c <"$work/index.json")"
cp "$work/index.json" "$work/layout/blobs/sha256/$digest"
jq -n --arg digest "sha256:$digest" --argjson size "$size" \
	'{schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.index.v1+json", digest: $digest, size: $size}]}' \
	>"$work/layout/index.json"

for tag in "${tags[@]}"; do
	>&2 echo "Publishing ${image_name}:${tag}"
	skopeo --insecure-policy copy --all --preserve-digests \
		"oci:$work/layout" "docker://${image_name}:${tag}"
done
