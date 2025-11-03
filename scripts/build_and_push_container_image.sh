#!/usr/bin/env bash

set -euo pipefail

# Clean up ignored files to ensure reproducible builds
echo "Cleaning up ignored files (*.egg-info, __pycache__, etc.)..."
find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
echo "✓ Cleanup complete"

COMPOSE_FILE=$(yq -r '.artifacts.container.compose' rofl.yaml)
TARGET_IMAGE=$(yq -r '.services.server.image' ${COMPOSE_FILE} | cut -d '@' -f 1)

BUILDER_NAME="buildkit_25"
BUILDER_IMAGE="moby/buildkit:v0.25.1"
SOURCE_DATE_EPOCH="1762154800"

if ! docker buildx inspect "${BUILDER_NAME}" &>/dev/null; then
    docker buildx create \
        --use \
        --driver-opt image="${BUILDER_IMAGE}" \
        --name "${BUILDER_NAME}"
fi

METADATA_FILE=$(mktemp)

export SOURCE_DATE_EPOCH

# Determine output type: load locally for verification, push to registry for deployment
if [[ "${PUSH_IMAGE:-true}" == "true" ]]; then
    OUTPUT_TYPE="type=registry,name=${TARGET_IMAGE},rewrite-timestamp=true"
else
    OUTPUT_TYPE="type=docker,name=${TARGET_IMAGE},rewrite-timestamp=true"
fi

docker buildx build \
    --builder "${BUILDER_NAME}" \
    --file Dockerfile \
    --no-cache \
    --provenance false \
    --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
    --output ${OUTPUT_TYPE} \
    --metadata-file "${METADATA_FILE}" \
    .

# Output the image digest.
IMAGE_NAME=$(jq -r '."image.name" + "@" + ."containerimage.digest"' "${METADATA_FILE}")
if [[ -n "${OUTPUT_IMAGE_NAME_PATH:-}" ]]; then
    echo "${IMAGE_NAME}" > ${OUTPUT_IMAGE_NAME_PATH}
fi

if [[ "${UPDATE_COMPOSE_SHA:-false}" == "true" ]]; then
    echo "Updating ${COMPOSE_FILE} image references to ${IMAGE_NAME}"
    yq eval --inplace \
        "(.services.server.image = \"${IMAGE_NAME}\") | (.services.worker.image = \"${IMAGE_NAME}\")" \
        "${COMPOSE_FILE}"
fi

echo "${IMAGE_NAME}"
