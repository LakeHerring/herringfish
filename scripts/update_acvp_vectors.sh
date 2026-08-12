#!/usr/bin/env bash
set -euo pipefail

REPO="https://api.github.com/repos/usnistgov/ACVP-Server/contents/gen-val/json-files"
OUT_DIR="tests/vectors"
mkdir -p "$OUT_DIR"

# List algorithm directories we care about
ALGS=(
  "ML-KEM-encapDecap-FIPS203"
  "ML-KEM-keyGen-FIPS203"
  "ML-DSA-keyGen-FIPS204"
  "ML-DSA-sigGen-FIPS204"
  "ML-DSA-sigVer-FIPS204"
  "SLH-DSA-keyGen-FIPS205"
  "SLH-DSA-sigGen-FIPS205"
  "SLH-DSA-sigVer-FIPS205"
)

for alg in "${ALGS[@]}"; do
  echo "Fetching $alg ..."
  # Get file list for this algorithm
  API_URL="https://api.github.com/repos/usnistgov/ACVP-Server/contents/gen-val/json-files/$alg"
  # Use curl + grep to find expectedResults.json raw URL
  RAW_URL=$(curl -s "$API_URL" | grep -o '"download_url": "https://[^"]*expectedResults.json"' | head -1 | cut -d'"' -f4)
  if [ -z "$RAW_URL" ]; then
    echo "  No expectedResults.json found for $alg"
    continue
  fi
  # Derive target filename - lowercase with underscores
  FILENAME=$(echo "$alg" | tr '[:upper:]' '[:lower:]' | tr '-' '_' )_expectedResults.json
  echo "  Downloading $RAW_URL -> $OUT_DIR/$FILENAME"
  curl -sL "$RAW_URL" -o "$OUT_DIR/$FILENAME"
done

echo "ACVP vectors updated in $OUT_DIR"
