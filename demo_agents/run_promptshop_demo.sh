#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/demo_output/promptshop"
RUNTIME=60

banner() {
    echo ""
    echo "==============================================================="
    echo "$1"
    echo "==============================================================="
    echo ""
}

run_scan() {
    local title="$1"
    local image="$2"
    local source_dir="$3"
    local manifest="$4"
    local output="$5"

    banner "$title"
    agentgate trust-scan \
        --image "$image" \
        --source-dir "$source_dir" \
        --manifest "$manifest" \
        --profile both \
        --report-profile promptshop \
        --runtime-seconds "$RUNTIME" \
        --format all \
        --output "$output" \
        --fail-on block \
        || true
}

mkdir -p "$OUTPUT_DIR"

banner "PROMPTSHOP MARKETPLACE TRUST DEMO"
echo "This walkthrough simulates seller submissions entering a PromptShop-style review queue."
echo "Each scan emits reviewer-ready artifacts with the promptshop report profile."

banner "BUILDING SELLER SUBMISSION IMAGES"
docker build -t promptshop-clean-agent:latest "$SCRIPT_DIR/clean_support_agent" --quiet
docker build -t promptshop-trojanized-agent:latest "$SCRIPT_DIR/trojanized_support_agent" --quiet
docker build -t promptshop-stealth-agent:latest "$SCRIPT_DIR/stealth_exfil_agent" --quiet

run_scan \
    "SELLER SUBMISSION 1: VERIFIED CUSTOMER SUPPORT LISTING" \
    "promptshop-clean-agent:latest" \
    "$SCRIPT_DIR/clean_support_agent" \
    "$SCRIPT_DIR/clean_support_agent/trust_manifest.yaml" \
    "$OUTPUT_DIR/verified_listing"

run_scan \
    "SELLER SUBMISSION 2: HIDDEN TELEMETRY / BLOCKED LISTING" \
    "promptshop-trojanized-agent:latest" \
    "$SCRIPT_DIR/trojanized_support_agent" \
    "$SCRIPT_DIR/trojanized_support_agent/trust_manifest.yaml" \
    "$OUTPUT_DIR/blocked_listing"

run_scan \
    "SELLER SUBMISSION 3: STEALTH EXFIL / REVIEWER ESCALATION" \
    "promptshop-stealth-agent:latest" \
    "$SCRIPT_DIR/stealth_exfil_agent" \
    "$SCRIPT_DIR/stealth_exfil_agent/trust_manifest.yaml" \
    "$OUTPUT_DIR/stealth_listing"

banner "LIVE WALKTHROUGH ORDER"
echo "1. Open verified_listing/trust_scan_report.html and show the buyer trust card."
echo "2. Open blocked_listing/trust_scan_report.html and point to reviewer actions."
echo "3. Open stealth_listing/trust_scan_report.html and explain why procfs-based detection matters."
echo "4. Tie the reviewer summary back to PromptShop's marketplace curation and enterprise trust story."
