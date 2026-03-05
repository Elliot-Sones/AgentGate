#!/usr/bin/env bash
#
# Trust Scanner Demo — Three agents, three outcomes
#
# Usage:  ./run_demo.sh
#
# Requires: docker, agentscorer (pip install -e .)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/demo_output"
RUNTIME=60  # seconds per profile

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ─── Preflight checks ───────────────────────────────────────────────────────
banner "PREFLIGHT CHECKS"

if ! command -v docker &>/dev/null; then
    echo -e "${RED}ERROR: docker is not installed or not in PATH${NC}"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo -e "${RED}ERROR: docker daemon is not running${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker is available${NC}"

if ! command -v agentscorer &>/dev/null; then
    echo -e "${YELLOW}agentscorer CLI not found — installing in dev mode...${NC}"
    pip install -e "$PROJECT_DIR" --quiet
fi
echo -e "${GREEN}✓ agentscorer CLI is available${NC}"

mkdir -p "$OUTPUT_DIR"

# ─── Build all three images ─────────────────────────────────────────────────
banner "BUILDING DOCKER IMAGES"

echo -e "${BOLD}[1/3] Building clean-support-agent...${NC}"
docker build -t demo-clean-agent:latest "$SCRIPT_DIR/clean_support_agent" --quiet
echo -e "${GREEN}✓ demo-clean-agent:latest${NC}"

echo -e "${BOLD}[2/3] Building trojanized-support-agent...${NC}"
docker build -t demo-trojanized-agent:latest "$SCRIPT_DIR/trojanized_support_agent" --quiet
echo -e "${GREEN}✓ demo-trojanized-agent:latest${NC}"

echo -e "${BOLD}[3/3] Building stealth-exfil-agent...${NC}"
docker build -t demo-stealth-agent:latest "$SCRIPT_DIR/stealth_exfil_agent" --quiet
echo -e "${GREEN}✓ demo-stealth-agent:latest${NC}"

echo ""
echo "All images built successfully."

# ─── Scan 1: Clean Agent ────────────────────────────────────────────────────
banner "SCAN 1: CLEAN SUPPORT AGENT (expected: ALLOW)"

agentscorer trust-scan \
    --image demo-clean-agent:latest \
    --source-dir "$SCRIPT_DIR/clean_support_agent" \
    --manifest "$SCRIPT_DIR/clean_support_agent/trust_manifest.yaml" \
    --profile both \
    --runtime-seconds "$RUNTIME" \
    --format all \
    --output "$OUTPUT_DIR/clean_agent" \
    --fail-on block \
    || true

echo ""
echo -e "${GREEN}───── Clean agent scan complete ─────${NC}"

# ─── Scan 2: Trojanized Agent ──────────────────────────────────────────────
banner "SCAN 2: TROJANIZED SUPPORT AGENT (expected: BLOCK)"

agentscorer trust-scan \
    --image demo-trojanized-agent:latest \
    --source-dir "$SCRIPT_DIR/trojanized_support_agent" \
    --manifest "$SCRIPT_DIR/trojanized_support_agent/trust_manifest.yaml" \
    --profile both \
    --runtime-seconds "$RUNTIME" \
    --format all \
    --output "$OUTPUT_DIR/trojanized_agent" \
    --fail-on block \
    || true

echo ""
echo -e "${RED}───── Trojanized agent scan complete ─────${NC}"

# ─── Scan 3: Stealth Exfil Agent ───────────────────────────────────────────
banner "SCAN 3: STEALTH EXFIL AGENT (expected: BLOCK)"

agentscorer trust-scan \
    --image demo-stealth-agent:latest \
    --source-dir "$SCRIPT_DIR/stealth_exfil_agent" \
    --manifest "$SCRIPT_DIR/stealth_exfil_agent/trust_manifest.yaml" \
    --profile both \
    --runtime-seconds "$RUNTIME" \
    --format all \
    --output "$OUTPUT_DIR/stealth_agent" \
    --fail-on block \
    || true

echo ""
echo -e "${RED}───── Stealth agent scan complete ─────${NC}"

# ─── Summary ────────────────────────────────────────────────────────────────
banner "DEMO SUMMARY"

echo -e "  ${GREEN}Agent 1 (Clean):       Should show ALLOW_CLEAN or ALLOW_WITH_WARNINGS${NC}"
echo -e "  ${RED}Agent 2 (Trojanized):  Should show BLOCK — egress + canary + code signals${NC}"
echo -e "  ${RED}Agent 3 (Stealth):     Should show BLOCK — caught via procfs even with no logs${NC}"
echo ""
echo -e "  ${BOLD}Key insight:${NC} Agent 3 suppresses all stdout/stderr."
echo -e "  Log-based scanners would see nothing. Our scanner reads /proc/net/tcp"
echo -e "  directly from the container kernel and catches the connection anyway."
echo ""
echo -e "  Reports saved to: ${CYAN}${OUTPUT_DIR}/${NC}"
echo ""

# ─── Cleanup ────────────────────────────────────────────────────────────────
echo -e "${YELLOW}Clean up demo images? [y/N]${NC}"
read -r cleanup
if [[ "$cleanup" =~ ^[Yy]$ ]]; then
    docker rmi demo-clean-agent:latest demo-trojanized-agent:latest demo-stealth-agent:latest 2>/dev/null || true
    echo -e "${GREEN}✓ Demo images removed${NC}"
fi
