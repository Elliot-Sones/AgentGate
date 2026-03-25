#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/demo_output/mem0_scan"
MEM0_DIR="/tmp/mem0"

banner() {
    echo ""
    echo "==============================================================="
    echo "$1"
    echo "==============================================================="
    echo ""
}

banner "PROMPTSHOP TRUST SCAN: MEM0 MEMORY LAYER"

# Clone mem0 if not already present
if [ ! -d "$MEM0_DIR" ]; then
    banner "CLONING MEM0"
    git clone --depth 1 https://github.com/mem0ai/mem0 "$MEM0_DIR"
else
    echo "mem0 already cloned at $MEM0_DIR"
fi

# Write trust manifest
banner "WRITING TRUST MANIFEST"
cat > "$MEM0_DIR/trust_manifest.yaml" <<'MANIFEST'
submission_id: ps-sub-mem0-001
agent_name: Mem0 Memory Layer
version: "1.0.7"
entrypoint: main.py
description: Universal memory layer for AI agents - stores, retrieves, and searches long-term memories with semantic search.
solution_category: ai_infrastructure
business_use_case: Adds persistent memory to AI agents and chatbots for personalized user experiences.

customer_data_access:
  - user_messages
  - conversation_history
  - user_metadata
  - session_data

integrations:
  - postgres
  - neo4j

business_claims:
  - memory storage and retrieval
  - semantic search over memories
  - user-level memory isolation
  - session-level memory isolation
  - agent-level memory isolation
  - memory history tracking

declared_tools:
  - add_memory
  - search_memory
  - get_memory
  - get_all_memories
  - update_memory
  - delete_memory
  - delete_all_memories
  - memory_history
  - reset

declared_external_domains: []

permissions:
  - read_user_data
  - write_user_data
  - read_conversation_history
  - write_conversation_history

dependencies:
  - service: pgvector
    env:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: postgres
  - service: neo4j
    env:
      NEO4J_AUTH: neo4j/mem0graph

runtime_env:
  POSTGRES_HOST: pgvector
  POSTGRES_PORT: "5432"
  POSTGRES_DB: postgres
  POSTGRES_USER: postgres
  POSTGRES_PASSWORD: postgres
  ENABLE_GRAPH_STORE: "true"
  NEO4J_URI: bolt://neo4j:7687
  NEO4J_USERNAME: neo4j
  NEO4J_PASSWORD: mem0graph
MANIFEST
echo "Manifest written."

# Build Docker image
banner "BUILDING MEM0 DOCKER IMAGE"
docker build -t mem0-agent:latest -f "$MEM0_DIR/server/Dockerfile" "$MEM0_DIR/server"

# Run trust scan
banner "RUNNING AGENTGATE TRUST SCAN"
mkdir -p "$OUTPUT_DIR"
agentgate trust-scan \
    --image mem0-agent:latest \
    --source-dir "$MEM0_DIR" \
    --manifest "$MEM0_DIR/trust_manifest.yaml" \
    --profile both \
    --report-profile promptshop \
    --runtime-seconds 120 \
    --format all \
    --output "$OUTPUT_DIR" \
    --fail-on block \
    || true

# Open report
banner "DONE — OPENING REPORT"
echo "Report saved to: $OUTPUT_DIR"
open "$OUTPUT_DIR/trust_scan_report.html" 2>/dev/null || echo "Open $OUTPUT_DIR/trust_scan_report.html in your browser."
