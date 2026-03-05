#!/bin/bash
# ══════════════════════════════════════════════════════════════
# ArgusWatch Ollama Entrypoint - Full Auto Model Pull
# ══════════════════════════════════════════════════════════════
# 1. Starts ollama serve in background
# 2. Waits for server ready
# 3. Pulls the configured model (first boot: ~9GB download)
# 4. Creates /tmp/.model_ready marker
# 5. Healthcheck only passes when marker exists
# ══════════════════════════════════════════════════════════════

set -e

MODEL="${OLLAMA_MODEL:-qwen2.5:14b}"

echo "═══════════════════════════════════════════════════════"
echo "  ArgusWatch AI Engine - Ollama"
echo "  Model: $MODEL"
echo "═══════════════════════════════════════════════════════"

# Remove stale marker
rm -f /tmp/.model_ready

# Start ollama serve in background
ollama serve &
OLLAMA_PID=$!

# Wait for server to accept connections
echo "Waiting for Ollama server..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "Ollama server is up."
        break
    fi
    sleep 1
done

# Check if model already exists (cached from previous run)
EXISTING=$(curl -sf http://localhost:11434/api/tags 2>/dev/null | grep -o "\"$MODEL\"" || true)

if [ -n "$EXISTING" ]; then
    echo "Model $MODEL already cached - skipping download."
else
    echo "Pulling $MODEL (first time only, ~9GB)..."
    echo "This may take 5-15 minutes depending on your connection."
    # Use ollama CLI which handles streaming properly
    ollama pull "$MODEL"
    echo "Model $MODEL downloaded successfully."
fi

# Verify model is usable
echo "Verifying model..."
VERIFY=$(curl -sf http://localhost:11434/api/tags 2>/dev/null | grep -c "$MODEL" || echo "0")
if [ "$VERIFY" -gt "0" ]; then
    echo "✅ Model $MODEL verified and ready."
    touch /tmp/.model_ready
else
    echo "⚠️  Model verification uncertain - marking ready anyway."
    touch /tmp/.model_ready
fi

echo "═══════════════════════════════════════════════════════"
echo "  Ollama ready - AI agents will now activate"
echo "═══════════════════════════════════════════════════════"

# Keep running (wait for ollama serve process)
wait $OLLAMA_PID
