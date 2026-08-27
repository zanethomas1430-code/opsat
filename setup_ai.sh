#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# OPSAT local AI setup  --  build llama.cpp + fetch a small model
# ============================================================
# Runs on the OPSAT phone in Termux. Idempotent: safe to re-run; it
# skips steps already done. If it dies partway, just run it again.
#
#   bash ~/setup_ai.sh
#
# Everything is LOCAL. The only network use is a one-time download of
# the build tools and the model file. After that the AI needs no
# internet, no accounts, no cloud -- matches the OPSAT ethic.
#
# Target: your phone has 3.7G total / ~1.5G free RAM, so we use a
# 1B-parameter model at Q4 (~0.8G file, ~1.2G to run). This is the
# realistic ceiling; bigger models would get OOM-killed.
set -e

AI_DIR="$HOME/opsat-ai"
LLAMA_DIR="$AI_DIR/llama.cpp"
MODEL_DIR="$AI_DIR/models"
MODEL_FILE="$MODEL_DIR/opsat-brain.gguf"

# A small, capable, permissively-licensed instruct model in GGUF Q4_K_M.
# Llama-3.2-1B-Instruct is a good size/quality balance for 1.5G RAM.
MODEL_URL="https://huggingface.co/bartowski/Llama-3.2-1B-Instruct-GGUF/resolve/main/Llama-3.2-1B-Instruct-Q4_K_M.gguf"

echo "== OPSAT AI setup =="
echo "   dir: $AI_DIR"
mkdir -p "$AI_DIR" "$MODEL_DIR"

# ---- 1. build tools -------------------------------------------------
echo
echo "[1/4] installing build tools (skips if present)..."
pkg install -y git cmake clang make wget > /dev/null 2>&1 || {
    echo "  pkg install hit a snag; trying 'pkg update' first..."
    pkg update -y && pkg install -y git cmake clang make wget
}
echo "  ok."

# ---- 2. clone llama.cpp ---------------------------------------------
echo
echo "[2/4] getting llama.cpp source..."
if [ -d "$LLAMA_DIR/.git" ]; then
    echo "  already cloned; pulling latest."
    git -C "$LLAMA_DIR" pull --ff-only || echo "  (pull skipped)"
else
    git clone --depth 1 https://github.com/ggerganov/llama.cpp "$LLAMA_DIR"
fi
echo "  ok."

# ---- 3. build (the long step) ---------------------------------------
echo
echo "[3/4] building llama.cpp -- this is the slow part, 15-40 min."
echo "      leave the phone plugged in and the screen on."
if [ -f "$LLAMA_DIR/build/bin/llama-server" ]; then
    echo "  build already exists; skipping. (delete $LLAMA_DIR/build to force rebuild)"
else
    cd "$LLAMA_DIR"
    # CPU-only build; no GPU on this path. -j2 keeps RAM use sane on a 4G phone.
    cmake -B build -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF > /dev/null
    cmake --build build --config Release -j2 --target llama-server llama-cli
fi
echo "  ok -- llama-server built."

# ---- 4. fetch the model ---------------------------------------------
echo
echo "[4/4] fetching the model (~0.8 GB, one time)..."
if [ -f "$MODEL_FILE" ]; then
    SIZE=$(stat -c%s "$MODEL_FILE" 2>/dev/null || echo 0)
    if [ "$SIZE" -gt 500000000 ]; then
        echo "  model already present (${SIZE} bytes); skipping."
    else
        echo "  partial/small model file found; re-downloading."
        rm -f "$MODEL_FILE"
    fi
fi
if [ ! -f "$MODEL_FILE" ]; then
    # -C - resumes a partial download if the connection drops
    wget -c -O "$MODEL_FILE" "$MODEL_URL"
fi
echo "  ok."

# ---- write the launcher ---------------------------------------------
cat > "$AI_DIR/start-ai.sh" << 'LAUNCH'
#!/data/data/com.termux/files/usr/bin/bash
# Start the OPSAT AI on port 8081 (the main OPSAT server stays on 8080).
# Memory-tight: we cap context small and threads at 2 to fit 1.5G RAM.
AI_DIR="$HOME/opsat-ai"
exec "$AI_DIR/llama.cpp/build/bin/llama-server" \
    -m "$AI_DIR/models/opsat-brain.gguf" \
    --host 127.0.0.1 --port 8081 \
    -c 1024 -t 2 --no-warmup
LAUNCH
chmod +x "$AI_DIR/start-ai.sh"

echo
echo "==================================================="
echo "  DONE. To run the AI:"
echo "     bash ~/opsat-ai/start-ai.sh"
echo "  It serves on http://127.0.0.1:8081"
echo "  First response is slow (model loads into RAM)."
echo
echo "  MEMORY NOTE: with only ~1.5G free, you may need to"
echo "  stop the sensor streams (Ctrl-C the main server)"
echo "  while the AI is loaded, or run them one at a time."
echo "==================================================="
