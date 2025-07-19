#!/bin/bash

################################################################################
# Minimal Large File Upload Test - Internxt Native
################################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCLONE_BIN="$(cd "$SCRIPT_DIR/../.." && pwd)/rclone"
TEST_FILES_DIR="/home/josez/test/rclone test files"
RESULTS_DIR="/home/josez/test/rclone test results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Remote configuration
NATIVE_REMOTE="internxt:"
TEST_PATH="${NATIVE_REMOTE}tests/rclone/large_upload_test"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() {
  echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"
}

log_success() {
  echo -e "${GREEN}[✓]${NC} $*"
}

log_error() {
  echo -e "${RED}[✗]${NC} $*"
}

# Check prerequisites
if [ ! -f "$RCLONE_BIN" ]; then
  log_error "Built rclone binary not found: $RCLONE_BIN"
  log "Run: go build"
  exit 1
fi

log "Using rclone binary: $RCLONE_BIN"
"$RCLONE_BIN" version | head -3
echo ""

# Find the large video file (1.4GB file starting with 20251116)
log "Searching for large video file..."
LARGE_FILE=$(find "$TEST_FILES_DIR" -name "20251116*.mp4" 2>/dev/null | head -1)

if [ -z "$LARGE_FILE" ]; then
  log_error "Could not find 20251116*.mp4 file in $TEST_FILES_DIR"
  log "Searching for any large MP4 file (>1GB)..."
  LARGE_FILE=$(find "$TEST_FILES_DIR" -name "*.mp4" -size +1000M 2>/dev/null | head -1)
fi

if [ -z "$LARGE_FILE" ]; then
  log_error "No large video file found"
  exit 1
fi

FILE_SIZE=$(stat -c%s "$LARGE_FILE")
FILE_NAME=$(basename "$LARGE_FILE")
FILE_SIZE_HUMAN=$(numfmt --to=iec-i --suffix=B $FILE_SIZE 2>/dev/null || echo "$FILE_SIZE bytes")

log_success "Found: $FILE_NAME"
log "Size: $FILE_SIZE_HUMAN ($FILE_SIZE bytes)"
echo ""

# Clean test directory
log "Cleaning remote test directory..."
"$RCLONE_BIN" purge "$TEST_PATH" 2>/dev/null || true
log_success "Test directory cleaned"
echo ""

# Perform upload test
log "=================================================="
log "Starting Large File Upload Test"
log "=================================================="
log "File: $FILE_NAME"
log "Size: $FILE_SIZE_HUMAN"
log "Remote: $TEST_PATH"
echo ""

START_TIME=$(date +%s.%N)

"$RCLONE_BIN" copy "$LARGE_FILE" "$TEST_PATH/" --progress -vv

EXIT_CODE=$?
END_TIME=$(date +%s.%N)

ELAPSED=$(awk "BEGIN {printf \"%.2f\", $END_TIME - $START_TIME}")
THROUGHPUT=$(awk "BEGIN {printf \"%.2f\", ($FILE_SIZE / 1048576) / $ELAPSED}")

echo ""
log "=================================================="

if [ $EXIT_CODE -eq 0 ]; then
  # Verify file exists
  log "Verifying upload..."
  if "$RCLONE_BIN" ls "$TEST_PATH/$FILE_NAME" &>/dev/null; then
    log_success "UPLOAD SUCCESSFUL"
    log_success "Time: ${ELAPSED}s"
    log_success "Throughput: ${THROUGHPUT} MB/s"

    # Save results
    mkdir -p "$RESULTS_DIR"
    RESULT_FILE="$RESULTS_DIR/large_upload_${TIMESTAMP}.txt"
    cat > "$RESULT_FILE" << EOF
Large File Upload Test - Internxt Native
Date: $(date)
File: $FILE_NAME
Size: $FILE_SIZE_HUMAN ($FILE_SIZE bytes)
Time: ${ELAPSED}s
Throughput: ${THROUGHPUT} MB/s
Status: SUCCESS
EOF
    log "Results saved to: $RESULT_FILE"
  else
    log_error "Upload reported success but file not found on remote!"
    exit 1
  fi
else
  log_error "UPLOAD FAILED"
  exit 1
fi

log "=================================================="
