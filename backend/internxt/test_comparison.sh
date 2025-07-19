#!/bin/bash

################################################################################
# Internxt Native vs WebDAV Performance Comparison Test Script
################################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCLONE_BIN="$(cd "$SCRIPT_DIR/../.." && pwd)/rclone"
TEST_FILES_DIR="/home/josez/test/rclone test files"
RESULTS_DIR="/home/josez/test/rclone test results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/results_${TIMESTAMP}.md"
CSV_FILE="$RESULTS_DIR/results_${TIMESTAMP}.csv"

# Remote names
NATIVE_REMOTE="internxt:"
WEBDAV_REMOTE="inxtdav:"

# Test directories on remotes (organized for easy deletion)
NATIVE_TEST_PATH="${NATIVE_REMOTE}tests/rclone"
WEBDAV_TEST_PATH="${WEBDAV_REMOTE}tests/webdav"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "$RESULTS_DIR"

################################################################################
# Helper Functions
################################################################################

log() {
  echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"
}

log_success() {
  echo -e "${GREEN}[✓]${NC} $*"
}

log_error() {
  echo -e "${RED}[✗]${NC} $*"
}

log_warning() {
  echo -e "${YELLOW}[!]${NC} $*"
}

# Initialize results files
init_results() {
  cat > "$RESULTS_FILE" << EOF
# Internxt Native vs WebDAV Performance Test Results

**Test Date**: $(date)
**Test Files**: $TEST_FILES_DIR
**Native Remote**: $NATIVE_REMOTE
**WebDAV Remote**: $WEBDAV_REMOTE

## Test Configuration

EOF

  # CSV header
  echo "Operation,Implementation,FileSize,TimeSeconds,ThroughputMBps,FilesCount,SuccessRate,Notes" > "$CSV_FILE"
}

# Record a test result
record_result() {
  local operation=$1
  local implementation=$2
  local file_size=$3
  local time_seconds=$4
  local files_count=$5
  local success_rate=$6
  local notes=$7

  # Calculate throughput (MB/s)
  local throughput=0
  if [ "$time_seconds" != "0" ] && [ "$time_seconds" != "FAILED" ] && [ "$time_seconds" != "0.00" ]; then
    throughput=$(awk "BEGIN {printf \"%.2f\", ($file_size / 1048576) / $time_seconds}")
  fi

  # Append to CSV
  echo "$operation,$implementation,$file_size,$time_seconds,$throughput,$files_count,$success_rate,$notes" >> "$CSV_FILE"

  log "  $implementation: ${time_seconds}s (${throughput} MB/s)"
}

# Measure execution time and return seconds
# Shows progress during operation
measure_time() {
  local start=$(date +%s.%N)

  # Run command and let output go to terminal (not captured)
  # Redirect to stderr to ensure nothing goes to stdout
  "$@" 1>&2
  local exit_code=$?

  local end=$(date +%s.%N)
  # Use awk for floating point arithmetic (more portable than bc)
  local elapsed=$(awk "BEGIN {printf \"%.2f\", $end - $start}")

  # Return ONLY the elapsed time (clean number) or FAILED
  if [ $exit_code -eq 0 ]; then
    # Print clean number to stdout (this is what gets captured)
    echo "$elapsed"
  else
    echo "FAILED"
  fi

  return $exit_code
}

# Check prerequisites
check_prerequisites() {
  log "Checking prerequisites..."

  # Check if built rclone binary exists
  if [ ! -f "$RCLONE_BIN" ]; then
    log_error "Built rclone binary not found: $RCLONE_BIN"
    log "Run: go build"
    exit 1
  fi

  log "Using rclone binary: $RCLONE_BIN"
  "$RCLONE_BIN" version | head -3

  # Check if test files exist
  if [ ! -d "$TEST_FILES_DIR" ]; then
    log_error "Test files directory not found: $TEST_FILES_DIR"
    exit 1
  fi

  # Check if native remote is configured
  if ! "$RCLONE_BIN" listremotes | grep -q "^${NATIVE_REMOTE}\$"; then
    log_error "Native remote not configured: $NATIVE_REMOTE"
    log "Run: $RCLONE_BIN config"
    exit 1
  fi

  # Check if WebDAV remote is configured
  if ! "$RCLONE_BIN" listremotes | grep -q "^${WEBDAV_REMOTE}\$"; then
    log_warning "WebDAV remote not configured: $WEBDAV_REMOTE"
    log_warning "WebDAV tests will be skipped"
    SKIP_WEBDAV=true
  fi

  log_success "Prerequisites check passed"
}

# Generate missing test files
generate_test_files() {
  log "Generating missing test files..."

  local gen_dir="$TEST_FILES_DIR/generated"
  mkdir -p "$gen_dir"/{empty,sizes,special,nested_deep,flat_wide}

  # Empty files
  if [ ! -f "$gen_dir/empty/empty_1.txt" ]; then
    log "  Creating empty files..."
    for i in {1..5}; do
      touch "$gen_dir/empty/empty_$i.txt"
    done
  fi

  # Specific sizes
  if [ ! -f "$gen_dir/sizes/file_10KB.bin" ]; then
    log "  Creating 10KB file..."
    dd if=/dev/urandom of="$gen_dir/sizes/file_10KB.bin" bs=10240 count=1 2>/dev/null
  fi

  if [ ! -f "$gen_dir/sizes/file_100KB.bin" ]; then
    log "  Creating 100KB file..."
    dd if=/dev/urandom of="$gen_dir/sizes/file_100KB.bin" bs=102400 count=1 2>/dev/null
  fi

  if [ ! -f "$gen_dir/sizes/file_1MB.bin" ]; then
    log "  Creating 1MB file..."
    dd if=/dev/urandom of="$gen_dir/sizes/file_1MB.bin" bs=1048576 count=1 2>/dev/null
  fi

  if [ ! -f "$gen_dir/sizes/file_10MB.bin" ]; then
    log "  Creating 10MB file..."
    dd if=/dev/urandom of="$gen_dir/sizes/file_10MB.bin" bs=10485760 count=1 2>/dev/null
  fi

  # Only create large files if explicitly requested
  if [ "$GENERATE_LARGE_FILES" = "true" ]; then
    if [ ! -f "$gen_dir/sizes/file_50MB.bin" ]; then
      log "  Creating 50MB file..."
      dd if=/dev/urandom of="$gen_dir/sizes/file_50MB.bin" bs=52428800 count=1 2>/dev/null
    fi

    if [ ! -f "$gen_dir/sizes/file_500MB.bin" ]; then
      log "  Creating 500MB file (this may take a while)..."
      dd if=/dev/urandom of="$gen_dir/sizes/file_500MB.bin" bs=524288000 count=1 2>/dev/null
    fi
  fi

  # Special characters
  if [ ! -f "$gen_dir/special/file with spaces.txt" ]; then
    log "  Creating files with special characters..."
    echo "test" > "$gen_dir/special/file with spaces.txt"
    echo "test" > "$gen_dir/special/file_with_@#%.txt"
    echo "test" > "$gen_dir/special/文件_chinese.txt"
  fi

  # Flat structure
  if [ ! -d "$gen_dir/flat_wide/folder_1" ]; then
    log "  Creating flat structure (100 files)..."
    for i in {1..100}; do
      echo "test $i" > "$gen_dir/flat_wide/flat_$i.txt"
    done
  fi

  log_success "Test files generated"
}

################################################################################
# Test Functions
################################################################################

# Test 1: Upload single file
test_upload_single() {
  local file=$1
  local remote=$2
  local impl=$3
  local size=$(stat -c%s "$file")
  local basename=$(basename "$file")

  log "Testing upload: $basename ($(numfmt --to=iec-i --suffix=B $size 2>/dev/null || echo "$size bytes")) - $impl"

  # Use system rclone with --no-check-certificate for WebDAV
  # Use --no-check-existing to force fresh upload even if file exists
  if [ "$impl" = "WebDAV" ]; then
    local time=$(measure_time rclone copy "$file" "${remote}test_upload/" --no-check-certificate --ignore-existing=false --progress -v)
  else
    local time=$(measure_time "$RCLONE_BIN" copy "$file" "${remote}test_upload/" --ignore-existing=false --progress -v)
  fi
  local exit_code=$?

  if [ $exit_code -eq 0 ] && [ "$time" != "FAILED" ]; then
    # Verify file actually exists on remote
    if [ "$impl" = "WebDAV" ]; then
      rclone ls "${remote}test_upload/$basename" --no-check-certificate &>/dev/null
    else
      "$RCLONE_BIN" ls "${remote}test_upload/$basename" &>/dev/null
    fi

    if [ $? -eq 0 ]; then
      record_result "Upload Single File" "$impl" "$size" "$time" "1" "100%" "$basename"
      log_success "Completed in ${time}s - verified on remote"
    else
      record_result "Upload Single File" "$impl" "$size" "FAILED" "1" "0%" "$basename - not found on remote"
      log_error "Upload reported success but file not found on remote!"
      return 1
    fi
  else
    record_result "Upload Single File" "$impl" "$size" "FAILED" "1" "0%" "$basename"
    log_error "Upload failed"
    return 1
  fi
}

# Test 2: Download single file
test_download_single() {
  local remote_path=$1
  local local_dir=$2
  local impl=$3
  local filename=$(basename "$remote_path")

  log "Testing download: $filename ($impl)"

  mkdir -p "$local_dir"

  # Use system rclone with --no-check-certificate for WebDAV
  if [ "$impl" = "WebDAV" ]; then
    local time=$(measure_time rclone copy "$remote_path" "$local_dir/" --no-check-certificate --progress)
  else
    local time=$(measure_time "$RCLONE_BIN" copy "$remote_path" "$local_dir/" --progress)
  fi
  local exit_code=$?

  if [ $exit_code -eq 0 ] && [ "$time" != "FAILED" ]; then
    local size=$(stat -c%s "$local_dir/$filename" 2>/dev/null || echo "0")
    record_result "Download Single File" "$impl" "$size" "$time" "1" "100%" "$filename"
    log_success "Completed in ${time}s"
  else
    record_result "Download Single File" "$impl" "0" "FAILED" "1" "0%" "$filename"
    log_error "Download failed"
    return 1
  fi
}

# Test 3: List directory
test_list_directory() {
  local remote=$1
  local impl=$2

  log "Testing list directory ($impl)"

  # Use system rclone with --no-check-certificate for WebDAV
  if [ "$impl" = "WebDAV" ]; then
    local time=$(measure_time rclone ls "$remote" --no-check-certificate 2>&1 >/dev/null)
    local exit_code=$?
    local file_count=$(rclone ls "$remote" --no-check-certificate 2>/dev/null | wc -l)
  else
    local time=$(measure_time "$RCLONE_BIN" ls "$remote" 2>&1 >/dev/null)
    local exit_code=$?
    local file_count=$("$RCLONE_BIN" ls "$remote" 2>/dev/null | wc -l)
  fi

  if [ $exit_code -eq 0 ] && [ "$time" != "FAILED" ]; then
    record_result "List Directory" "$impl" "0" "$time" "$file_count" "100%" ""
    log_success "Listed $file_count items in ${time}s"
  else
    record_result "List Directory" "$impl" "0" "FAILED" "0" "0%" ""
    log_error "List failed"
    return 1
  fi
}

# Test 4: Sync directory
test_sync_directory() {
  local source=$1
  local dest=$2
  local impl=$3

  log "Testing sync directory ($impl)"

  local file_count=$(find "$source" -type f 2>/dev/null | wc -l)
  local total_size=$(du -sb "$source" 2>/dev/null | cut -f1)

  log "  Syncing $file_count files ($(numfmt --to=iec-i --suffix=B $total_size 2>/dev/null || echo "$total_size bytes"))"

  # Use system rclone with --no-check-certificate for WebDAV
  if [ "$impl" = "WebDAV" ]; then
    local time=$(measure_time rclone sync "$source" "$dest" --no-check-certificate --progress)
  else
    local time=$(measure_time "$RCLONE_BIN" sync "$source" "$dest" --progress)
  fi
  local exit_code=$?

  if [ $exit_code -eq 0 ] && [ "$time" != "FAILED" ]; then
    record_result "Sync Directory" "$impl" "$total_size" "$time" "$file_count" "100%" "$file_count files"
    log_success "Synced $file_count files in ${time}s"
  else
    record_result "Sync Directory" "$impl" "$total_size" "FAILED" "$file_count" "0%" "$file_count files"
    log_error "Sync failed"
    return 1
  fi
}

# Test 5: Delete file
test_delete_file() {
  local remote_path=$1
  local impl=$2

  log "Testing delete file ($impl)"

  # Use system rclone with --no-check-certificate for WebDAV
  if [ "$impl" = "WebDAV" ]; then
    local time=$(measure_time rclone delete "$remote_path" --no-check-certificate)
  else
    local time=$(measure_time "$RCLONE_BIN" delete "$remote_path")
  fi
  local exit_code=$?

  if [ $exit_code -eq 0 ] && [ "$time" != "FAILED" ]; then
    record_result "Delete File" "$impl" "0" "$time" "1" "100%" "$(basename "$remote_path")"
    log_success "Deleted in ${time}s"
  else
    record_result "Delete File" "$impl" "0" "FAILED" "1" "0%" "$(basename "$remote_path")"
    log_error "Delete failed"
    return 1
  fi
}

# Test 6: Empty file handling
test_empty_files() {
  local remote=$1
  local impl=$2
  local empty_dir="$TEST_FILES_DIR/generated/empty"

  log "Testing empty file handling ($impl)"

  # Upload empty files
  if [ "$impl" = "WebDAV" ]; then
    log "  Uploading via WebDAV"
    local upload_time=$(measure_time rclone copy "$empty_dir" "${remote}empty_test/" --no-check-certificate --progress)
  else
    log "  Uploading with --internxt-simulate-empty-files flag"
    local upload_time=$(measure_time "$RCLONE_BIN" copy "$empty_dir" "${remote}empty_test/" --internxt-simulate-empty-files --progress)
  fi
  local upload_exit=$?

  # Download and verify
  local download_dir="/tmp/empty_download_$$"
  mkdir -p "$download_dir"

  if [ "$impl" = "WebDAV" ]; then
    local download_time=$(measure_time rclone copy "${remote}empty_test/" "$download_dir/" --no-check-certificate --progress)
    local download_exit=$?
    local uploaded_count=$(rclone ls "${remote}empty_test/" --no-check-certificate 2>/dev/null | wc -l)
  else
    local download_time=$(measure_time "$RCLONE_BIN" copy "${remote}empty_test/" "$download_dir/" --progress)
    local download_exit=$?
    local uploaded_count=$("$RCLONE_BIN" ls "${remote}empty_test/" 2>/dev/null | wc -l)
  fi

  local downloaded_count=$(find "$download_dir" -type f 2>/dev/null | wc -l)

  if [ $upload_exit -eq 0 ] && [ $download_exit -eq 0 ] && [ "$uploaded_count" -eq "$downloaded_count" ] && [ "$uploaded_count" -gt 0 ]; then
    record_result "Empty Files" "$impl" "0" "$upload_time" "$uploaded_count" "100%" "Upload+Download"
    log_success "Empty file test passed: $uploaded_count files uploaded and downloaded"
  else
    record_result "Empty Files" "$impl" "0" "FAILED" "0" "0%" "Mismatch: $uploaded_count up, $downloaded_count down"
    log_error "Empty file test failed (up:$uploaded_count, down:$downloaded_count)"
    return 1
  fi

  # Cleanup
  rm -rf "$download_dir"
 # "$RCLONE_BIN" purge "${remote}empty_test/" 2>/dev/null || true
}

# Test 7: Concurrent operations
test_concurrent_operations() {
  local source=$1
  local remote=$2
  local impl=$3
  local transfers=${4:-8}

  log "Testing concurrent operations with $transfers transfers ($impl)"

  local file_count=$(find "$source" -type f 2>/dev/null | wc -l)
  local total_size=$(du -sb "$source" 2>/dev/null | cut -f1)

  log "  Copying $file_count files ($(numfmt --to=iec-i --suffix=B $total_size 2>/dev/null || echo "$total_size bytes"))"

  # Use system rclone with --no-check-certificate for WebDAV
  if [ "$impl" = "WebDAV" ]; then
    local time=$(measure_time rclone copy "$source" "$remote" --no-check-certificate --transfers "$transfers" --progress)
  else
    local time=$(measure_time "$RCLONE_BIN" copy "$source" "$remote" --transfers "$transfers" --progress)
  fi
  local exit_code=$?

  if [ $exit_code -eq 0 ] && [ "$time" != "FAILED" ]; then
    record_result "Concurrent Ops" "$impl" "$total_size" "$time" "$file_count" "100%" "$transfers transfers"
    log_success "Completed $file_count files in ${time}s"
  else
    record_result "Concurrent Ops" "$impl" "$total_size" "FAILED" "$file_count" "0%" "$transfers transfers"
    log_error "Concurrent operation failed"
    return 1
  fi
}

################################################################################
# Main Test Execution
################################################################################

main() {
  echo "=================================================="
  echo "Internxt Native vs WebDAV Performance Comparison"
  echo "=================================================="
  echo ""

  check_prerequisites
  init_results
  generate_test_files

  echo ""
  log "Starting tests..."
  echo ""

  # Clean test directories first to ensure fresh uploads
  log "=== Preparing Test Environment ==="
  log "Cleaning test directories to ensure fresh uploads..."
  "$RCLONE_BIN" purge "$NATIVE_TEST_PATH" 2>/dev/null || true
  if [ -z "$SKIP_WEBDAV" ]; then
    rclone purge "$WEBDAV_TEST_PATH" --no-check-certificate 2>/dev/null || true
  fi
  log_success "Test directories cleaned"

  # Test 1: Upload specific file sizes
  log ""
  log "=== Test 1: Upload Performance ==="
  for file in "$TEST_FILES_DIR/generated/sizes"/*.bin; do
    [ -f "$file" ] || continue
    test_upload_single "$file" "$NATIVE_TEST_PATH/" "Native" || true
    [ -z "$SKIP_WEBDAV" ] && test_upload_single "$file" "$WEBDAV_TEST_PATH/" "WebDAV" || true
  done

  # Test 2: Upload large files (existing)
  log ""
  log "=== Test 2: Large File Upload ==="
  large_file=$(find "$TEST_FILES_DIR" -name "*.mp4" -size +100M 2>/dev/null | head -1)
  if [ -n "$large_file" ]; then
    test_upload_single "$large_file" "$NATIVE_TEST_PATH/" "Native" || true
    [ -z "$SKIP_WEBDAV" ] && test_upload_single "$large_file" "$WEBDAV_TEST_PATH/" "WebDAV" || true
  fi

  # Test 2b: Sync nested directory structure (your existing files)
  log ""
  log "=== Test 2b: Sync Nested Directory Structure (Real Files) ==="
  if [ -d "$TEST_FILES_DIR/nested 1" ]; then
    log "  Using existing nested directory structure (5 levels)"
    test_sync_directory "$TEST_FILES_DIR/nested 1" "$NATIVE_TEST_PATH/nested_real/" "Native" || true
    [ -z "$SKIP_WEBDAV" ] && test_sync_directory "$TEST_FILES_DIR/nested 1" "$WEBDAV_TEST_PATH/nested_real/" "WebDAV" || true
  else
    log_warning "Skipping: nested 1 directory not found"
  fi

  # Test 3: List directory
  log ""
  log "=== Test 3: List Directory Performance ==="
  test_list_directory "$NATIVE_TEST_PATH/" "Native" || true
  [ -z "$SKIP_WEBDAV" ] && test_list_directory "$WEBDAV_TEST_PATH/" "WebDAV" || true

  # Test 4: Empty file handling
  log ""
  log "=== Test 4: Empty File Handling ==="
  test_empty_files "$NATIVE_TEST_PATH/" "Native" || true
  [ -z "$SKIP_WEBDAV" ] && test_empty_files "$WEBDAV_TEST_PATH/" "WebDAV" || true

  # Test 5: Sync flat directory
  log ""
  log "=== Test 5: Sync Flat Directory (100 files) ==="
  test_sync_directory "$TEST_FILES_DIR/generated/flat_wide" "$NATIVE_TEST_PATH/flat_sync/" "Native" || true
  [ -z "$SKIP_WEBDAV" ] && test_sync_directory "$TEST_FILES_DIR/generated/flat_wide" "$WEBDAV_TEST_PATH/flat_sync/" "WebDAV" || true

  # Test 6: Concurrent operations (generated files)
  log ""
  log "=== Test 6: Concurrent Operations - Generated Files (8 transfers) ==="
  test_concurrent_operations "$TEST_FILES_DIR/generated/flat_wide" "$NATIVE_TEST_PATH/concurrent/" "Native" 8 || true
  [ -z "$SKIP_WEBDAV" ] && test_concurrent_operations "$TEST_FILES_DIR/generated/flat_wide" "$WEBDAV_TEST_PATH/concurrent/" "WebDAV" 8 || true

  # Test 7: Bulk operations with real files (subset)
  log ""
  log "=== Test 7: Bulk Upload - Real Files Sample ==="
  # Create a temporary directory with a sample of real files for testing
  temp_sample_dir="/tmp/rclone_test_sample_$$"
  mkdir -p "$temp_sample_dir"

  # Copy first 50 files from your test directory for bulk testing
  log "  Creating sample of 50 real files for bulk test..."
  find "$TEST_FILES_DIR" -type f ! -name "*Identifier" -size +1k -size -10M 2>/dev/null | head -50 | while read file; do
    cp "$file" "$temp_sample_dir/" 2>/dev/null || true
  done

  actual_count=$(find "$temp_sample_dir" -type f 2>/dev/null | wc -l)
  if [ "$actual_count" -gt 0 ]; then
    log "  Using $actual_count real files from your test collection"
    test_concurrent_operations "$temp_sample_dir" "$NATIVE_TEST_PATH/bulk_real/" "Native" 8 || true
    [ -z "$SKIP_WEBDAV" ] && test_concurrent_operations "$temp_sample_dir" "$WEBDAV_TEST_PATH/bulk_real/" "WebDAV" 8 || true
  else
    log_warning "No suitable files found for bulk test"
  fi

  # Cleanup temp directory
  rm -rf "$temp_sample_dir"

  echo ""
  log "=== Cleanup ==="
  log "Removing test directories from remotes..."
 # "$RCLONE_BIN" purge "$NATIVE_TEST_PATH" 2>/dev/null || log_warning "Could not purge native test dir (may not exist)"

  if [ -z "$SKIP_WEBDAV" ]; then
   # "$RCLONE_BIN" purge "$WEBDAV_TEST_PATH" 2>/dev/null || log_warning "Could not purge WebDAV test dir (may not exist)"
   echo "WebDAV test directory not purged"
  fi

  echo ""
  log_success "Tests complete!"
  log "Results saved to:"
  log "  Markdown: $RESULTS_FILE"
  log "  CSV: $CSV_FILE"
  echo ""
  log "To analyze results, run:"
  log "  ./analyze_results.sh $CSV_FILE"
  log "Or view CSV directly:"
  log "  cat $CSV_FILE | column -t -s,"
}

# Run main
main "$@"
