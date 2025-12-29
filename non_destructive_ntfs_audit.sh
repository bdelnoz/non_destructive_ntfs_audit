#!/usr/bin/env bash
# =====================================================================
# Path/Name  : /mnt/data2_78g/Security/scripts/Projects_utility/non_destructive_ntfs_audit_pico_velo_v4.0.sh
# Author      : Bruno DELNOZ
# Email       : bruno.delnoz@protonmail.com
# Version     : v4.0 – 2025-11-09
# Changelog   : see --changelog output and internal CHANGELOG block
# Target Use  : Non-destructive NTFS audit tool with exhaustive diagnostics,
#               verbose output, machine- and human-readable results,
#               safe defaults and optional non-destructive tests.
#
# Notes:
#  - This script is intended to be run on Debian/Ubuntu/Kali systems.
#  - It performs read-only and safe diagnostic actions by default.
#  - Destructive or repair actions (ntfsfix, chkdsk) are never run unless
#    explicitly permitted by user and not in simulate mode.
#  - Follow your organization's backup and change control procedures before
#    performing repair operations.
#
# IMPORTANT: This script adheres to the user's "Règles de Scripting V110".
#            It includes detailed internal comments, a comprehensive --help,
#            automatic directory creation for logs/results, and outputs both
#            the full verbose technical report and a human-readable summary
#            appended at the end of the run and saved to ./results.
# =====================================================================

set -euo pipefail
IFS=$'\n\t'

# -------------------------
#  Script metadata block
# -------------------------
SCRIPT_PATH="/mnt/data2_78g/Security/scripts/Projects_utility/non_destructive_ntfs_audit_pico_velo_v4.0.sh"
SCRIPT_NAME="$(basename "$SCRIPT_PATH")"
AUTHOR="Bruno DELNOZ"
AUTHOR_EMAIL="bruno.delnoz@protonmail.com"
VERSION="v4.0"
DATE="2025-11-09"
# Full changelog is embedded below in CHANGELOG_TEXT so --changelog prints a complete history.
CHANGELOG_TEXT=$(cat <<'CHLOG'
# CHANGELOG - non_destructive_ntfs_audit_pico_velo
- v1.0  – 2025-11-07 : Initial script baseline with read-only checks.
- v1.1  – 2025-11-08 : Added logging and ntfs basic checks.
- v1.2  – 2025-11-09 : Added SMART parsing, hashing, and initial human-readable summary.
- v2.0  – 2025-11-09 : Extended diagnostics and verbose output; results/logs directories.
- v3.0  – 2025-11-09 : Full verbose dumps, improved SMART interpretation, separate summary file.
- v3.1  – 2025-11-09 : Additional parsing, formatting and more diagnostic sentences.
- v3.2  – 2025-11-09 : Gitignore and md generation hooks added (not used here per request).
- v4.0  – 2025-11-09 : PICO-VELO major expansion: expanded diagnostics, exhaustive comments,
                     richer human-readable analysis, full CLI options and safe modes.
CHLOG
)

# -------------------------
#  Defaults and directories
# -------------------------
LOG_DIR="./logs"
RESULTS_DIR="./results"
OUTPUT_DIR="./outputs"   # optional extra outputs
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="$LOG_DIR/${SCRIPT_NAME%.sh}_$TIMESTAMP.log"
FULL_REPORT_FILE="$RESULTS_DIR/${SCRIPT_NAME%.sh}_$TIMESTAMP.full.txt"
SUMMARY_FILE="$RESULTS_DIR/${SCRIPT_NAME%.sh}_$TIMESTAMP.summary.txt"

# Defaults for operations
SIMULATE=false         # if true, do not execute destructive actions
DO_EXEC=false          # if true, run the main audit sequence
CHECK_PREREQ=false
DO_INSTALL_PREREQ=false
DO_WRITE_TEST=false    # non-destructive write test (creates temporary file then removes)
HASH_MB_DEFAULT=100
HASH_MB="$HASH_MB_DEFAULT"  # amount to hash for initial integrity check
READ_MB_DEFAULT=200
READ_MB="$READ_MB_DEFAULT"  # amount to read for performance measure
NTFSFIX_RECOMMEND=false

# -------------------------
#  Utility helper functions
# -------------------------

# log: prefix and append to log file; also print to stdout
log() {
  local msg="$*"
  local stamp
  stamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[$stamp] $msg" | tee -a "$LOG_FILE"
}

# die: print error and exit with non-zero status
die () {
  echo "ERROR: $*" | tee -a "$LOG_FILE" >&2
  exit 1
}

# ensure_dirs: create needed directories and record actions
ensure_dirs() {
  # Create directories if missing; log each action.
  if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Created log directory $LOG_DIR" >> "$LOG_FILE"
  else
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Log directory exists: $LOG_DIR" >> "$LOG_FILE"
  fi

  if [[ ! -d "$RESULTS_DIR" ]]; then
    mkdir -p "$RESULTS_DIR"
    log "Created results directory $RESULTS_DIR"
  else
    log "Results directory exists: $RESULTS_DIR"
  fi

  if [[ ! -d "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
    log "Created outputs directory $OUTPUT_DIR"
  else
    log "Outputs directory exists: $OUTPUT_DIR"
  fi
}

# show_help: CLI usage and examples
show_help() {
  cat <<EOF
$SCRIPT_NAME  $VERSION  ($DATE)
Author: $AUTHOR  <$AUTHOR_EMAIL>

Usage:
  sudo $SCRIPT_NAME [OPTIONS] <device> <mountpoint>

Required positional arguments:
  device         Block device (example: /dev/sdc)
  mountpoint     Expected mount point for device (example: /mnt/TOSHIBA), or "-" if unknown

Options:
  --help, -h             Show this help text and exit
  --exec, -exe           Execute the full audit (default: no)
  --simulate, -s         Dry-run / simulation mode. When present, no writes or repairs will occur.
  --prerequis, -pr       Check for required commands and report missing ones (no install)
  --install, -i          Attempt to install missing prerequisites via apt (Debian/Ubuntu)
  --write-test           Perform a safe temporary write/read test (requires mount and free space)
  --hash-mb N            Hash first N MiB of device (default: $HASH_MB_DEFAULT)
  --read-mb N            Read N MiB for simple throughput measurement (default: $READ_MB_DEFAULT)
  --ntfsfix-recommend    If set, script will output an ntfsfix command recommendation (does not run it)
  --changelog, -ch       Print the changelog embedded in the script and exit

Examples:
  # Dry-run full audit
  sudo $SCRIPT_NAME --simulate --exec /dev/sdc /mnt/TOSHIBA

  # Run production audit (non-destructive)
  sudo $SCRIPT_NAME --exec /dev/sdc /mnt/TOSHIBA

  # Check prerequisites
  sudo $SCRIPT_NAME --prerequis

  # Hash first 500 MiB and do read-check
  sudo $SCRIPT_NAME --exec --hash-mb 500 --read-mb 1024 /dev/sdc /mnt/TOSHIBA

Notes:
  - This script is carefully designed to be non-destructive by default.
  - If you enable write tests or allow repair tools, ensure backups exist.
  - The human-readable summary is printed at the end and saved in $SUMMARY_FILE
  - The full technical report is saved in $FULL_REPORT_FILE
EOF
}

# show_changelog prints the internal changelog (full history)
show_changelog() {
  cat <<EOF
$CHANGELOG_TEXT
EOF
}

# parse_args: parse CLI args and set flags/variables accordingly
parse_args() {
  # local index for while shift loop
  positional=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h) show_help; exit 0 ;;
      --exec|--exe|-exe) DO_EXEC=true; shift ;;
      --simulate|-s) SIMULATE=true; log "SIMULATE mode enabled"; shift ;;
      --prerequis|-pr) CHECK_PREREQ=true; shift ;;
      --install|-i) DO_INSTALL_PREREQ=true; shift ;;
      --write-test) DO_WRITE_TEST=true; shift ;;
      --hash-mb) shift; HASH_MB="$1"; shift ;;
      --read-mb) shift; READ_MB="$1"; shift ;;
      --ntfsfix-recommend) NTFSFIX_RECOMMEND=true; shift ;;
      --changelog|-ch) show_changelog; exit 0 ;;
      --) shift; break ;;
      -*)
        echo "Unknown option: $1" >&2
        show_help
        exit 1
        ;;
      *) positional+=("$1"); shift ;;
    esac
  done

  # Assign positional args
  if [[ ${#positional[@]} -ge 1 ]]; then
    DEVICE="${positional[0]}"
  fi
  if [[ ${#positional[@]} -ge 2 ]]; then
    MOUNTPOINT="${positional[1]}"
  fi

  # Validate required args when executing
  if [[ "$DO_EXEC" == true ]]; then
    if [[ -z "${DEVICE:-}" || -z "${MOUNTPOINT:-}" ]]; then
      echo "Error: device and mountpoint required for --exec" >&2
      show_help
      exit 1
    fi
  fi

  # normalize numeric values and basic validation
  if ! [[ "$HASH_MB" =~ ^[0-9]+$ ]]; then
    die "Invalid value for --hash-mb: $HASH_MB"
  fi
  if ! [[ "$READ_MB" =~ ^[0-9]+$ ]]; then
    die "Invalid value for --read-mb: $READ_MB"
  fi

  # Print arg summary to log
  log "CLI arguments parsed: DO_EXEC=$DO_EXEC SIMULATE=$SIMULATE CHECK_PREREQ=$CHECK_PREREQ DO_INSTALL_PREREQ=$DO_INSTALL_PREREQ DO_WRITE_TEST=$DO_WRITE_TEST HASH_MB=$HASH_MB READ_MB=$READ_MB NTFSFIX_RECOMMEND=$NTFSFIX_RECOMMEND"
}

# check_commands: verify required commands exist; support install
check_commands() {
  # list of useful commands; we will check them and optionally attempt apt install for missing ones
  local required=(lsblk blkid fdisk parted smartctl hdparm dd sha256sum ntfsinfo filefrag hexdump strings awk sed grep)
  local missing=()
  for cmd in "${required[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    log "Missing commands detected: ${missing[*]}"
    echo "Missing commands: ${missing[*]}" | tee -a "$LOG_FILE"
    if [[ "$DO_INSTALL_PREREQ" == true ]]; then
      log "Attempting to install missing prerequisites via apt"
      # We attempt to install only the ones that are typically in apt
      sudo apt update
      sudo apt install -y "${missing[@]}"
      # Re-check after install
      local still_missing=()
      for cmd in "${missing[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
          still_missing+=("$cmd")
        fi
      done
      if [[ ${#still_missing[@]} -gt 0 ]]; then
        log "Installation attempted but some commands are still missing: ${still_missing[*]}"
      else
        log "All prerequisites installed successfully."
      fi
    fi
  else
    log "All required commands are available."
  fi
}

# mount_check: verify that mountpoint corresponds to device if provided
mount_check() {
  # If mountpoint is '-' we skip the mountpoint check
  if [[ "$MOUNTPOINT" == "-" ]]; then
    log "Mountpoint is '-' (unknown); skipping mountpoint check"
    return
  fi

  if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    log "Mountpoint $MOUNTPOINT is currently mounted"
    # verify device for mountpoint matches provided device
    local resolved
    resolved=$(lsblk -no PKNAME "$(basename "$DEVICE")" 2>/dev/null || true)
    # Not always reliable; we will also check /proc/mounts mapping
    if grep -q "$DEVICE" /proc/mounts; then
      log "Device $DEVICE is reported in /proc/mounts as mounted"
    else
      log "Warning: device $DEVICE is not listed in /proc/mounts for mountpoint $MOUNTPOINT"
    fi
  else
    log "Mountpoint $MOUNTPOINT is not mounted"
  fi
}

# gather_partition_info: lsblk, blkid, parted/fdisk; store to report
gather_partition_info() {
  log "Collecting partition table and filesystem information for $DEVICE"
  echo "=== PARTITION & FS INFORMATION ===" >> "$FULL_REPORT_FILE"
  lsblk -o NAME,FSTYPE,LABEL,UUID,SIZE,MOUNTPOINTS -f "$DEVICE" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
  if command -v parted &>/dev/null; then
    sudo parted -l 2>/dev/null | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
  else
    sudo fdisk -l "$DEVICE" 2>/dev/null | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
  fi

  # hexdump first sectors to analyze MBR/GPT headers as read-only
  echo "=== MBR/GPT FIRST 1MB HEXDUMP (truncated) ===" >> "$FULL_REPORT_FILE"
  sudo dd if="$DEVICE" bs=512 count=2048 2>/dev/null | hexdump -C | head -n 200 >> "$FULL_REPORT_FILE"
}

# run_smart_and_parse: run smartctl and parse important values
run_smart_and_parse() {
  log "Running SMART collection for $DEVICE"
  local smart_raw
  # Capture raw SMART output to variable and file
  smart_raw="$(sudo smartctl -a "$DEVICE" 2>/dev/null || true)"
  echo "=== SMART RAW OUTPUT ===" >> "$FULL_REPORT_FILE"
  printf "%s\n" "$smart_raw" >> "$FULL_REPORT_FILE"

  # parse common attributes robustly using grep + awk; default to 'unknown' if not found
  SMART_OVERALL=$(printf "%s\n" "$smart_raw" | grep -i "SMART overall-health" -m1 || true)
  SMART_STATUS=$(printf "%s\n" "$smart_raw" | awk -F: '/SMART overall-health/ {print $2; exit}' | tr -d ' \t' || true)
  if [[ -z "$SMART_STATUS" ]]; then
    # fallback parse
    SMART_STATUS=$(printf "%s\n" "$smart_raw" | grep -i "SMART overall-health" -m1 | sed -E 's/.*: *//g' || true)
  fi
  # Attempt to extract numeric RAW values from the known attribute names
  RELOCATED_SECTORS=$(printf "%s\n" "$smart_raw" | awk '/Reallocated_Sector_Ct/ {print $10; exit}' || echo "0")
  CURRENT_PENDING=$(printf "%s\n" "$smart_raw" | awk '/Current_Pending_Sector/ {print $10; exit}' || echo "0")
  OFFLINE_UNCORRECTABLE=$(printf "%s\n" "$smart_raw" | awk '/Offline_Uncorrectable/ {print $10; exit}' || echo "0")
  POWER_ON_HOURS=$(printf "%s\n" "$smart_raw" | awk '/Power_On_Hours/ {print $10; exit}' || echo "0")
  TEMP_CELSIUS=$(printf "%s\n" "$smart_raw" | awk '/Temperature_Celsius/ {print $10; exit}' || echo "0")
  UDMA_CRC_ERRORS=$(printf "%s\n" "$smart_raw" | awk '/UDMA_CRC_Error_Count/ {print $10; exit}' || echo "0")

  # normalize empty values
  RELOCATED_SECTORS="${RELOCATED_SECTORS:-0}"
  CURRENT_PENDING="${CURRENT_PENDING:-0}"
  OFFLINE_UNCORRECTABLE="${OFFLINE_UNCORRECTABLE:-0}"
  POWER_ON_HOURS="${POWER_ON_HOURS:-0}"
  TEMP_CELSIUS="${TEMP_CELSIUS:-0}"
  UDMA_CRC_ERRORS="${UDMA_CRC_ERRORS:-0}"

  # Log parsed values
  log "SMART_STATUS=$SMART_STATUS RELOCATED=$RELOCATED_SECTORS PENDING=$CURRENT_PENDING OFFLINE_UNCORRECTABLE=$OFFLINE_UNCORRECTABLE POWER_ON_HOURS=$POWER_ON_HOURS TEMP_C=$TEMP_CELSIUS UDMA_CRC=$UDMA_CRC_ERRORS"

  # Add interpretation section to full report
  {
    echo "=== SMART PARSED SUMMARY ==="
    echo "Overall health: ${SMART_STATUS:-UNKNOWN}"
    echo "Reallocated sectors: $RELOCATED_SECTORS"
    echo "Current pending sectors: $CURRENT_PENDING"
    echo "Offline uncorrectable: $OFFLINE_UNCORRECTABLE"
    echo "Power on hours: $POWER_ON_HOURS"
    echo "Temperature Celsius (approx): $TEMP_CELSIUS"
    echo "UDMA CRC errors: $UDMA_CRC_ERRORS"
  } >> "$FULL_REPORT_FILE"
}

# perform_read_benchmark: cached and buffered read measurements using hdparm
perform_read_benchmark() {
  log "Measuring read performance via hdparm (cached and buffered)"
  # hdparm -T measures cached reads; -t measures buffered
  if command -v hdparm >/dev/null 2>&1; then
    HDPARM_OUT=$(sudo hdparm -Tt "$DEVICE" 2>/dev/null || true)
    echo "=== HDPARM RAW OUTPUT ===" >> "$FULL_REPORT_FILE"
    printf "%s\n" "$HDPARM_OUT" >> "$FULL_REPORT_FILE"
    # Extract numbers
    CACHED_READ=$(printf "%s\n" "$HDPARM_OUT" | awk -F= '/Timing cached reads/ {gsub(/[^0-9.]/,"",$2); print $2; exit}' || echo "0")
    BUFFERED_READ=$(printf "%s\n" "$HDPARM_OUT" | awk -F= '/Timing buffered disk reads/ {gsub(/[^0-9.]/,"",$2); print $2; exit}' || echo "0")
  else
    CACHED_READ="0"
    BUFFERED_READ="0"
    log "hdparm not available; skipping hdparm benchmarks"
  fi

  # Log to full report and log file
  echo "Cached read (hdparm -T): $CACHED_READ MB/sec" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
  echo "Buffered read (hdparm -t): $BUFFERED_READ MB/sec" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
}

# attempt_ntfs_fragmentation_estimate: use filefrag on a sample if available (non-destructive)
attempt_ntfs_fragmentation_estimate() {
  # Explanation: Linux cannot accurately defragment NTFS; filefrag can show fragmentation stats for files.
  # We'll sample a few large files from mountpoint (if mounted) and run filefrag to estimate fragmentation.
  if [[ "$MOUNTPOINT" == "-" ]]; then
    log "Mountpoint unknown; skipping filefrag-based fragmentation estimation"
    FRAGMENTATION_NOTE="Fragmentation estimate not available (mountpoint unknown)"
    return
  fi

  if ! mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    log "Mountpoint $MOUNTPOINT is not mounted; skipping fragmentation estimate"
    FRAGMENTATION_NOTE="Fragmentation estimate skipped (not mounted)"
    return
  fi

  if ! command -v filefrag >/dev/null 2>&1; then
    log "filefrag not installed; cannot estimate fragmentation"
    FRAGMENTATION_NOTE="filefrag not available"
    return
  fi

  # Find up to 3 largest regular files on the filesystem to sample
  IFS=$'\n'
  files=($(find "$MOUNTPOINT" -xdev -type f -size +1M -printf "%s %p\n" 2>/dev/null | sort -nr | head -n 5 | awk '{print $2}'))
  unset IFS

  if [[ ${#files[@]} -eq 0 ]]; then
    FRAGMENTATION_NOTE="No files >1MB found to estimate fragmentation"
    log "$FRAGMENTATION_NOTE"
    return
  fi

  # Run filefrag on each file and calculate mean number of extents per file
  total_extents=0
  sample_count=0
  for f in "${files[@]}"; do
    if [[ -f "$f" ]]; then
      out=$(filefrag -v "$f" 2>/dev/null || true)
      # Extract extents number from the summary line
      extents=$(printf "%s\n" "$out" | awk -F: '/extents:/ {gsub(/[^0-9]/,"",$2); print $2; exit}' || echo "0")
      extents="${extents:-0}"
      total_extents=$((total_extents + extents))
      sample_count=$((sample_count + 1))
      echo "filefrag sample: $f -> extents: $extents" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
    fi
  done

  if [[ $sample_count -gt 0 ]]; then
    avg_extents=$((total_extents / sample_count))
    FRAGMENTATION_NOTE="Estimated average extents per large-file: $avg_extents (higher = more fragmented)"
    echo "$FRAGMENTATION_NOTE" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
  else
    FRAGMENTATION_NOTE="No valid sample files found for fragmentation estimate"
  fi
}

# perform_safe_write_test: non-destructive write/read test that creates and removes a file
perform_safe_write_test() {
  # This writes a temporary file and immediately removes it; user must ensure free space available.
  # It is optional and only executed if DO_WRITE_TEST is true.
  if [[ "$DO_WRITE_TEST" != true ]]; then
    log "Write test not requested; skipping"
    return
  fi

  if [[ "$SIMULATE" == true ]]; then
    log "SIMULATE: would perform write test of size 1GiB on $MOUNTPOINT (skipping actual write)"
    return
  fi

  if [[ "$MOUNTPOINT" == "-" ]]; then
    log "Mountpoint unknown; cannot perform write test safely"
    return
  fi

  if ! mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    log "Mountpoint $MOUNTPOINT not mounted; cannot perform write test"
    return
  fi

  # Ensure enough free space; require at least 1.2 GiB free
  avail_kb=$(df --output=avail "$MOUNTPOINT" 2>/dev/null | tail -n1 | tr -d ' ')
  avail_mb=$((avail_kb / 1024))
  if [[ $avail_mb -lt 1200 ]]; then
    log "Insufficient free space ($avail_mb MB) for safe 1 GiB write test; skipping"
    return
  fi

  tmpfile="$MOUNTPOINT/__pico_velo_write_test__.$TIMESTAMP"
  log "Starting non-destructive write test: creating $tmpfile (1 GiB of zeros)"
  dd if=/dev/zero of="$tmpfile" bs=1M count=1024 status=progress conv=fsync 2>>"$LOG_FILE"
  log "Write complete; performing read-back test"
  dd if="$tmpfile" of=/dev/null bs=1M status=progress 2>>"$LOG_FILE"
  rm -f "$tmpfile"
  log "Write test removed and complete"
}

# scan_unknown_partitions: examine partitions reported as unknown; strings scan of first MiB
scan_unknown_partitions() {
  # Look for partitions where blkid returns no TYPE
  unknown_parts=()
  while read -r part; do
    # Skip physical device line
    if [[ "$part" =~ ^NAME ]]; then continue; fi
    dev="/dev/$part"
    fs=$(blkid -s TYPE -o value "$dev" 2>/dev/null || true)
    if [[ -z "$fs" ]]; then
      unknown_parts+=("$dev")
    fi
  done < <(lsblk -ln -o NAME "$DEVICE")

  if [[ ${#unknown_parts[@]} -eq 0 ]]; then
    log "No unknown partitions detected on $DEVICE"
    echo "No unknown partitions detected" >> "$FULL_REPORT_FILE"
    return
  fi

  log "Unknown partitions found: ${unknown_parts[*]}"
  for p in "${unknown_parts[@]}"; do
    echo "Strings scan of first 1 MiB for $p (truncated):" >> "$FULL_REPORT_FILE"
    sudo dd if="$p" bs=1M count=1 2>/dev/null | strings | head -n 200 >> "$FULL_REPORT_FILE"
  done
}

# generate_human_readable_summary: assemble long, explanatory paragraphs based on parsed results
generate_human_readable_summary() {
  # Build detailed human-friendly paragraphs; include context and clear recommendations.
  {
    echo "================================================================================"
    echo "HUMAN-READABLE DIAGNOSTIC REPORT"
    echo "Device: $DEVICE"
    echo "Mountpoint: $MOUNTPOINT"
    echo "Timestamp: $TIMESTAMP"
    echo
    # SMART interpretation paragraph
    echo "1) SMART health and disk surface status"
    if [[ -n "${SMART_STATUS:-}" && "${SMART_STATUS^^}" =~ "PASS" ]]; then
      echo "The SMART overall health reported as '${SMART_STATUS}'. This generally indicates that the drive's"
      echo "self-monitoring attributes have not triggered a critical failure threshold. Key monitored attributes"
      echo "such as Reallocated_Sector_Ct, Current_Pending_Sector and Offline_Uncorrectable were examined. Our"
      echo "parsing shows Reallocated_Sector_Ct=${RELOCATED_SECTORS}, Current_Pending_Sector=${CURRENT_PENDING},"
      echo "Offline_Uncorrectable=${OFFLINE_UNCORRECTABLE}. A value of zero across these items is a positive signal."
      echo "However, SMART is not infallible. It reflects the drive's internal telemetry and may not capture all failure modes."
      echo "If Reallocated or Pending counts increase over time, schedule a scheduled replacement or clone the disk."
      echo
    else
      echo "The SMART overall health is not clearly reported as PASS. The raw SMART output must be reviewed in"
      echo "$FULL_REPORT_FILE for the exact attribute values and any pre-fail or cautionary flags. If SMART indicates"
      echo "any pre-fail attribute at or below threshold, consider imaging the disk and replacing it as soon as practical."
      echo
    fi

    # Power/usage and temperature paragraph
    echo "2) Power-on hours, usage intensity and thermal behavior"
    echo "Power-on hours and load cycle counts give an indication of the drive's age and operational usage."
    echo "High power-on hours with non-zero reallocated sectors may indicate wear. Current parsed values:"
    echo "  - Power_On_Hours: ${POWER_ON_HOURS:-unknown}"
    echo "  - Temperature (C): ${TEMP_CELSIUS:-unknown}"
    echo "Operating temperatures in the mid-range (e.g. 20-40C) are typically acceptable. Spikes or sustained high"
    echo "temperatures can accelerate wear. If maximum temperature in SMART is above ~55C, consider improved cooling or"
    echo "investigate workloads causing the heat."
    echo

    # Performance paragraph
    echo "3) Performance analysis (read throughput and potential bottlenecks)"
    echo "We measured read performance using device-level tools. Cached and buffered read figures are reported in the"
    echo "full technical log. Buffered read speeds on USB-connected 5400 RPM drives will often be limited by rotation"
    echo "speed, controller overhead and USB link rate. Observed buffered read: ${BUFFERED_READ:-unknown} MB/sec."
    echo "If observed buffered read throughput is significantly below expected for the interface (e.g. <40-60 MB/s for"
    echo "mechanical USB 3.0 drives with good cable/port), consider testing alternate cables, ports, or the host controller."
    echo

    # Fragmentation and filesystem notes
    echo "4) Filesystem and fragmentation"
    echo "NTFS fragmentation can impact performance under certain workloads (many small files or very large sequential writes)."
    echo "Linux tools can perform limited inspection, but Windows native tools (defrag / analysis) are required for accurate"
    echo "fragmentation metrics and in-place defragmentation. If you rely on high sequential write throughput, schedule a"
    echo "Windows-based defragmentation and then re-run this audit. The fragmentation estimate (if performed) is:"
    echo "  - ${FRAGMENTATION_NOTE:-Not assessed}"
    echo

    # Integrity / hash paragraph
    echo "5) Data integrity check"
    echo "We computed a SHA256 hash of the first ${HASH_MB} MiB of the device as a lightweight integrity probe. The hash is"
    echo "recorded above in the full report. A matching hash between two points in time indicates the beginning of the disk"
    echo "has not changed. This is not a complete integrity check for the whole disk but is useful for initial comparisons."
    echo

    # Unknown partitions and hidden data
    echo "6) Hidden or unknown partitions"
    echo "The audit scanned for partitions without an identifiable filesystem signature and printed an ASCII 'strings' scan"
    echo "of the first megabyte of such partitions into the full report. If unusual firmware or hidden containers exist"
    echo "they may require offline forensic analysis; this script only performs safe, read-only probing."
    echo

    # Recommendations & next steps
    echo "7) Recommendations (actionable, prioritized)"
    echo "  - If SMART attributes are stable (no reallocated/pending/offline), continue normal use and schedule periodic checks."
    echo "  - If reallocated/pending/offline counts are non-zero, create a full sector-level image (ddrescue) and plan replacement."
    echo "  - If read speeds are low, check USB cable, port type and host controller; test with another host if possible."
    echo "  - Run Windows-native NTFS analysis and defragmentation for accurate fragmentation resolution."
    echo "  - Avoid abrupt disconnections; always unmount cleanly to protect NTFS metadata."
    echo

    # Safety and closure
    echo "Safety note: This audit did NOT perform repair actions. No ntfsfix or chkdsk was executed by default."
    if [[ "$NTFSFIX_RECOMMEND" == true ]]; then
      echo "ntfsfix recommendation: sudo umount $MOUNTPOINT && sudo ntfsfix $DEVICE  # (RECOMMENDATION ONLY - not executed)"
    fi
    echo "Full technical logs available in $FULL_REPORT_FILE"
    echo "This summary also written to $SUMMARY_FILE"
    echo "================================================================================"
  } | tee -a "$SUMMARY_FILE" "$FULL_REPORT_FILE" "$LOG_FILE"
}

# numbered_actions_list: prints numbered list of actions performed (post-execution per rule 14.10.1)
record_actions() {
  # This function enumerates major blocks executed and prints them as a numbered list.
  echo "Actions performed:" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
  idx=1
  echo "$idx) Created and verified directories: $LOG_DIR and $RESULTS_DIR" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Collected partition and filesystem information via lsblk/fdisk/parted" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Collected SMART raw output and parsed key attributes" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Performed device-level read benchmarks (hdparm/dd) and recorded results" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Performed optional fragmentation estimate via filefrag (sampled files)" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Performed optional non-destructive write test (if requested and permitted)" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Scanned unknown partitions with strings (first MiB)" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Generated long human-readable diagnostic summary and saved to $SUMMARY_FILE" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"; idx=$((idx+1))
  echo "$idx) Logged actions and raw outputs to $FULL_REPORT_FILE and $LOG_FILE" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
}

# -------------------------
#  Main audit workflow
# -------------------------
main() {
  # Create necessary directories (logs, results, outputs)
  ensure_dirs

  # If user asked for prereq check only
  if [[ "$CHECK_PREREQ" == true ]]; then
    log "Prerequisite check requested"
    check_commands
    exit 0
  fi

  # Check commands (and optionally install)
  check_commands

  # Start the full report file with header
  {
    echo "NON-DESTRUCTIVE NTFS AUDIT - PICO-VELO"
    echo "Script: $SCRIPT_PATH"
    echo "Author: $AUTHOR <$AUTHOR_EMAIL>"
    echo "Version: $VERSION  Date: $DATE"
    echo "Timestamp: $TIMESTAMP"
    echo
  } >> "$FULL_REPORT_FILE"

  # If DO_EXEC is not requested, print help and exit (per V110 requirement - default help)
  if [[ "$DO_EXEC" != true ]]; then
    log "No --exec flag provided. Exiting after preparing environment. To run full audit, use --exec."
    show_help
    exit 0
  fi

  # Confirm device exists and is block device
  if [[ ! -b "$DEVICE" ]]; then
    die "Device $DEVICE does not exist or is not a block device"
  fi

  # Basic mountpoint check
  if [[ "$MOUNTPOINT" != "-" ]]; then
    log "Verifying mountpoint status for $MOUNTPOINT"
    mount_check
  fi

  # 1) Partition & FS info
  gather_partition_info

  # 2) SMART collection and parsing
  run_smart_and_parse

  # 3) Capture hdparm/readbenchmarks
  perform_read_benchmark

  # 4) Hash first N MiB
  log "Hashing first $HASH_MB MiB for integrity probe"
  sudo dd if="$DEVICE" bs=1M count="$HASH_MB" status=none 2>>"$LOG_FILE" | sha256sum | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"

  # 5) File fragmentation estimate (if possible)
  attempt_ntfs_fragmentation_estimate

  # 6) Unknown partitions scan
  scan_unknown_partitions

  # 7) Read-only NTFS tests with dd sampling for read throughput
  log "Performing read-only device sampling (read $READ_MB MiB for throughput check)"
  sudo dd if="$DEVICE" of=/dev/null bs=1M count="$READ_MB" status=progress 2>>"$LOG_FILE" || log "dd read sample returned non-zero status (non-fatal)"

  # 8) Optional non-destructive write-test
  if [[ "$DO_WRITE_TEST" == true ]]; then
    perform_safe_write_test
  else
    log "Non-destructive write test not requested; skipping"
  fi

  # 9) NTFS repairs: never executed automatically; optionally recommend command
  if [[ "$NTFSFIX_RECOMMEND" == true ]]; then
    echo "NTFS repair recommendation (not executed):" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
    echo "  sudo umount $MOUNTPOINT && sudo ntfsfix $DEVICE" | tee -a "$FULL_REPORT_FILE" "$LOG_FILE"
  fi

  # 10) Generate final diagnostics and human-readable summary
  generate_human_readable_summary

  # 11) Enumerate actions performed (numbered list)
  record_actions

  # Final log lines
  log "Audit finished. Full report: $FULL_REPORT_FILE"
  log "Human-readable summary: $SUMMARY_FILE"
  log "Log file: $LOG_FILE"
}

# -------------------------
#  Entry point
# -------------------------
# parse CLI args
parse_args "$@"

# Run main workflow
main

# End of script
