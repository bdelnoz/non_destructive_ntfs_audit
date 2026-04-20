<!--
Document : README.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v1.0.0
Date : 2026-04-20 11:28
-->
# non_destructive_ntfs_audit

## Overview

`non_destructive_ntfs_audit.sh` is a **non-destructive NTFS audit** utility focused on diagnostics, integrity checks, and actionable reporting.

The script is designed for Debian/Ubuntu/Kali-like environments and provides:

- deep disk and partition diagnostics,
- SMART collection and parsed health indicators,
- read benchmark sampling,
- SHA256 integrity probing,
- optional safe write/read validation,
- unknown partition probing,
- verbose technical reports and a human-readable summary.

## Script metadata

- Script file: `./non_destructive_ntfs_audit.sh`
- Script internal version: `v4.0`
- Script internal date: `2025-11-09`
- Author: Bruno DELNOZ
- Contact: bruno.delnoz@protonmail.com

## Main features

1. **Partition and filesystem inventory**
   - `lsblk`, `parted`/`fdisk`, and read-only first sectors hexdump.

2. **SMART diagnostics**
   - Raw SMART export and parsed fields:
     - overall health,
     - reallocated sectors,
     - pending sectors,
     - offline uncorrectable,
     - power-on hours,
     - temperature,
     - UDMA CRC errors.

3. **Performance checks**
   - `hdparm -Tt` cached/buffered read indicators.
   - read sampling with `dd` for throughput behavior.

4. **Integrity probe**
   - SHA256 hash of first N MiB (`--hash-mb`, default 100).

5. **Fragmentation estimate**
   - `filefrag` sampling on selected large files (when mounted and available).

6. **Unknown partition scan**
   - string extraction from first MiB for partitions without detected filesystem type.

7. **Optional non-destructive write test**
   - temporary 1 GiB create/read/remove cycle (`--write-test`) with free-space checks.

8. **Dual-level reports**
   - full technical report (`*.full.txt`),
   - human-readable summary (`*.summary.txt`),
   - detailed log file.

## CLI usage

```bash
sudo ./non_destructive_ntfs_audit.sh [OPTIONS] <device> <mountpoint>
```

### Positional arguments

- `device`: block device (example: `/dev/sdc`)
- `mountpoint`: expected mount point (example: `/mnt/TOSHIBA`) or `-` if unknown

### Options

- `--help`, `-h` → show help
- `--exec`, `--exe`, `-exe` → execute full audit
- `--simulate`, `-s` → dry-run mode
- `--prerequis`, `-pr` → prerequisite check only
- `--install`, `-i` → install missing prerequisites (apt)
- `--write-test` → optional non-destructive write/read test
- `--hash-mb N` → integrity hash scope in MiB
- `--read-mb N` → read sampling scope in MiB
- `--ntfsfix-recommend` → print ntfsfix recommendation only (never auto-run)
- `--changelog`, `-ch` → print script changelog

## Examples

```bash
# Help
sudo ./non_destructive_ntfs_audit.sh --help

# Prerequisites only
sudo ./non_destructive_ntfs_audit.sh --prerequis

# Dry-run full audit
sudo ./non_destructive_ntfs_audit.sh --simulate --exec /dev/sdc /mnt/TOSHIBA

# Full non-destructive audit
sudo ./non_destructive_ntfs_audit.sh --exec /dev/sdc /mnt/TOSHIBA

# Unknown mountpoint
sudo ./non_destructive_ntfs_audit.sh --exec /dev/sdc -

# Extended hash/read sizing
sudo ./non_destructive_ntfs_audit.sh --exec --hash-mb 500 --read-mb 1024 /dev/sdc /mnt/TOSHIBA
```

## Output structure

- `./logs/`
  - runtime log files
- `./results/`
  - technical full report files
  - human-readable summary files
- `./outputs/`
  - auxiliary output directory

## Safety model

- Default mode is diagnostic-first and non-destructive.
- Repair actions are not executed automatically.
- `--simulate` disables sensitive actions while preserving analysis and logging.
- `--write-test` is optional and guarded.

## Limitations

- NTFS fragmentation accuracy is limited on Linux; Windows-native tools remain authoritative.
- SMART availability and completeness depend on drive/controller support.
- Some commands require elevated privileges.

## Related documentation

- `./INSTALL.md`
- `./CHANGELOG.md`
- `./WHY.md`
- `./AGENTS.md`
