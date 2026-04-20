<!--
Document : INSTALL.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v1.0.0
Date : 2026-04-20 11:28
-->
# Installation Guide - non_destructive_ntfs_audit

## Scope

This repository provides a single main script:

- `./non_destructive_ntfs_audit.sh`

The script is intended for Debian/Ubuntu/Kali style systems.

## 1) Clone repository

```bash
git clone <your-repository-url>
cd non_destructive_ntfs_audit
```

## 2) Make script executable

```bash
chmod +x ./non_destructive_ntfs_audit.sh
```

## 3) Install recommended prerequisites

The script can self-check prerequisites (`--prerequis`) and attempt installation (`--install`).

Manual package installation example:

```bash
sudo apt update
sudo apt install -y util-linux fdisk parted smartmontools hdparm ntfs-3g ntfsprogs e2fsprogs coreutils gawk sed grep
```

> Note: package naming can vary slightly by distribution and release.

## 4) Validate prerequisites through script

```bash
sudo ./non_destructive_ntfs_audit.sh --prerequis
```

Optional auto-install path:

```bash
sudo ./non_destructive_ntfs_audit.sh --prerequis --install
```

## 5) Basic execution

```bash
sudo ./non_destructive_ntfs_audit.sh --exec /dev/sdc /mnt/TOSHIBA
```

Dry-run:

```bash
sudo ./non_destructive_ntfs_audit.sh --simulate --exec /dev/sdc /mnt/TOSHIBA
```

## 6) Generated directories

The script creates and uses:

- `./logs`
- `./results`
- `./outputs`

## 7) Post-install verification checklist

1. `--help` displays successfully.
2. `--prerequis` runs and reports requirements.
3. `--simulate --exec` completes and writes logs/reports.
4. Runtime artifacts are present in `./logs` and `./results`.
