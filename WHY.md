<!--
Document : WHY.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v1.0.0
Date : 2026-04-20 11:28
-->
# WHY - non_destructive_ntfs_audit

## Purpose

This project exists to provide a **safe-first NTFS audit workflow** for Linux environments where users need actionable disk diagnostics without immediate repair or destructive operations.

## Why this script is useful

1. **Risk reduction first**
   - prioritizes read-only diagnostics,
   - keeps repair commands as recommendations only.

2. **Structured triage**
   - combines partition metadata, SMART, performance, integrity, and optional write validation into one repeatable flow.

3. **Operational clarity**
   - produces both detailed technical data and a human-readable summary for quick decision-making.

4. **Incident support**
   - helps identify early warning signs (pending sectors, reallocated sectors, uncorrectable errors, unusual throughput).

5. **Auditability**
   - logs and reports are timestamped and stored in dedicated folders for evidence retention and comparison between runs.

## Design principles

- Non-destructive by default.
- Explain each step.
- Keep output usable for both engineers and less technical stakeholders.
- Prefer explicit recommendations over implicit assumptions.

## Typical scenarios

- pre-maintenance health checks on removable NTFS media,
- troubleshooting slow external disks,
- confirming a baseline before migration or backup,
- collecting evidence prior to forensic or recovery escalation.
