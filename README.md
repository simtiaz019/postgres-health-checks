# DB Heatlh Checks

This folder contains a daily PostgreSQL and host monitoring script for a multi-node cluster.

It is designed for your stated operating model:

- same PostgreSQL user on all nodes
- different PostgreSQL ports per node
- shared named OS user for SSH-based host checks
- one consolidated HTML report
- one consolidated email with only major alerts in the body

## Files

- `db_health_checks.py`: main runner
- `db_health_checks_config.json`: shared credential, node, threshold, and SMTP config
- `reports/`: created automatically for HTML output and the rolling state file

## What The Script Collects

- primary or standby role
- PostgreSQL uptime
- connection usage versus `max_connections`
- primary replication status from `pg_stat_replication`
- standby WAL receiver and replay status from `pg_stat_wal_receiver`
- replay delay and receive-to-replay backlog
- long-running SQLs
- blocking SQLs
- idle-in-transaction sessions
- top SQLs by total time, calls, and mean time from `pg_stat_statements`
- interval TPS and row throughput using the previous run state file
- data directory size and daily growth rate
- WAL directory size and daily growth rate
- tablespace sizes
- filesystem usage for database-critical paths
- archive queue backlog from `pg_wal/archive_status`
- archiver status from `pg_stat_archiver`
- host uptime, load average, memory usage, and filesystem usage over SSH

## Important Notes

- Host checks require Python package `paramiko`.
- The database hosts are assumed to be Linux servers because the SSH checks use `df`, `du`, `free`, `uptime`, and `find`.
- `pg_stat_statements` must be installed in the connected database if you want top SQL analysis in the report.
- Daily growth and TPS calculations become meaningful from the second run onward, because the first run creates the baseline state file.

## Install Dependency

```powershell
.\.venv\Scripts\python.exe -m pip install paramiko
```

## Usage

Run all configured nodes:

```powershell
.\.venv\Scripts\python.exe Scripts\DB_Heatlh_Checks\db_health_checks.py
```

Run a single node:

```powershell
.\.venv\Scripts\python.exe Scripts\DB_Heatlh_Checks\db_health_checks.py --node node1
```

Run without email:

```powershell
.\.venv\Scripts\python.exe Scripts\DB_Heatlh_Checks\db_health_checks.py --no-email
```

## Scheduling

Windows Task Scheduler daily task:

1. Program:

```text
d:\PBFTL\Development\pbftl-repo\.venv\Scripts\python.exe
```

2. Arguments:

```text
Scripts\DB_Heatlh_Checks\db_health_checks.py
```

3. Start in:

```text
d:\PBFTL\Development\pbftl-repo
```
