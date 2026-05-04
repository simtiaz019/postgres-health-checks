#!/usr/bin/env python3
import argparse
import json
import shlex
import smtplib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import psycopg2

try:
    import paramiko
except ImportError:
    paramiko = None


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DEFAULT_SETTINGS = {
    "connect_timeout": 10,
    "statement_timeout_ms": 30000,
    "default_output_dir": "reports",
    "state_file": "db_health_checks_state.json",
    "top_sql_limit": 10,
    "long_running_query_seconds": 300,
    "long_running_query_alert_seconds": 900,
    "idle_in_transaction_seconds": 300,
    "idle_in_transaction_alert_seconds": 900,
    "blocking_sql_limit": 10,
    "connection_usage_warn_pct": 80,
    "connection_usage_critical_pct": 90,
    "replication_lag_bytes_warn": 268435456,
    "replication_lag_bytes_critical": 1073741824,
    "standby_replay_delay_warn_seconds": 300,
    "standby_replay_delay_critical_seconds": 900,
    "wal_receiver_stale_warn_seconds": 300,
    "wal_receiver_stale_critical_seconds": 900,
    "archive_ready_warn_count": 20,
    "archive_ready_critical_count": 100,
    "filesystem_usage_warn_pct": 80,
    "filesystem_usage_critical_pct": 90,
    "data_dir_growth_warn_bytes": 0,
    "data_dir_growth_critical_bytes": 0,
    "wal_dir_growth_warn_bytes": 0,
    "wal_dir_growth_critical_bytes": 0,
    "major_alert_severities": ["critical", "high"],
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    summary: str
    details: str
    recommendation: str
    evidence: List[str]


@dataclass
class NodeReport:
    name: str
    host: str
    port: int
    database: str
    role: str
    ok: bool
    generated_at: str
    metadata: Dict[str, Any]
    metrics: Dict[str, Any]
    findings: List[Finding]
    errors: List[str]
    state: Dict[str, Any]


class AuthenticationFailure(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run PostgreSQL and host daily health checks and email a consolidated HTML report."
    )
    parser.add_argument(
        "--config",
        default=str(Path(__file__).resolve().parent / "db_health_checks_config.json"),
    )
    parser.add_argument(
        "--node",
        action="append",
        dest="nodes",
        help="Optional node name filter. Pass more than once to target multiple nodes.",
    )
    parser.add_argument("--output-dir")
    parser.add_argument("--no-email", action="store_true")
    return parser.parse_args()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def format_bytes(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    value = float(value)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if abs(value) < 1024 or unit == units[-1]:
            return f"{value:,.2f} {unit}"
        value /= 1024
    return f"{value:,.2f} PB"


def format_number(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:,.2f}"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def format_timestamp(value: Any) -> str:
    if value in (None, ""):
        return "n/a"
    if hasattr(value, "isoformat"):
        return value.isoformat(sep=" ", timespec="seconds")
    return str(value)


def shorten_sql(value: Optional[str], limit: int = 220) -> str:
    if not value:
        return ""
    normalized = " ".join(str(value).split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_config(config_path: Path) -> Dict[str, Any]:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    payload.setdefault("settings", {})
    payload.setdefault("database_defaults", {})
    payload.setdefault("ssh_defaults", {})
    payload.setdefault("nodes", [])
    payload.setdefault("email", {})
    return payload


def load_settings(config_data: Dict[str, Any]) -> Dict[str, Any]:
    settings = dict(DEFAULT_SETTINGS)
    settings.update(config_data.get("settings", {}))
    return settings


def is_auth_failure_message(message: str) -> bool:
    lowered = str(message).lower()
    markers = (
        "authentication failed",
        "password authentication failed",
        "access denied",
        "permission denied",
        "sorry, try again",
        "account is locked",
        "too many authentication failures",
        "pam",
    )
    return any(marker in lowered for marker in markers)


def merge_node_config(
    node_entry: Dict[str, Any],
    database_defaults: Dict[str, Any],
    ssh_defaults: Dict[str, Any],
) -> Dict[str, Any]:
    merged = dict(node_entry)
    db_defaults = dict(database_defaults)
    ssh_cfg = dict(ssh_defaults)

    for field in ("database", "username", "password", "connect_timeout"):
        if field in db_defaults and field not in merged:
            merged[field] = db_defaults[field]

    merged.setdefault("host", node_entry.get("host"))
    merged.setdefault("port", node_entry.get("port", db_defaults.get("port")))

    ssh_cfg.update(node_entry.get("ssh", {}))
    if "ssh_host" in merged:
        ssh_cfg["host"] = merged["ssh_host"]
    else:
        ssh_cfg.setdefault("host", merged.get("host"))
    if "ssh_username" in merged:
        ssh_cfg["username"] = merged["ssh_username"]
    if "ssh_password" in merged:
        ssh_cfg["password"] = merged["ssh_password"]
    if "ssh_key_filename" in merged:
        ssh_cfg["key_filename"] = merged["ssh_key_filename"]

    merged["ssh"] = ssh_cfg
    return merged


def filter_nodes(node_entries: List[Dict[str, Any]], requested_nodes: Optional[List[str]]) -> List[Dict[str, Any]]:
    if not requested_nodes:
        return node_entries
    requested = {item.strip() for item in requested_nodes if item and item.strip()}
    return [entry for entry in node_entries if str(entry.get("name")) in requested]


def require_paramiko_if_needed(node_entries: List[Dict[str, Any]]) -> None:
    if paramiko is not None:
        return
    for entry in node_entries:
        if parse_bool(entry.get("ssh", {}).get("enabled", True), default=True):
            raise RuntimeError(
                "The script needs the 'paramiko' package for SSH-based host checks. "
                "Install it with '.\\.venv\\Scripts\\python.exe -m pip install paramiko'."
            )


def build_connection_kwargs(node_cfg: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    values = {
        "host": node_cfg.get("host"),
        "port": node_cfg.get("port"),
        "dbname": node_cfg.get("database"),
        "user": node_cfg.get("username") or node_cfg.get("user"),
        "password": node_cfg.get("password"),
        "connect_timeout": int(node_cfg.get("connect_timeout") or settings.get("connect_timeout", 10)),
        "application_name": "db-health-checks",
    }
    missing = [field for field in ("host", "port", "dbname", "user", "password") if values.get(field) in (None, "")]
    if missing:
        raise ValueError(
            f"Node '{node_cfg.get('name', 'unknown')}' is missing database connection values: {', '.join(missing)}"
        )
    return values


def fetch_all(conn, query: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(query, params)
        columns = [desc[0] for desc in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]


def fetch_one(conn, query: str, params: Optional[Sequence[Any]] = None) -> Optional[Dict[str, Any]]:
    rows = fetch_all(conn, query, params)
    return rows[0] if rows else None


def fetch_value(conn, query: str, params: Optional[Sequence[Any]] = None) -> Any:
    row = fetch_one(conn, query, params)
    if not row:
        return None
    return next(iter(row.values()))


def safe_fetch_all(conn, query: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
    try:
        return fetch_all(conn, query, params)
    except Exception:
        return []


def safe_fetch_one(conn, query: str, params: Optional[Sequence[Any]] = None) -> Optional[Dict[str, Any]]:
    try:
        return fetch_one(conn, query, params)
    except Exception:
        return None


def safe_fetch_value(conn, query: str, params: Optional[Sequence[Any]] = None) -> Any:
    try:
        return fetch_value(conn, query, params)
    except Exception:
        return None


def current_wal_lsn_expr(version_num: int) -> str:
    return "pg_current_wal_lsn()" if version_num >= 100000 else "pg_current_xlog_location()"


def last_receive_lsn_expr(version_num: int) -> str:
    return "pg_last_wal_receive_lsn()" if version_num >= 100000 else "pg_last_xlog_receive_location()"


def last_replay_lsn_expr(version_num: int) -> str:
    return "pg_last_wal_replay_lsn()" if version_num >= 100000 else "pg_last_xlog_replay_location()"


def lsn_diff_expr(version_num: int, left: str, right: str) -> str:
    func_name = "pg_wal_lsn_diff" if version_num >= 100000 else "pg_xlog_location_diff"
    return f"{func_name}({left}, {right})"


def build_finding(
    severity: str,
    category: str,
    title: str,
    summary: str,
    details: str,
    recommendation: str,
    evidence: Optional[List[str]] = None,
) -> Finding:
    return Finding(
        severity=severity,
        category=category,
        title=title,
        summary=summary,
        details=details,
        recommendation=recommendation,
        evidence=evidence or [],
    )


def normalize_email_config(email_cfg: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(email_cfg)
    normalized["enabled"] = parse_bool(
        email_cfg.get("enabled", email_cfg.get("SMTP_ENABLED", True)),
        default=True,
    )
    normalized["host"] = email_cfg.get("host") or email_cfg.get("SMTP_HOST")
    normalized["port"] = int(email_cfg.get("port") or email_cfg.get("SMTP_PORT") or 25)
    normalized["from"] = email_cfg.get("from") or email_cfg.get("SMTP_MAIL_FROM")
    normalized["from_name"] = email_cfg.get("from_name") or email_cfg.get("SMTP_FROM_NAME")
    normalized["ehlo_identity"] = email_cfg.get("ehlo_identity") or email_cfg.get("SMTP_EHLO_IDENTITY")
    normalized["username"] = email_cfg.get("username") or email_cfg.get("SMTP_USERNAME")
    normalized["password"] = email_cfg.get("password") or email_cfg.get("SMTP_PASSWORD")
    normalized["use_tls"] = parse_bool(
        email_cfg.get("use_tls", email_cfg.get("SMTP_STARTTLS")),
        default=False,
    )
    normalized["use_ssl"] = parse_bool(
        email_cfg.get("use_ssl", email_cfg.get("SMTP_SSL")),
        default=False,
    )
    return normalized


def send_email(
    email_cfg: Dict[str, Any],
    subject: str,
    text_body: str,
    html_body: str,
    attachments: List[Path],
) -> None:
    email_cfg = normalize_email_config(email_cfg)
    if not email_cfg.get("enabled", False):
        return

    recipients = email_cfg.get("to", [])
    if isinstance(recipients, str):
        recipients = [recipients]
    recipients = [item for item in recipients if item]
    if not recipients:
        raise ValueError("Email is enabled but no recipients are configured.")

    msg = MIMEMultipart()
    msg["Subject"] = subject
    from_name = email_cfg.get("from_name")
    from_address = str(email_cfg["from"])
    msg["From"] = formataddr((str(from_name), from_address)) if from_name else from_address
    msg["To"] = ", ".join(recipients)

    alternative = MIMEMultipart("alternative")
    alternative.attach(MIMEText(text_body, "plain", "utf-8"))
    alternative.attach(MIMEText(html_body, "html", "utf-8"))
    msg.attach(alternative)

    for attachment in attachments:
        part = MIMEApplication(attachment.read_bytes(), Name=attachment.name)
        part["Content-Disposition"] = f'attachment; filename="{attachment.name}"'
        msg.attach(part)

    host = str(email_cfg["host"])
    port = int(email_cfg.get("port", 25))
    username = email_cfg.get("username")
    password = email_cfg.get("password")
    use_tls = parse_bool(email_cfg.get("use_tls"), default=False)
    use_ssl = parse_bool(email_cfg.get("use_ssl"), default=False)
    ehlo_identity = email_cfg.get("ehlo_identity")
    smtp_cls = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP

    with smtp_cls(host, port, timeout=30, local_hostname=ehlo_identity) as server:
        if ehlo_identity:
            server.ehlo(ehlo_identity)
        if use_tls:
            server.starttls()
            if ehlo_identity:
                server.ehlo(ehlo_identity)
        if username and password:
            server.login(str(username), str(password))
        server.sendmail(from_address, recipients, msg.as_string())


def open_ssh_client(ssh_cfg: Dict[str, Any]):
    if not parse_bool(ssh_cfg.get("enabled", True), default=True):
        return None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_port = int(str(ssh_cfg.get("port", 22)).strip() or 22)
    except (ValueError, TypeError):
        ssh_port = 22
    try:
        ssh_timeout = int(str(ssh_cfg.get("timeout_seconds", 20)).strip() or 20)
    except (ValueError, TypeError):
        ssh_timeout = 20
    connect_kwargs = {
        "hostname": ssh_cfg.get("host"),
        "port": ssh_port,
        "username": ssh_cfg.get("username"),
        "timeout": ssh_timeout,
        "look_for_keys": parse_bool(ssh_cfg.get("look_for_keys"), default=False),
        "allow_agent": parse_bool(ssh_cfg.get("allow_agent"), default=False),
    }
    if ssh_cfg.get("password"):
        connect_kwargs["password"] = ssh_cfg.get("password")
    if ssh_cfg.get("key_filename"):
        connect_kwargs["key_filename"] = ssh_cfg.get("key_filename")
    missing = [field for field in ("hostname", "username") if not connect_kwargs.get(field)]
    if missing:
        raise ValueError(f"SSH config is missing: {', '.join(missing)}")
    try:
        client.connect(**connect_kwargs)
    except Exception as exc:
        if is_auth_failure_message(str(exc)):
            raise AuthenticationFailure(f"SSH authentication failed for {connect_kwargs.get('username')}@{connect_kwargs.get('hostname')}: {exc}") from exc
        raise
    return client


def ssh_run(client, command: str, as_postgres: bool = False, sudo_password: Optional[str] = None) -> str:
    def run_remote(remote_command: str, use_pty: bool = False) -> Tuple[str, str, int]:
        stdin, stdout, stderr = client.exec_command(remote_command, timeout=30, get_pty=use_pty)
        _ = stdin
        output = stdout.read().decode("utf-8", errors="replace").strip()
        error = stderr.read().decode("utf-8", errors="replace").strip()
        exit_status = stdout.channel.recv_exit_status()
        return output, error, exit_status

    remote_command = command
    if as_postgres:
        # Use non-interactive sudo to avoid repeated password prompts that can trigger account lockout.
        remote_command = f"sudo -n -u postgres bash -lc {shlex.quote(command)}"
    output, error, exit_status = run_remote(remote_command)
    if exit_status != 0:
        if as_postgres:
            # If sudo requires a password, provide the SSH user's password non-interactively.
            if sudo_password:
                sudo_with_password = f"sudo -S -p '' -u postgres bash -lc {shlex.quote(command)}"
                stdin, stdout, stderr = client.exec_command(sudo_with_password, timeout=30, get_pty=True)
                stdin.write(str(sudo_password) + "\n")
                stdin.flush()
                _ = stdin
                output3 = stdout.read().decode("utf-8", errors="replace").strip()
                error3 = stderr.read().decode("utf-8", errors="replace").strip()
                status3 = stdout.channel.recv_exit_status()
                if status3 == 0:
                    return output3
                if is_auth_failure_message(error3):
                    raise AuthenticationFailure(f"Sudo authentication failed while switching to postgres user: {error3}")
            stdin2, stdout2, stderr2 = client.exec_command(command, timeout=30)
            _ = stdin2
            fallback_output = stdout2.read().decode("utf-8", errors="replace").strip()
            fallback_error = stderr2.read().decode("utf-8", errors="replace").strip()
            fallback_status = stdout2.channel.recv_exit_status()
            if fallback_status == 0:
                return fallback_output
            if is_auth_failure_message(fallback_error) or is_auth_failure_message(error):
                raise AuthenticationFailure(
                    f"Authentication failed while running remote command as postgres user: {fallback_error or error}"
                )
            raise RuntimeError(
                fallback_error
                or error
                or f"Remote command failed with exit status {fallback_status}: {command}"
            )
        if is_auth_failure_message(error):
            raise AuthenticationFailure(f"Remote authentication failed: {error}")
        raise RuntimeError(error or f"Remote command failed with exit status {exit_status}: {command}")
    return output


def parse_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def parse_free_output(value: str) -> Dict[str, Optional[int]]:
    for line in value.splitlines():
        stripped = line.strip()
        if not stripped.startswith("Mem:"):
            continue
        parts = stripped.split()
        if len(parts) < 7:
            continue
        return {
            "total_bytes": parse_int(parts[1]),
            "used_bytes": parse_int(parts[2]),
            "free_bytes": parse_int(parts[3]),
            "available_bytes": parse_int(parts[6]),
        }
    return {
        "total_bytes": None,
        "used_bytes": None,
        "free_bytes": None,
        "available_bytes": None,
    }


def parse_df_output(value: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    lines = [line for line in value.splitlines() if line.strip()]
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        rows.append(
            {
                "filesystem": parts[0],
                "size_bytes": parse_int(parts[1]) or 0,
                "used_bytes": parse_int(parts[2]) or 0,
                "available_bytes": parse_int(parts[3]) or 0,
                "used_pct": parse_int(parts[4].replace("%", "")) or 0,
                "mountpoint": parts[5],
            }
        )
    return rows


def collect_host_metrics(
    client,
    data_directory: Optional[str],
    wal_directory: Optional[str],
    tablespace_locations: List[Optional[str]],
    sudo_password: Optional[str] = None,
) -> Dict[str, Any]:
    if client is None:
        return {"enabled": False}

    metrics: Dict[str, Any] = {"enabled": True}
    metrics["hostname"] = ssh_run(client, "hostname", as_postgres=True, sudo_password=sudo_password)
    metrics["uptime"] = ssh_run(client, "uptime -p 2>/dev/null || uptime", as_postgres=True, sudo_password=sudo_password)
    metrics["load_average"] = ssh_run(
        client, "cat /proc/loadavg 2>/dev/null || uptime", as_postgres=True, sudo_password=sudo_password
    )
    metrics["memory"] = parse_free_output(ssh_run(client, "free -b", as_postgres=True, sudo_password=sudo_password))

    size_targets: List[Tuple[str, str]] = []
    if data_directory:
        size_targets.append(("data_directory", data_directory))
    if wal_directory:
        size_targets.append(("wal_directory", wal_directory))
    for index, location in enumerate(tablespace_locations, start=1):
        if location:
            size_targets.append((f"tablespace_{index}", location))

    sizes: Dict[str, Dict[str, Any]] = {}
    for label, path_value in size_targets:
        quoted = shlex.quote(path_value)
        size_output = ssh_run(
            client,
            f"du -sb {quoted} 2>/dev/null | awk '{{print $1}}'",
            as_postgres=True,
            sudo_password=sudo_password,
        )
        sizes[label] = {
            "path": path_value,
            "size_bytes": parse_int(size_output, 0) or 0,
        }
    metrics["sizes"] = sizes

    df_targets = list(dict.fromkeys(path_value for _, path_value in size_targets if path_value))
    if df_targets:
        quoted_targets = " ".join(shlex.quote(item) for item in df_targets)
        metrics["filesystems"] = parse_df_output(
            ssh_run(client, f"df -P -B1 {quoted_targets}", as_postgres=True, sudo_password=sudo_password)
        )
    else:
        metrics["filesystems"] = []

    archive_status_dir = None
    if wal_directory:
        archive_status_dir = str(Path(wal_directory) / "archive_status").replace("\\", "/")
    metrics["archive_status_dir"] = archive_status_dir
    if archive_status_dir:
        quoted_archive = shlex.quote(archive_status_dir)
        ready_cmd = f"if [ -d {quoted_archive} ]; then find {quoted_archive} -maxdepth 1 -type f -name '*.ready' | wc -l; else echo 0; fi"
        done_cmd = f"if [ -d {quoted_archive} ]; then find {quoted_archive} -maxdepth 1 -type f -name '*.done' | wc -l; else echo 0; fi"
        metrics["archive_ready_count"] = (
            parse_int(ssh_run(client, ready_cmd, as_postgres=True, sudo_password=sudo_password), 0) or 0
        )
        metrics["archive_done_count"] = (
            parse_int(ssh_run(client, done_cmd, as_postgres=True, sudo_password=sudo_password), 0) or 0
        )
    else:
        metrics["archive_ready_count"] = 0
        metrics["archive_done_count"] = 0

    return metrics


def collect_instance_overview(conn) -> Dict[str, Any]:
    overview = fetch_one(
        conn,
        """
        select
            current_database() as database_name,
            current_user as current_user,
            inet_server_addr()::text as server_addr,
            inet_server_port() as server_port,
            version() as server_version,
            current_setting('server_version_num')::int as server_version_num,
            now() as collected_at,
            pg_postmaster_start_time() as postmaster_start_time,
            pg_is_in_recovery() as is_in_recovery
        """,
    )
    overview["data_directory"] = safe_fetch_value(conn, "show data_directory")
    return overview


def collect_connection_stats(conn) -> Dict[str, Any]:
    row = fetch_one(
        conn,
        """
        select
            count(*) as total_connections,
            count(*) filter (where state = 'active') as active_connections,
            count(*) filter (where state = 'idle in transaction') as idle_in_transaction,
            count(*) filter (where wait_event_type = 'Lock') as lock_waiters
        from pg_stat_activity
        """,
    )
    max_connections = int(fetch_value(conn, "select setting::int from pg_settings where name = 'max_connections'") or 0)
    total_connections = int(row["total_connections"])
    row["max_connections"] = max_connections
    row["usage_pct"] = round((total_connections / max_connections) * 100, 2) if max_connections else 0.0
    return row


def collect_primary_replication(conn, version_num: int) -> List[Dict[str, Any]]:
    current_lsn = current_wal_lsn_expr(version_num)
    return safe_fetch_all(
        conn,
        f"""
        select
            pid,
            application_name,
            usename,
            client_addr::text as client_addr,
            state,
            sync_state,
            sent_lsn::text as sent_lsn,
            write_lsn::text as write_lsn,
            flush_lsn::text as flush_lsn,
            replay_lsn::text as replay_lsn,
            coalesce({lsn_diff_expr(version_num, current_lsn, "replay_lsn")}, 0)::bigint as replay_backlog_bytes,
            coalesce({lsn_diff_expr(version_num, current_lsn, "flush_lsn")}, 0)::bigint as flush_backlog_bytes,
            write_lag,
            flush_lag,
            replay_lag
        from pg_stat_replication
        order by application_name, client_addr::text
        """,
    )


def collect_standby_status(conn, version_num: int) -> Dict[str, Any]:
    receiver = safe_fetch_one(conn, "select * from pg_stat_wal_receiver")
    replay_row = safe_fetch_one(
        conn,
        f"""
        select
            pg_last_xact_replay_timestamp() as last_replay_timestamp,
            now() - pg_last_xact_replay_timestamp() as replay_delay,
            {lsn_diff_expr(version_num, last_receive_lsn_expr(version_num), last_replay_lsn_expr(version_num))}::bigint as replay_backlog_bytes,
            pg_is_wal_replay_paused() as replay_paused
        """,
    )
    return {
        "wal_receiver": receiver,
        "replay": replay_row or {},
    }


def collect_long_running_queries(conn, settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    return safe_fetch_all(
        conn,
        """
        select
            pid,
            datname,
            usename,
            client_addr::text as client_addr,
            state,
            wait_event_type,
            wait_event,
            now() - query_start as runtime,
            extract(epoch from now() - query_start)::bigint as runtime_seconds,
            left(query, 2000) as query
        from pg_stat_activity
        where pid <> pg_backend_pid()
          and state <> 'idle'
          and coalesce(backend_type, '') <> 'walsender'
          and query_start is not null
          and coalesce(query, '') not ilike 'start_replication%'
          and coalesce(query, '') not ilike '%repmgr%'
          and extract(epoch from now() - query_start) >= %s
        order by runtime_seconds desc
        limit %s
        """,
        (
            int(settings.get("long_running_query_seconds", 300)),
            int(settings.get("top_sql_limit", 10)),
        ),
    )


def collect_idle_in_transaction_queries(conn, settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    return safe_fetch_all(
        conn,
        """
        select
            pid,
            datname,
            usename,
            client_addr::text as client_addr,
            now() - xact_start as xact_age,
            extract(epoch from now() - xact_start)::bigint as xact_age_seconds,
            left(query, 2000) as query
        from pg_stat_activity
        where pid <> pg_backend_pid()
          and state = 'idle in transaction'
          and xact_start is not null
          and extract(epoch from now() - xact_start) >= %s
        order by xact_age_seconds desc
        limit %s
        """,
        (
            int(settings.get("idle_in_transaction_seconds", 300)),
            int(settings.get("top_sql_limit", 10)),
        ),
    )


def collect_blocking_queries(conn, settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    return safe_fetch_all(
        conn,
        """
        with waiting as (
            select
                sa.pid as waiting_pid,
                sa.datname as waiting_database,
                sa.usename as waiting_user,
                sa.client_addr::text as waiting_client_addr,
                extract(epoch from now() - sa.query_start)::bigint as waiting_seconds,
                left(sa.query, 2000) as waiting_query,
                unnest(pg_blocking_pids(sa.pid)) as blocking_pid
            from pg_stat_activity sa
            where cardinality(pg_blocking_pids(sa.pid)) > 0
        )
        select
            w.waiting_pid,
            w.waiting_database,
            w.waiting_user,
            w.waiting_client_addr,
            w.waiting_seconds,
            w.waiting_query,
            blocker.pid as blocking_pid,
            blocker.usename as blocking_user,
            blocker.datname as blocking_database,
            blocker.client_addr::text as blocking_client_addr,
            left(blocker.query, 2000) as blocking_query
        from waiting w
        join pg_stat_activity blocker on blocker.pid = w.blocking_pid
        order by w.waiting_seconds desc, w.waiting_pid
        limit %s
        """,
        (int(settings.get("blocking_sql_limit", 10)),),
    )


def get_pg_stat_statements_columns(conn) -> List[str]:
    rows = safe_fetch_all(
        conn,
        """
        select column_name
        from information_schema.columns
        where table_schema = 'public'
          and table_name = 'pg_stat_statements'
        order by ordinal_position
        """,
    )
    return [str(row["column_name"]) for row in rows]


def collect_pg_stat_statements(conn, settings: Dict[str, Any]) -> Dict[str, Any]:
    columns = get_pg_stat_statements_columns(conn)
    if not columns:
        return {
            "enabled": False,
            "message": "pg_stat_statements is not installed in the connected database.",
            "top_by_total_time": [],
            "top_by_calls": [],
            "top_by_mean_time": [],
        }

    total_time_col = "total_exec_time" if "total_exec_time" in columns else "total_time"
    mean_time_col = "mean_exec_time" if "mean_exec_time" in columns else "mean_time"
    limit_value = int(settings.get("top_sql_limit", 10))

    base_select = f"""
        select
            coalesce(d.datname, s.dbid::text) as database_name,
            s.calls,
            round(coalesce(s.{total_time_col}, 0)::numeric, 2) as total_time_ms,
            round(coalesce(s.{mean_time_col}, 0)::numeric, 2) as mean_time_ms,
            s.rows,
            left(regexp_replace(s.query, '\\s+', ' ', 'g'), 1000) as query
        from public.pg_stat_statements s
        left join pg_database d on d.oid = s.dbid
    """

    top_by_total_time = safe_fetch_all(
        conn,
        base_select + f" order by s.{total_time_col} desc limit %s",
        (limit_value,),
    )
    top_by_calls = safe_fetch_all(
        conn,
        base_select + " order by s.calls desc limit %s",
        (limit_value,),
    )
    top_by_mean_time = safe_fetch_all(
        conn,
        base_select + f" where s.calls > 0 order by s.{mean_time_col} desc limit %s",
        (limit_value,),
    )

    info_row = safe_fetch_one(conn, "select * from public.pg_stat_statements_info")
    return {
        "enabled": True,
        "message": "",
        "top_by_total_time": top_by_total_time,
        "top_by_calls": top_by_calls,
        "top_by_mean_time": top_by_mean_time,
        "info": info_row or {},
    }


def collect_database_counters(conn) -> Dict[str, Any]:
    row = fetch_one(
        conn,
        """
        select
            sum(xact_commit + xact_rollback) as xact_total,
            sum(tup_returned + tup_fetched) as tuples_read,
            sum(tup_inserted + tup_updated + tup_deleted) as tuples_written,
            sum(blks_hit + blks_read) as buffer_accesses,
            sum(deadlocks) as deadlocks,
            max(stats_reset) as stats_reset
        from pg_stat_database
        where datname not in ('template0', 'template1')
        """,
    )
    return {
        "xact_total": int(row["xact_total"] or 0),
        "tuples_read": int(row["tuples_read"] or 0),
        "tuples_written": int(row["tuples_written"] or 0),
        "buffer_accesses": int(row["buffer_accesses"] or 0),
        "deadlocks": int(row["deadlocks"] or 0),
        "stats_reset": format_timestamp(row["stats_reset"]),
    }


def collect_storage_metrics(conn) -> Dict[str, Any]:
    tablespaces = safe_fetch_all(
        conn,
        """
        select
            spcname,
            nullif(pg_tablespace_location(oid), '') as location,
            pg_tablespace_size(oid) as size_bytes
        from pg_tablespace
        order by size_bytes desc, spcname
        """,
    )
    database_sizes = safe_fetch_all(
        conn,
        """
        select
            datname,
            pg_database_size(datname) as size_bytes
        from pg_database
        where datallowconn
        order by size_bytes desc, datname
        """
    )
    archiver = safe_fetch_one(conn, "select * from pg_stat_archiver")
    return {
        "tablespaces": tablespaces,
        "database_sizes": database_sizes,
        "archiver": archiver or {},
    }


def compute_rate_metrics(
    previous_state: Dict[str, Any],
    current_state: Dict[str, Any],
) -> Dict[str, Any]:
    previous_timestamp = previous_state.get("captured_at")
    current_timestamp = current_state.get("captured_at")
    if not previous_timestamp or not current_timestamp:
        return {"interval_seconds": None}

    previous_dt = datetime.fromisoformat(previous_timestamp)
    current_dt = datetime.fromisoformat(current_timestamp)
    interval_seconds = max(int((current_dt - previous_dt).total_seconds()), 0)
    metrics: Dict[str, Any] = {"interval_seconds": interval_seconds}
    if interval_seconds == 0:
        return metrics

    prev_counters = previous_state.get("database_counters", {})
    curr_counters = current_state.get("database_counters", {})
    metrics["stats_reset_changed"] = prev_counters.get("stats_reset") != curr_counters.get("stats_reset")
    if not metrics["stats_reset_changed"]:
        for key, label in (
            ("xact_total", "tps"),
            ("tuples_read", "rows_read_per_second"),
            ("tuples_written", "rows_written_per_second"),
            ("buffer_accesses", "buffer_accesses_per_second"),
        ):
            delta = int(curr_counters.get(key, 0)) - int(prev_counters.get(key, 0))
            metrics[f"{key}_delta"] = delta
            metrics[label] = round(delta / interval_seconds, 2)
        deadlocks_delta = int(curr_counters.get("deadlocks", 0)) - int(prev_counters.get("deadlocks", 0))
        metrics["deadlocks_delta"] = deadlocks_delta

    prev_host = previous_state.get("host_metrics", {})
    curr_host = current_state.get("host_metrics", {})
    for section_key, label in (
        ("data_directory", "data_directory_growth_bytes"),
        ("wal_directory", "wal_directory_growth_bytes"),
    ):
        prev_value = ((prev_host.get("sizes") or {}).get(section_key) or {}).get("size_bytes")
        curr_value = ((curr_host.get("sizes") or {}).get(section_key) or {}).get("size_bytes")
        if prev_value is not None and curr_value is not None:
            metrics[label] = int(curr_value) - int(prev_value)

    prev_ready = prev_host.get("archive_ready_count")
    curr_ready = curr_host.get("archive_ready_count")
    if prev_ready is not None and curr_ready is not None:
        metrics["archive_ready_delta"] = int(curr_ready) - int(prev_ready)

    return metrics


def add_connection_findings(
    findings: List[Finding],
    connection_stats: Dict[str, Any],
    settings: Dict[str, Any],
) -> None:
    usage_pct = float(connection_stats.get("usage_pct") or 0.0)
    warn_pct = float(settings.get("connection_usage_warn_pct", 80))
    critical_pct = float(settings.get("connection_usage_critical_pct", 90))
    if usage_pct >= critical_pct:
        findings.append(
            build_finding(
                "critical",
                "instance_health",
                "Connection usage is near saturation",
                f"Connections reached {usage_pct:.2f}% of max_connections.",
                "The instance is close to exhausting available backend slots. New sessions may fail soon.",
                "Reduce unnecessary sessions, add pooling, or increase max_connections only after memory impact review.",
                [
                    f"active={connection_stats.get('active_connections')}",
                    f"total={connection_stats.get('total_connections')}",
                    f"max_connections={connection_stats.get('max_connections')}",
                ],
            )
        )
    elif usage_pct >= warn_pct:
        findings.append(
            build_finding(
                "high",
                "instance_health",
                "Connection usage is elevated",
                f"Connections reached {usage_pct:.2f}% of max_connections.",
                "Connection pressure is materially higher than the configured warning threshold.",
                "Review pool sizing, session leaks, and batch-job concurrency before the instance runs out of slots.",
                [
                    f"active={connection_stats.get('active_connections')}",
                    f"total={connection_stats.get('total_connections')}",
                    f"max_connections={connection_stats.get('max_connections')}",
                ],
            )
        )


def add_primary_replication_findings(
    findings: List[Finding],
    replication_rows: List[Dict[str, Any]],
    node_cfg: Dict[str, Any],
    settings: Dict[str, Any],
) -> None:
    expected_standby_count = int(node_cfg.get("expected_standby_count", 0))
    if expected_standby_count and len(replication_rows) < expected_standby_count:
        findings.append(
            build_finding(
                "critical",
                "replication",
                "Expected standby connections are missing",
                f"Primary sees {len(replication_rows)} standby connection(s) but {expected_standby_count} were expected.",
                "A standby may be disconnected or the primary may be unable to stream WAL to every replica.",
                "Check replication services, network reachability, and authentication for the missing standby nodes.",
                [f"expected={expected_standby_count}", f"observed={len(replication_rows)}"],
            )
        )

    warn_bytes = int(settings.get("replication_lag_bytes_warn", 268435456))
    critical_bytes = int(settings.get("replication_lag_bytes_critical", 1073741824))
    for row in replication_rows:
        backlog = int(row.get("replay_backlog_bytes") or 0)
        if backlog >= critical_bytes:
            findings.append(
                build_finding(
                    "critical",
                    "replication",
                    "Standby replay backlog is critical",
                    f"Standby {row.get('application_name') or row.get('client_addr') or row.get('pid')} is {format_bytes(backlog)} behind.",
                    "The primary is generating WAL faster than this standby is replaying it.",
                    "Check standby I/O, network, and replay health. Clear backlog before failover readiness is affected.",
                    [
                        f"state={row.get('state')}",
                        f"sync_state={row.get('sync_state')}",
                        f"replay_backlog_bytes={backlog}",
                    ],
                )
            )
        elif backlog >= warn_bytes:
            findings.append(
                build_finding(
                    "high",
                    "replication",
                    "Standby replay backlog is elevated",
                    f"Standby {row.get('application_name') or row.get('client_addr') or row.get('pid')} is {format_bytes(backlog)} behind.",
                    "Replication is still functioning but lag is beyond the configured warning threshold.",
                    "Review standby resource usage and network latency, then confirm that WAL replay is keeping up.",
                    [
                        f"state={row.get('state')}",
                        f"sync_state={row.get('sync_state')}",
                        f"replay_backlog_bytes={backlog}",
                    ],
                )
            )


def interval_seconds(value: Any) -> Optional[float]:
    if value is None:
        return None
    if hasattr(value, "total_seconds"):
        return float(value.total_seconds())
    return None


def add_standby_findings(
    findings: List[Finding],
    standby_status: Dict[str, Any],
    settings: Dict[str, Any],
) -> None:
    receiver = standby_status.get("wal_receiver")
    replay = standby_status.get("replay", {})
    if not receiver:
        findings.append(
            build_finding(
                "critical",
                "replication",
                "WAL receiver is not running on the standby",
                "The standby did not report an active row in pg_stat_wal_receiver.",
                "The replica is not actively receiving WAL from upstream.",
                "Check recovery configuration, replication credentials, network path, and PostgreSQL logs on the standby.",
                [],
            )
        )
        return

    if str(receiver.get("status") or "").lower() != "streaming":
        findings.append(
            build_finding(
                "high",
                "replication",
                "Standby WAL receiver is not in streaming state",
                f"WAL receiver status is {receiver.get('status')}.",
                "The standby is connected but not in the expected continuous streaming state.",
                "Review WAL receiver state, upstream connectivity, and recent PostgreSQL log messages on the standby.",
                [f"slot_name={receiver.get('slot_name')}", f"conninfo={receiver.get('conninfo')}"],
            )
        )

    replay_delay_seconds = interval_seconds(replay.get("replay_delay"))
    warn_seconds = int(settings.get("standby_replay_delay_warn_seconds", 300))
    critical_seconds = int(settings.get("standby_replay_delay_critical_seconds", 900))
    if replay_delay_seconds is not None and replay_delay_seconds >= critical_seconds:
        findings.append(
            build_finding(
                "critical",
                "replication",
                "Standby replay delay is critical",
                f"Replay delay reached {int(replay_delay_seconds)} seconds.",
                "The standby is materially behind the latest transaction replay point.",
                "Check standby CPU, disk, and network performance, then confirm replay resumes at expected speed.",
                [f"last_replay_timestamp={format_timestamp(replay.get('last_replay_timestamp'))}"],
            )
        )
    elif replay_delay_seconds is not None and replay_delay_seconds >= warn_seconds:
        findings.append(
            build_finding(
                "high",
                "replication",
                "Standby replay delay is elevated",
                f"Replay delay reached {int(replay_delay_seconds)} seconds.",
                "The standby is behind beyond the configured warning threshold.",
                "Investigate replay lag before it grows enough to compromise failover readiness.",
                [f"last_replay_timestamp={format_timestamp(replay.get('last_replay_timestamp'))}"],
            )
        )

    backlog = int(replay.get("replay_backlog_bytes") or 0)
    warn_bytes = int(settings.get("replication_lag_bytes_warn", 268435456))
    critical_bytes = int(settings.get("replication_lag_bytes_critical", 1073741824))
    if backlog >= critical_bytes:
        findings.append(
            build_finding(
                "critical",
                "replication",
                "Standby receive-to-replay backlog is critical",
                f"Standby backlog between received and replayed WAL reached {format_bytes(backlog)}.",
                "WAL is arriving faster than it is being replayed.",
                "Check standby I/O saturation and replay blockers, then confirm replay lag declines after remediation.",
                [f"replay_backlog_bytes={backlog}"],
            )
        )
    elif backlog >= warn_bytes:
        findings.append(
            build_finding(
                "high",
                "replication",
                "Standby receive-to-replay backlog is elevated",
                f"Standby backlog between received and replayed WAL reached {format_bytes(backlog)}.",
                "Replay throughput is behind the current WAL receive rate.",
                "Review standby performance and recent workload spikes before lag becomes critical.",
                [f"replay_backlog_bytes={backlog}"],
            )
        )

    receipt_time = receiver.get("last_msg_receipt_time")
    if receipt_time and hasattr(receipt_time, "tzinfo"):
        stale_seconds = max(int((now_utc() - receipt_time).total_seconds()), 0)
        warn_stale = int(settings.get("wal_receiver_stale_warn_seconds", 300))
        critical_stale = int(settings.get("wal_receiver_stale_critical_seconds", 900))
        if stale_seconds >= critical_stale:
            findings.append(
                build_finding(
                    "critical",
                    "replication",
                    "Standby has not received WAL messages recently",
                    f"Last WAL receiver message arrived {stale_seconds} seconds ago.",
                    "The standby connection appears stale and may stop progressing soon.",
                    "Check upstream availability, network connectivity, and standby logs immediately.",
                    [f"last_msg_receipt_time={format_timestamp(receipt_time)}"],
                )
            )
        elif stale_seconds >= warn_stale:
            findings.append(
                build_finding(
                    "high",
                    "replication",
                    "Standby WAL receiver freshness is degraded",
                    f"Last WAL receiver message arrived {stale_seconds} seconds ago.",
                    "The receiver is still present but message freshness is beyond the warning threshold.",
                    "Review replication connectivity and message flow before the receiver disconnects completely.",
                    [f"last_msg_receipt_time={format_timestamp(receipt_time)}"],
                )
            )

    if replay.get("replay_paused"):
        findings.append(
            build_finding(
                "high",
                "replication",
                "Standby WAL replay is paused",
                "pg_is_wal_replay_paused() returned true.",
                "The standby cannot catch up while replay remains paused.",
                "Resume WAL replay unless the pause is part of a controlled maintenance action.",
                [],
            )
        )


def add_workload_findings(
    findings: List[Finding],
    long_running_queries: List[Dict[str, Any]],
    blocking_queries: List[Dict[str, Any]],
    idle_queries: List[Dict[str, Any]],
    pg_stat_statements_metrics: Dict[str, Any],
    settings: Dict[str, Any],
) -> None:
    alert_seconds = int(settings.get("long_running_query_alert_seconds", 900))
    severe_long_running = [row for row in long_running_queries if int(row.get("runtime_seconds") or 0) >= alert_seconds]
    if severe_long_running:
        findings.append(
            build_finding(
                "high",
                "performance",
                "Long-running SQLs exceeded the alert threshold",
                f"{len(severe_long_running)} long-running query or queries exceeded {alert_seconds} seconds.",
                "Extended runtime can indicate missing indexes, blocked transactions, or application-side inefficiency.",
                "Review the SQL text, execution plans, and locking chains, then terminate only when the business impact justifies it.",
                [
                    f"pid={row.get('pid')} runtime_seconds={row.get('runtime_seconds')} query={shorten_sql(row.get('query'))}"
                    for row in severe_long_running[:5]
                ],
            )
        )

    if blocking_queries:
        findings.append(
            build_finding(
                "high",
                "performance",
                "Blocking SQL detected",
                f"{len(blocking_queries)} blocking relationship(s) were found in pg_stat_activity.",
                "Blocked sessions reduce throughput and can cascade into application errors.",
                "Review the blocker sessions, lock types, and application code path. Clear the blocker in a controlled way.",
                [
                    f"waiting_pid={row.get('waiting_pid')} blocking_pid={row.get('blocking_pid')} waiting_seconds={row.get('waiting_seconds')}"
                    for row in blocking_queries[:5]
                ],
            )
        )

    idle_alert_seconds = int(settings.get("idle_in_transaction_alert_seconds", 900))
    severe_idle = [row for row in idle_queries if int(row.get("xact_age_seconds") or 0) >= idle_alert_seconds]
    if severe_idle:
        findings.append(
            build_finding(
                "high",
                "performance",
                "Idle-in-transaction sessions are aged",
                f"{len(severe_idle)} idle-in-transaction session(s) exceeded {idle_alert_seconds} seconds.",
                "Idle transactions hold resources and can delay vacuum, DDL, and lock release.",
                "Fix the application transaction scope and clear the oldest sessions that are no longer safe to keep open.",
                [
                    f"pid={row.get('pid')} age_seconds={row.get('xact_age_seconds')} query={shorten_sql(row.get('query'))}"
                    for row in severe_idle[:5]
                ],
            )
        )

    if not pg_stat_statements_metrics.get("enabled"):
        findings.append(
            build_finding(
                "medium",
                "performance",
                "pg_stat_statements is unavailable",
                "Top SQL by time, calls, and mean runtime could not be collected because pg_stat_statements is not available.",
                "The monitor can still collect session-level activity, but the historical SQL profile is incomplete.",
                "Install and enable pg_stat_statements in the database used by this monitor.",
                [pg_stat_statements_metrics.get("message", "pg_stat_statements not found.")],
            )
        )


def match_path_filesystem(filesystems: List[Dict[str, Any]], path_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path_value:
        return None
    best_match = None
    best_length = -1
    for row in filesystems:
        mountpoint = str(row.get("mountpoint") or "")
        if path_value.startswith(mountpoint) and len(mountpoint) > best_length:
            best_match = row
            best_length = len(mountpoint)
    return best_match


def add_storage_findings(
    findings: List[Finding],
    storage_metrics: Dict[str, Any],
    host_metrics: Dict[str, Any],
    rate_metrics: Dict[str, Any],
    settings: Dict[str, Any],
) -> None:
    archiver = storage_metrics.get("archiver") or {}
    archive_ready_count = int(host_metrics.get("archive_ready_count") or 0)
    archive_ready_warn = int(settings.get("archive_ready_warn_count", 20))
    archive_ready_critical = int(settings.get("archive_ready_critical_count", 100))

    if archive_ready_count >= archive_ready_critical:
        findings.append(
            build_finding(
                "critical",
                "storage_wal",
                "WAL archive backlog is critical",
                f"The archive_status queue currently has {archive_ready_count} ready WAL files.",
                "A large .ready backlog indicates WAL files are waiting to be archived and retention pressure can build quickly.",
                "Check archive_command, archive destination availability, and filesystem permissions immediately.",
                [f"archive_status_dir={host_metrics.get('archive_status_dir')}"],
            )
        )
    elif archive_ready_count >= archive_ready_warn:
        findings.append(
            build_finding(
                "high",
                "storage_wal",
                "WAL archive backlog is elevated",
                f"The archive_status queue currently has {archive_ready_count} ready WAL files.",
                "Archive delivery is lagging behind WAL generation.",
                "Review archive throughput before the queue grows enough to threaten disk capacity or RPO expectations.",
                [f"archive_status_dir={host_metrics.get('archive_status_dir')}"],
            )
        )

    archive_ready_delta = rate_metrics.get("archive_ready_delta")
    if archive_ready_delta is not None and archive_ready_delta > 0:
        findings.append(
            build_finding(
                "high" if archive_ready_delta >= archive_ready_warn else "medium",
                "storage_wal",
                "WAL archive backlog increased since the previous run",
                f"The .ready queue increased by {archive_ready_delta} file(s) since the previous state snapshot.",
                "The backlog is growing rather than draining between runs.",
                "Review archiving throughput and downstream storage availability.",
                [f"previous_interval_seconds={rate_metrics.get('interval_seconds')}"],
            )
        )

    if archiver:
        failed_count = int(archiver.get("failed_count") or 0)
        archived_count = int(archiver.get("archived_count") or 0)
        last_archived_time = archiver.get("last_archived_time")
        last_failed_time = archiver.get("last_failed_time")
        if failed_count > 0 and (not last_archived_time or (last_failed_time and last_failed_time >= last_archived_time)):
            findings.append(
                build_finding(
                    "high",
                    "storage_wal",
                    "Recent WAL archive failures were reported",
                    "pg_stat_archiver shows failures that are not clearly followed by a successful archive.",
                    "WAL archiving may be failing continuously or intermittently.",
                    "Inspect archive_command, destination storage, and PostgreSQL logs on the primary.",
                    [
                        f"archived_count={archived_count}",
                        f"failed_count={failed_count}",
                        f"last_archived_time={format_timestamp(last_archived_time)}",
                        f"last_failed_time={format_timestamp(last_failed_time)}",
                    ],
                )
            )

    filesystems = host_metrics.get("filesystems") or []
    filesystem_warn = int(settings.get("filesystem_usage_warn_pct", 80))
    filesystem_critical = int(settings.get("filesystem_usage_critical_pct", 90))
    sizes = host_metrics.get("sizes") or {}
    for label in ("data_directory", "wal_directory"):
        path_value = (sizes.get(label) or {}).get("path")
        fs_row = match_path_filesystem(filesystems, path_value)
        if not fs_row:
            continue
        used_pct = int(fs_row.get("used_pct") or 0)
        if used_pct >= filesystem_critical:
            findings.append(
                build_finding(
                    "critical",
                    "storage_wal",
                    f"{label.replace('_', ' ').title()} filesystem usage is critical",
                    f"Filesystem usage for {path_value} reached {used_pct}%.",
                    "The host is close to running out of disk space on a critical PostgreSQL path.",
                    "Free capacity immediately or expand storage before PostgreSQL starts failing writes or checkpoints.",
                    [f"filesystem={fs_row.get('filesystem')}", f"mountpoint={fs_row.get('mountpoint')}"],
                )
            )
        elif used_pct >= filesystem_warn:
            findings.append(
                build_finding(
                    "high",
                    "storage_wal",
                    f"{label.replace('_', ' ').title()} filesystem usage is elevated",
                    f"Filesystem usage for {path_value} reached {used_pct}%.",
                    "Disk pressure is above the warning threshold on a PostgreSQL-critical path.",
                    "Plan capacity cleanup or expansion before write performance and WAL retention are affected.",
                    [f"filesystem={fs_row.get('filesystem')}", f"mountpoint={fs_row.get('mountpoint')}"],
                )
            )

    for growth_key, warn_key, critical_key, title in (
        ("data_directory_growth_bytes", "data_dir_growth_warn_bytes", "data_dir_growth_critical_bytes", "Data directory growth"),
        ("wal_directory_growth_bytes", "wal_dir_growth_warn_bytes", "wal_dir_growth_critical_bytes", "WAL directory growth"),
    ):
        growth_value = rate_metrics.get(growth_key)
        if growth_value is None:
            continue
        warn_value = int(settings.get(warn_key, 0))
        critical_value = int(settings.get(critical_key, 0))
        if critical_value > 0 and growth_value >= critical_value:
            findings.append(
                build_finding(
                    "critical",
                    "storage_wal",
                    f"{title} is above the critical threshold",
                    f"{title} since the previous run was {format_bytes(growth_value)}.",
                    "The path grew beyond the configured critical daily growth limit.",
                    "Check workload growth, retention, and housekeeping before disk pressure accelerates further.",
                    [f"interval_seconds={rate_metrics.get('interval_seconds')}"],
                )
            )
        elif warn_value > 0 and growth_value >= warn_value:
            findings.append(
                build_finding(
                    "high",
                    "storage_wal",
                    f"{title} is above the warning threshold",
                    f"{title} since the previous run was {format_bytes(growth_value)}.",
                    "The path grew beyond the configured daily warning limit.",
                    "Review the growth source and confirm it matches expected workload behavior.",
                    [f"interval_seconds={rate_metrics.get('interval_seconds')}"],
                )
            )


def summarize_findings(findings: List[Finding]) -> Dict[str, int]:
    return dict(Counter(finding.severity for finding in findings))


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.category, item.title))


def build_node_state(
    metadata: Dict[str, Any],
    connection_stats: Dict[str, Any],
    database_counters: Dict[str, Any],
    host_metrics: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "captured_at": format_timestamp(metadata.get("collected_at")),
        "database_counters": database_counters,
        "connection_stats": connection_stats,
        "host_metrics": host_metrics,
    }


def collect_node_report(
    node_cfg: Dict[str, Any],
    settings: Dict[str, Any],
    previous_state: Dict[str, Any],
) -> NodeReport:
    generated_at = now_utc().isoformat()
    host = str(node_cfg.get("host"))
    port = int(node_cfg.get("port"))
    database_name = str(node_cfg.get("database"))
    errors: List[str] = []
    findings: List[Finding] = []
    metrics: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    state: Dict[str, Any] = {}
    role = "unknown"
    ssh_client = None

    try:
        conn_kwargs = build_connection_kwargs(node_cfg, settings)
        conn = psycopg2.connect(**conn_kwargs)
    except Exception as exc:
        if is_auth_failure_message(str(exc)):
            raise AuthenticationFailure(f"Database authentication failed for node '{node_cfg.get('name')}': {exc}") from exc
        return NodeReport(
            name=str(node_cfg.get("name")),
            host=host,
            port=port,
            database=database_name,
            role="unreachable",
            ok=False,
            generated_at=generated_at,
            metadata={},
            metrics={},
            findings=[],
            errors=[f"Database connection failed: {exc}"],
            state={},
        )

    try:
        with conn.cursor() as cur:
            cur.execute("set statement_timeout = %s", (int(settings.get("statement_timeout_ms", 30000)),))

        metadata = collect_instance_overview(conn)
        role = "standby" if metadata.get("is_in_recovery") else "primary"
        version_num = int(metadata.get("server_version_num") or 0)
        wal_directory = str(
            node_cfg.get("wal_directory")
            or (Path(str(metadata.get("data_directory"))) / ("pg_wal" if version_num >= 100000 else "pg_xlog"))
        )

        connection_stats = collect_connection_stats(conn)
        primary_replication = collect_primary_replication(conn, version_num) if role == "primary" else []
        standby_status = collect_standby_status(conn, version_num) if role == "standby" else {}
        long_running_queries = collect_long_running_queries(conn, settings)
        idle_in_transaction_queries = collect_idle_in_transaction_queries(conn, settings)
        blocking_queries = collect_blocking_queries(conn, settings)
        pg_stat_statements_metrics = collect_pg_stat_statements(conn, settings)
        database_counters = collect_database_counters(conn)
        storage_metrics = collect_storage_metrics(conn)
        tablespace_locations = [row.get("location") for row in storage_metrics.get("tablespaces", []) if row.get("location")]

        try:
            ssh_client = open_ssh_client(node_cfg.get("ssh", {}))
            host_metrics = collect_host_metrics(
                ssh_client,
                metadata.get("data_directory"),
                wal_directory,
                tablespace_locations,
                sudo_password=str((node_cfg.get("ssh", {}) or {}).get("password") or ""),
            )
        except AuthenticationFailure:
            raise
        except Exception as exc:
            host_metrics = {"enabled": False, "error": str(exc)}
            errors.append(f"Host collection failed: {exc}")

        state = build_node_state(metadata, connection_stats, database_counters, host_metrics)
        rate_metrics = compute_rate_metrics(previous_state, state)
        metrics = {
            "connection_stats": connection_stats,
            "primary_replication": primary_replication,
            "standby_status": standby_status,
            "long_running_queries": long_running_queries,
            "idle_in_transaction_queries": idle_in_transaction_queries,
            "blocking_queries": blocking_queries,
            "pg_stat_statements": pg_stat_statements_metrics,
            "database_counters": database_counters,
            "storage": storage_metrics,
            "host": host_metrics,
            "rates": rate_metrics,
        }

        add_connection_findings(findings, connection_stats, settings)
        if role == "primary":
            add_primary_replication_findings(findings, primary_replication, node_cfg, settings)
        elif role == "standby":
            add_standby_findings(findings, standby_status, settings)
        add_workload_findings(
            findings,
            long_running_queries,
            blocking_queries,
            idle_in_transaction_queries,
            pg_stat_statements_metrics,
            settings,
        )
        if host_metrics.get("enabled"):
            add_storage_findings(findings, storage_metrics, host_metrics, rate_metrics, settings)
    except Exception as exc:
        errors.append(f"Health collection failed: {exc}")
    finally:
        conn.close()
        if ssh_client is not None:
            ssh_client.close()

    findings = sort_findings(findings)
    ok = len(errors) == 0
    return NodeReport(
        name=str(node_cfg.get("name")),
        host=host,
        port=port,
        database=database_name,
        role=role,
        ok=ok,
        generated_at=generated_at,
        metadata=metadata,
        metrics=metrics,
        findings=findings,
        errors=errors,
        state=state,
    )


def build_summary_rows(node_reports: List[NodeReport]) -> List[Dict[str, Any]]:
    rows = []
    for report in node_reports:
        severities = summarize_findings(report.findings)
        rows.append(
            {
                "node": report.name,
                "host": report.host,
                "port": report.port,
                "role": report.role,
                "database": report.database,
                "critical": severities.get("critical", 0),
                "high": severities.get("high", 0),
                "medium": severities.get("medium", 0),
                "low": severities.get("low", 0),
                "errors": len(report.errors),
            }
        )
    return rows


def build_table_html(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "<p class='empty'>No rows.</p>"
    parts = ["<table><thead><tr>"]
    for header in headers:
        parts.append(f"<th>{escape(header)}</th>")
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for value in row:
            parts.append(f"<td>{value}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def render_finding_cards(findings: List[Finding]) -> str:
    if not findings:
        return "<p class='empty'>No findings on this node.</p>"
    cards: List[str] = []
    for finding in findings:
        evidence_html = "".join(f"<li>{escape(item)}</li>" for item in finding.evidence) if finding.evidence else "<li>No extra evidence captured.</li>"
        cards.append(
            "<div class='card'>"
            f"<div class='card-header'><span class='badge severity-{escape(finding.severity)}'>{escape(finding.severity.upper())}</span>"
            f"<h4>{escape(finding.title)}</h4></div>"
            f"<div class='meta'>{escape(finding.category)}</div>"
            f"<p><strong>Summary:</strong> {escape(finding.summary)}</p>"
            f"<p><strong>Details:</strong> {escape(finding.details)}</p>"
            f"<p><strong>Recommendation:</strong> {escape(finding.recommendation)}</p>"
            f"<ul>{evidence_html}</ul>"
            "</div>"
        )
    return "".join(cards)


def build_node_section_html(report: NodeReport) -> str:
    metadata = report.metadata
    metrics = report.metrics
    connection_stats = metrics.get("connection_stats", {})
    storage = metrics.get("storage", {})
    host_metrics = metrics.get("host", {})
    rate_metrics = metrics.get("rates", {})
    pg_stat_statements_metrics = metrics.get("pg_stat_statements", {})

    summary_tiles = [
        ("Role", report.role),
        ("Current DB", metadata.get("database_name", report.database)),
        ("Connections", f"{connection_stats.get('total_connections', 'n/a')} / {connection_stats.get('max_connections', 'n/a')}"),
        ("Connection Usage", f"{connection_stats.get('usage_pct', 'n/a')}%"),
        ("Archive Ready", format_number(host_metrics.get("archive_ready_count"))),
        ("Daily TPS", format_number(rate_metrics.get("tps"))),
    ]
    tile_html = "".join(
        "<div class='tile'>"
        f"<div class='tile-label'>{escape(label)}</div>"
        f"<div class='tile-value'>{escape(str(value))}</div>"
        "</div>"
        for label, value in summary_tiles
    )

    primary_rows = [
        [
            escape(str(row.get("application_name") or "")),
            escape(str(row.get("client_addr") or "")),
            escape(str(row.get("state") or "")),
            escape(str(row.get("sync_state") or "")),
            escape(format_bytes(row.get("replay_backlog_bytes"))),
            escape(str(row.get("replay_lag") or "")),
        ]
        for row in metrics.get("primary_replication", [])
    ]
    standby_receiver = metrics.get("standby_status", {}).get("wal_receiver") or {}
    standby_replay = metrics.get("standby_status", {}).get("replay") or {}
    standby_rows = [
        ["Receiver Status", escape(str(standby_receiver.get("status") or "n/a"))],
        ["Last Message Receipt", escape(format_timestamp(standby_receiver.get("last_msg_receipt_time")))],
        ["Latest End LSN", escape(str(standby_receiver.get("latest_end_lsn") or "n/a"))],
        ["Replay Delay", escape(str(standby_replay.get("replay_delay") or "n/a"))],
        ["Replay Backlog", escape(format_bytes(standby_replay.get("replay_backlog_bytes")))],
        ["Replay Paused", escape(str(standby_replay.get("replay_paused") or "n/a"))],
    ]

    connection_rows = [
        ["Total Connections", escape(format_number(connection_stats.get("total_connections")))],
        ["Active Connections", escape(format_number(connection_stats.get("active_connections")))],
        ["Idle In Transaction", escape(format_number(connection_stats.get("idle_in_transaction")))],
        ["Lock Waiters", escape(format_number(connection_stats.get("lock_waiters")))],
        ["Max Connections", escape(format_number(connection_stats.get("max_connections")))],
        ["Usage Percent", escape(f"{connection_stats.get('usage_pct', 'n/a')}%")],
        ["Uptime", escape(str(metadata.get("collected_at") - metadata.get("postmaster_start_time")) if metadata.get("collected_at") and metadata.get("postmaster_start_time") else "n/a")],
        ["Postmaster Start", escape(format_timestamp(metadata.get("postmaster_start_time")))],
    ]

    host_rows = [
        ["Host Collection", escape("Enabled" if host_metrics.get("enabled") else "Unavailable")],
        ["Remote Hostname", escape(str(host_metrics.get("hostname") or "n/a"))],
        ["Host Uptime", escape(str(host_metrics.get("uptime") or "n/a"))],
        ["Load Average", escape(str(host_metrics.get("load_average") or "n/a"))],
        ["Memory Used", escape(format_bytes((host_metrics.get("memory") or {}).get("used_bytes")))],
        ["Memory Available", escape(format_bytes((host_metrics.get("memory") or {}).get("available_bytes")))],
    ]
    if host_metrics.get("error"):
        host_rows.append(["Host Error", escape(str(host_metrics.get("error")))])

    filesystem_rows = [
        [
            escape(str(row.get("filesystem") or "")),
            escape(str(row.get("mountpoint") or "")),
            escape(format_bytes(row.get("used_bytes"))),
            escape(format_bytes(row.get("available_bytes"))),
            escape(f"{row.get('used_pct')}%"),
        ]
        for row in host_metrics.get("filesystems", [])
    ]

    tablespace_rows = [
        [
            escape(str(row.get("spcname") or "")),
            escape(str(row.get("location") or "inside data directory")),
            escape(format_bytes(row.get("size_bytes"))),
        ]
        for row in storage.get("tablespaces", [])
    ]

    long_running_rows = [
        [
            escape(format_number(row.get("pid"))),
            escape(str(row.get("datname") or "")),
            escape(format_number(row.get("runtime_seconds"))),
            escape(str(row.get("usename") or "")),
            escape(shorten_sql(row.get("query"))),
        ]
        for row in metrics.get("long_running_queries", [])
    ]
    blocking_rows = [
        [
            escape(format_number(row.get("waiting_pid"))),
            escape(format_number(row.get("blocking_pid"))),
            escape(format_number(row.get("waiting_seconds"))),
            escape(shorten_sql(row.get("waiting_query"))),
            escape(shorten_sql(row.get("blocking_query"))),
        ]
        for row in metrics.get("blocking_queries", [])
    ]
    top_sql_rows = [
        [
            escape(str(row.get("database_name") or "")),
            escape(format_number(row.get("calls"))),
            escape(format_number(row.get("total_time_ms"))),
            escape(format_number(row.get("mean_time_ms"))),
            escape(shorten_sql(row.get("query"))),
        ]
        for row in pg_stat_statements_metrics.get("top_by_total_time", [])
    ]

    rate_rows = [
        ["Interval Seconds", escape(format_number(rate_metrics.get("interval_seconds")))],
        ["TPS", escape(format_number(rate_metrics.get("tps")))],
        ["Rows Read / Sec", escape(format_number(rate_metrics.get("rows_read_per_second")))],
        ["Rows Written / Sec", escape(format_number(rate_metrics.get("rows_written_per_second")))],
        ["Buffer Accesses / Sec", escape(format_number(rate_metrics.get("buffer_accesses_per_second")))],
        ["Deadlocks Delta", escape(format_number(rate_metrics.get("deadlocks_delta")))],
        ["Data Dir Growth", escape(format_bytes(rate_metrics.get("data_directory_growth_bytes")))],
        ["WAL Dir Growth", escape(format_bytes(rate_metrics.get("wal_directory_growth_bytes")))],
        ["Archive Ready Delta", escape(format_number(rate_metrics.get("archive_ready_delta")))],
    ]

    role_section = (
        "<h4>Primary Replication</h4>"
        + build_table_html(
            ["Application", "Client", "State", "Sync State", "Replay Backlog", "Replay Lag"],
            primary_rows,
        )
        if report.role == "primary"
        else "<h4>Standby Replication</h4>" + build_table_html(["Metric", "Value"], standby_rows)
    )

    errors_html = ""
    if report.errors:
        errors_html = "<div class='card error-card'><h4>Collection Errors</h4><ul>" + "".join(
            f"<li>{escape(item)}</li>" for item in report.errors
        ) + "</ul></div>"

    return (
        "<section class='node-section'>"
        f"<h2>{escape(report.name)} ({escape(report.host)}:{report.port})</h2>"
        f"<div class='meta'>Database={escape(report.database)} | Generated={escape(report.generated_at)} | PostgreSQL={escape(str(metadata.get('server_version') or 'n/a'))}</div>"
        f"<div class='tiles'>{tile_html}</div>"
        f"{errors_html}"
        "<div class='section-grid'>"
        "<div>"
        "<h3>Major Findings</h3>"
        f"{render_finding_cards(report.findings)}"
        "</div>"
        "<div>"
        "<h3>Instance Health</h3>"
        f"{build_table_html(['Metric', 'Value'], connection_rows)}"
        f"{role_section}"
        "<h3>Host Health</h3>"
        f"{build_table_html(['Metric', 'Value'], host_rows)}"
        "<h4>Filesystem Usage</h4>"
        f"{build_table_html(['Filesystem', 'Mountpoint', 'Used', 'Available', 'Used %'], filesystem_rows)}"
        "<h3>Storage And WAL</h3>"
        f"{build_table_html(['Tablespace', 'Location', 'Size'], tablespace_rows)}"
        "<h4>Daily Rate Metrics</h4>"
        f"{build_table_html(['Metric', 'Value'], rate_rows)}"
        "<h3>Performance</h3>"
        "<h4>Long Running SQLs</h4>"
        f"{build_table_html(['PID', 'Database', 'Runtime Sec', 'User', 'Query'], long_running_rows)}"
        "<h4>Blocking SQLs</h4>"
        f"{build_table_html(['Waiting PID', 'Blocking PID', 'Wait Sec', 'Waiting Query', 'Blocking Query'], blocking_rows)}"
        "<h4>Top SQL By Total Time</h4>"
        f"{build_table_html(['Database', 'Calls', 'Total Time ms', 'Mean Time ms', 'Query'], top_sql_rows)}"
        "</div>"
        "</div>"
        "</section>"
    )


def build_html_report(node_reports: List[NodeReport], generated_at: str) -> str:
    summary_rows = build_summary_rows(node_reports)
    summary_table_rows = [
        [
            escape(str(row["node"])),
            escape(str(row["host"])),
            escape(str(row["port"])),
            escape(str(row["role"])),
            escape(str(row["database"])),
            escape(format_number(row["critical"])),
            escape(format_number(row["high"])),
            escape(format_number(row["medium"])),
            escape(format_number(row["low"])),
            escape(format_number(row["errors"])),
        ]
        for row in summary_rows
    ]

    critical_count = sum(row["critical"] for row in summary_rows)
    high_count = sum(row["high"] for row in summary_rows)
    medium_count = sum(row["medium"] for row in summary_rows)
    node_sections = "".join(build_node_section_html(report) for report in node_reports)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DB Health Checks</title>
  <style>
    body {{ font-family: "Segoe UI", Tahoma, sans-serif; margin: 24px; background: #f8fafc; color: #142236; }}
    h1, h2, h3, h4 {{ margin-bottom: 8px; }}
    table {{ width: 100%; border-collapse: collapse; background: #ffffff; margin-bottom: 16px; }}
    th, td {{ border: 1px solid #d7e0ea; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #14324b; color: #ffffff; }}
    tr:nth-child(even) td {{ background: #f6f8fb; }}
    .hero {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .hero-card {{ background: #ffffff; border: 1px solid #d7e0ea; border-radius: 14px; padding: 16px; }}
    .hero-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #62748a; }}
    .hero-value {{ margin-top: 6px; font-size: 28px; font-weight: 700; }}
    .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 14px 0 22px; }}
    .tile {{ background: #ffffff; border: 1px solid #d7e0ea; border-radius: 14px; padding: 14px; }}
    .tile-label {{ color: #62748a; font-size: 12px; text-transform: uppercase; }}
    .tile-value {{ margin-top: 6px; font-size: 20px; font-weight: 700; }}
    .node-section {{ background: #ffffff; border: 1px solid #d7e0ea; border-radius: 18px; padding: 20px; margin-top: 24px; }}
    .meta {{ color: #62748a; margin-bottom: 8px; }}
    .section-grid {{ display: grid; grid-template-columns: 1.2fr 1fr; gap: 20px; }}
    .card {{ background: #fbfdff; border: 1px solid #d7e0ea; border-radius: 14px; padding: 16px; margin-bottom: 14px; }}
    .card-header {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
    .badge {{ display: inline-block; border-radius: 999px; padding: 4px 10px; font-size: 12px; font-weight: 700; color: #ffffff; }}
    .severity-critical {{ background: #b42318; }}
    .severity-high {{ background: #c2410c; }}
    .severity-medium {{ background: #b54708; }}
    .severity-low {{ background: #475467; }}
    .severity-info {{ background: #155eef; }}
    .empty {{ color: #62748a; font-style: italic; }}
    .error-card {{ border-color: #fda29b; background: #fff6f5; }}
    @media (max-width: 960px) {{
      .section-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <h1>PostgreSQL Daily Health Check</h1>
  <div class="meta">Generated at {escape(generated_at)} UTC</div>
  <div class="hero">
    <div class="hero-card"><div class="hero-label">Nodes</div><div class="hero-value">{len(node_reports)}</div></div>
    <div class="hero-card"><div class="hero-label">Critical Alerts</div><div class="hero-value">{critical_count}</div></div>
    <div class="hero-card"><div class="hero-label">High Alerts</div><div class="hero-value">{high_count}</div></div>
    <div class="hero-card"><div class="hero-label">Medium Alerts</div><div class="hero-value">{medium_count}</div></div>
  </div>
  <h2>Cluster Summary</h2>
  {build_table_html(['Node', 'Host', 'Port', 'Role', 'Database', 'Critical', 'High', 'Medium', 'Low', 'Errors'], summary_table_rows)}
  {node_sections}
</body>
</html>
"""


def build_email_bodies(node_reports: List[NodeReport], settings: Dict[str, Any]) -> Tuple[str, str]:
    major_alert_severities = {str(item).lower() for item in settings.get("major_alert_severities", ["critical", "high"])}
    major_alerts: List[Tuple[str, Finding]] = []
    for report in node_reports:
        for finding in report.findings:
            if finding.severity.lower() in major_alert_severities:
                major_alerts.append((report.name, finding))
        for error in report.errors:
            major_alerts.append(
                (
                    report.name,
                    build_finding(
                        "critical",
                        "collection",
                        "Node collection error",
                        error,
                        error,
                        "Review connectivity and retry the health check.",
                        [],
                    ),
                )
            )

    text_lines = ["Database health summary", ""]
    html_lines = [
        "<html><body style='font-family:Segoe UI,Tahoma,sans-serif;color:#142236'>",
        "<h2>Database health summary</h2>",
    ]

    if not major_alerts:
        text_lines.append("No major alerts were found in this run.")
        html_lines.append("<p>No major alerts were found in this run.</p>")
    else:
        text_lines.append("Major alerts:")
        html_lines.append("<ul>")
        for node_name, finding in major_alerts:
            text_lines.append(f"- {node_name} [{finding.severity.upper()}] {finding.title}: {finding.summary}")
            html_lines.append(
                f"<li><strong>{escape(node_name)}</strong> "
                f"[{escape(finding.severity.upper())}] "
                f"{escape(finding.title)}: {escape(finding.summary)}</li>"
            )
        html_lines.append("</ul>")

    html_lines.append("<p>The full consolidated HTML report is attached.</p></body></html>")
    return "\n".join(text_lines), "".join(html_lines)


def persist_state(output_dir: Path, state_file_name: str, node_reports: List[NodeReport], generated_at: str) -> Path:
    payload = {
        "generated_at": generated_at,
        "nodes": {report.name: report.state for report in node_reports if report.state},
    }
    state_path = output_dir / state_file_name
    state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return state_path


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    try:
        config_data = load_config(config_path)
    except FileNotFoundError:
        print(f"Config file not found: {config_path}")
        return 1
    except json.JSONDecodeError as exc:
        print(f"Config file is not valid JSON: {config_path} ({exc})")
        return 1

    settings = load_settings(config_data)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else (config_path.parent / settings["default_output_dir"]).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_nodes = [
        merge_node_config(item, config_data.get("database_defaults", {}), config_data.get("ssh_defaults", {}))
        for item in config_data.get("nodes", [])
    ]
    selected_nodes = filter_nodes(raw_nodes, args.nodes)
    if not selected_nodes:
        print("No nodes matched the configuration and optional --node filters.")
        return 1

    try:
        require_paramiko_if_needed(selected_nodes)
    except RuntimeError as exc:
        print(str(exc))
        return 1

    previous_state_path = output_dir / str(settings.get("state_file", "db_health_checks_state.json"))
    previous_state_payload = load_json(previous_state_path, {"nodes": {}})
    previous_nodes = previous_state_payload.get("nodes", {})

    node_reports: List[NodeReport] = []
    for node_cfg in selected_nodes:
        try:
            report = collect_node_report(
                node_cfg,
                settings,
                previous_nodes.get(str(node_cfg.get("name")), {}),
            )
        except AuthenticationFailure as exc:
            print(f"Authentication failure detected. Stopping further processing: {exc}")
            return 1
        node_reports.append(report)
        severity_counter = summarize_findings(report.findings)
        print(
            f"{report.name}: role={report.role} critical={severity_counter.get('critical', 0)} "
            f"high={severity_counter.get('high', 0)} medium={severity_counter.get('medium', 0)} "
            f"errors={len(report.errors)}"
        )

    generated_at = now_utc().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"db_health_checks_{generated_at}.html"
    report_path.write_text(build_html_report(node_reports, generated_at), encoding="utf-8")
    persist_state(output_dir, str(settings.get("state_file", "db_health_checks_state.json")), node_reports, generated_at)
    print(f"Consolidated report written: {report_path}")

    run_success = all(report.ok for report in node_reports)
    email_cfg = config_data.get("email", {})
    if run_success and (not args.no_email) and normalize_email_config(email_cfg).get("enabled", False):
        try:
            text_body, html_body = build_email_bodies(node_reports, settings)
            critical_count = sum(summarize_findings(report.findings).get("critical", 0) for report in node_reports)
            high_count = sum(summarize_findings(report.findings).get("high", 0) for report in node_reports)
            subject_prefix = "ALERT" if critical_count or high_count or any(report.errors for report in node_reports) else "OK"
            subject = f"{subject_prefix}: PostgreSQL daily health report for {len(node_reports)} node(s)"
            send_email(email_cfg, subject, text_body, html_body, [report_path])
            print("Email summary sent successfully.")
        except Exception as exc:
            print(f"Email delivery failed: {exc}")
            return 2
    elif not run_success:
        print("Run did not complete successfully for all nodes; email notification was skipped.")

    return 0 if run_success else 1


if __name__ == "__main__":
    raise SystemExit(main())
