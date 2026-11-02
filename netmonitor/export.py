"""Log export and backup utilities.

Hardening:
- Path traversal protection for backup source paths.
- Archive names sanitized to prevent directory escape.
- File size limits to prevent disk exhaustion.
"""

import csv
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import BACKUPS_DIR, LOGS_DIR

# Maximum backup archive size (100 MB) to prevent disk exhaustion
MAX_BACKUP_SIZE = 100 * 1024 * 1024

# Characters allowed in archive names
ARCHIVE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _sanitize_archive_name(name: Optional[str]) -> str:
    """Sanitize an archive name to prevent path traversal."""
    if not name:
        return ""
    name = name.strip()
    if not ARCHIVE_NAME_RE.match(name):
        raise ValueError("Archive name contains invalid characters. Use alphanumeric, dots, dashes, underscores only.")
    if ".." in name or name.startswith("/") or name.startswith("\\"):
        raise ValueError("Invalid archive name")
    return name


def export_logs(
    data: Any,
    label: str = "netmonitor",
    fmt: str = "json",
) -> str:
    """Export scan/intel data to a timestamped file.

    Returns the absolute path of the written file.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _timestamp()

    safe_label = re.sub(r"[^A-Za-z0-9._-]", "_", label) or "netmonitor"

    if fmt == "json":
        path = LOGS_DIR / f"{safe_label}_{stamp}.json"
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
    elif fmt == "csv":
        path = LOGS_DIR / f"{safe_label}_{stamp}.csv"
        rows: List[Dict[str, Any]] = data if isinstance(data, list) else [data]
        fieldnames = sorted({k for row in rows for k in row.keys()}) if rows else []
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({k: str(v) for k, v in row.items()})
    else:
        path = LOGS_DIR / f"{safe_label}_{stamp}.txt"
        with path.open("w", encoding="utf-8") as fh:
            fh.write(f"netmonitor export — {safe_label}\n")
            fh.write(f"Generated: {datetime.now().isoformat()}\n")
            fh.write("=" * 60 + "\n\n")
            fh.write(json.dumps(data, indent=2, ensure_ascii=False, default=str))

    return str(path.resolve())


def backup(source_path: str, archive_name: Optional[str] = None) -> str:
    """Create a ZIP backup of a file or directory.

    Returns the absolute path of the ZIP archive.

    Raises:
        FileNotFoundError: If source doesn't exist.
        ValueError: If archive_name is unsafe or source is protected.
    """
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(source_path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"Source path not found: {source_path}")

    # Prevent backing up the config directory itself (contains secrets)
    config_dir = Path.home() / ".netmonitor"
    try:
        src.relative_to(config_dir)
        # src IS under config_dir — block it
        raise ValueError("Cannot back up the .netmonitor configuration directory (contains secrets).")
    except ValueError as exc:
        if "Cannot back up" in str(exc):
            raise
        # relative_to failed — src is NOT under config_dir, which is OK
        pass

    safe_name = _sanitize_archive_name(archive_name)
    stamp = _timestamp()
    base = f"backup_{src.name}_{stamp}"
    if safe_name:
        base = f"backup_{safe_name}_{stamp}"
    name = base + ".zip"
    out = BACKUPS_DIR / name

    total_size = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        if src.is_file():
            zf.write(src, arcname=src.name)
            total_size += src.stat().st_size
        else:
            for file in src.rglob("*"):
                if file.is_file():
                    if file.is_symlink():
                        continue
                    arcname = str(file.relative_to(src))
                    if ".." in arcname or arcname.startswith("/"):
                        continue
                    zf.write(file, arcname=arcname)
                    total_size += file.stat().st_size
                    if total_size > MAX_BACKUP_SIZE:
                        out.unlink(missing_ok=True)
                        raise ValueError(f"Backup exceeds maximum size ({MAX_BACKUP_SIZE // (1024 * 1024)} MB)")

    return str(out.resolve())
