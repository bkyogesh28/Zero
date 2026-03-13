import hashlib
from pathlib import Path
from typing import Optional, Dict, Any

import psutil


LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "certutil.exe",
    "regsvr32.exe",
    "wmiprvse.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "schtasks.exe",
    "msbuild.exe",
    "net.exe",
    "mstsc.exe",
}


def get_sha256(file_path: Optional[str], chunk_size: int = 8192) -> Optional[str]:
    if not file_path:
        return None

    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def classify_path(file_path: Optional[str]) -> str:
    if not file_path:
        return "unknown"

    path = file_path.lower()

    if "\\windows\\" in path:
        return "system"
    if "\\program files\\" in path or "\\program files (x86)\\" in path:
        return "program_files"
    if "\\downloads\\" in path:
        return "downloads"
    if "\\appdata\\local\\temp\\" in path or "\\temp\\" in path:
        return "temp"
    if "\\appdata\\" in path:
        return "user_appdata"
    if "\\desktop\\" in path:
        return "desktop"
    if "\\users\\" in path:
        return "user_profile"

    return "other"


def get_username(proc: psutil.Process) -> Optional[str]:
    try:
        return proc.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def get_parent_process_info(proc: psutil.Process) -> Dict[str, Any]:
    try:
        parent = proc.parent()
        if parent is None:
            return {
                "parent_pid": None,
                "parent_name": None,
            }

        return {
            "parent_pid": parent.pid,
            "parent_name": parent.name(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {
            "parent_pid": None,
            "parent_name": None,
        }


def normalize_cmdline(cmdline: Optional[list]) -> Optional[str]:
    if not cmdline:
        return None
    return " ".join(str(part) for part in cmdline)


def is_lolbin(process_name: Optional[str]) -> bool:
    if not process_name:
        return False
    return process_name.lower() in LOLBINS


def get_file_name(file_path: Optional[str]) -> Optional[str]:
    if not file_path:
        return None
    try:
        return Path(file_path).name
    except Exception:
        return None


def build_metadata(proc: psutil.Process) -> Optional[Dict[str, Any]]:
    try:
        info = proc.as_dict(attrs=["pid", "name", "exe", "ppid", "cmdline"])

        exe_path = info.get("exe")
        process_name = info.get("name")

        parent_info = get_parent_process_info(proc)

        metadata = {
            "pid": info.get("pid"),
            "process_name": process_name,
            "exe": exe_path,
            "file_name": get_file_name(exe_path),
            "parent_pid": parent_info["parent_pid"],
            "parent_name": parent_info["parent_name"],
            "cmdline": normalize_cmdline(info.get("cmdline")),
            "username": get_username(proc),
            "sha256": get_sha256(exe_path),
            "path_type": classify_path(exe_path),
            "is_lolbin": is_lolbin(process_name),
        }

        return metadata

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None