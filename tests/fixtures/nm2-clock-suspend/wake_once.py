"""PRIVATE source proposal; no native action without explicit reviewed selection.

No module-level native loading. Returned observations are NEVER C09 acceptance.
The orchestrator must bind the original job and corroborate guest clock/exit proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent
PS = Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
RTC = Path("/sys/class/rtc/rtc0")
FIELDS = {"schema", "platform", "seconds", "boot_identity", "primitive_sha256", "rtc_device"}


class Refused(ValueError):
    pass


class RTCReturnRefused(Refused):
    def __init__(self, readback):
        super().__init__("rtc_return_unconfirmed")
        self.readback = readback


def require(value, reason):
    if not value:
        raise Refused(reason)


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, "selection_invalid")
        result[key] = value
    return result


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "selection_invalid")
    def constant(_):
        raise Refused("selection_invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("selection_invalid") from None
    require(type(value) is dict, "selection_invalid")
    return value


def selection(path, reviewed_sha256):
    require(type(reviewed_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", reviewed_sha256), "selection_invalid")
    require(path.is_absolute() and not path.is_symlink() and path.parent.resolve() == ROOT, "selection_invalid")
    require(stat.S_ISREG(path.stat().st_mode) and 0 < path.stat().st_size <= 16384, "selection_invalid")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == reviewed_sha256, "selection_changed")
    value = decode(raw)
    require(set(value) == FIELDS and value["schema"] == "vardr.nm2-c09-wake-selection/1"
            and value["platform"] == sys.platform and sys.platform in {"win32", "linux"}
            and type(value["seconds"]) is int and value["seconds"] == 20
            and type(value["boot_identity"]) is str and 0 < len(value["boot_identity"]) <= 80
            and type(value["primitive_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", value["primitive_sha256"])
            and value["rtc_device"] == ("/dev/rtc0" if sys.platform == "linux" else None), "selection_invalid")
    return value


def boot_identity():
    if sys.platform == "linux":
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        require(str(uuid.UUID(value)) == value, "boot_identity_unavailable")
        return value
    reply = subprocess.run([str(PS), "-NoProfile", "-NonInteractive", "-Command",
        "(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')"],
        capture_output=True, check=True, timeout=10)
    require(reply.stderr == b"" and 0 < len(reply.stdout) <= 128, "boot_identity_unavailable")
    value = reply.stdout.decode("ascii").strip()
    require(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z", value), "boot_identity_unavailable")
    return value


def binary(path, wanted):
    require(path.is_absolute() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), "primitive_invalid")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == wanted, "primitive_changed")
    return str(path)


def linux_sample():
    value = {"utc_before": time.time_ns(), "boot": time.clock_gettime_ns(time.CLOCK_BOOTTIME),
             "mono": time.clock_gettime_ns(time.CLOCK_MONOTONIC), "utc_after": time.time_ns()}
    require(0 <= value["utc_after"] - value["utc_before"] <= 50_000_000, "clock_sample_invalid")
    return value


def rtc_identity():
    info = Path("/dev/rtc0").lstat()
    require(stat.S_ISCHR(info.st_mode)
            and (RTC / "dev").read_text().strip() == f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}",
            "rtc_identity_unconfirmed")
    return info.st_dev, info.st_ino, info.st_rdev


def rtc_readback(identity, mem_sleep):
    result = {}
    try:
        result["device"] = "unchanged" if rtc_identity() == identity else "changed"
    except (OSError, ValueError):
        result["device"] = "unavailable"
    try:
        result["alarm"] = "disabled" if (RTC / "wakealarm").read_text().strip() in {"", "0"} else "still_set"
    except (OSError, ValueError):
        result["alarm"] = "unavailable"
    try:
        result["mem_sleep"] = "unchanged" if Path("/sys/power/mem_sleep").read_bytes() == mem_sleep else "changed"
    except (OSError, ValueError):
        result["mem_sleep"] = "unavailable"
    return result


def linux_once(selected):
    program = binary(Path("/usr/sbin/rtcwake"), selected["primitive_sha256"])
    require(os.geteuid() == 0 and "freeze" in Path("/sys/power/state").read_text().split()
            and "[none]" in Path("/sys/power/pm_test").read_text().split(), "power_precondition_refused")
    identity = rtc_identity()
    require((RTC / "wakealarm").read_text().strip() in {"", "0"}
            and (RTC / "device/power/wakeup").read_text().strip() == "enabled", "rtc_precondition_refused")
    require(abs(int((RTC / "since_epoch").read_text().strip()) - time.time_ns() // 1_000_000_000) <= 2, "rtc_utc_unconfirmed")
    mem_sleep = Path("/sys/power/mem_sleep").read_bytes()
    before = linux_sample()
    # Exactly one device/mode/seconds selection; never qualify, retry or fall back.
    reply = None
    try:
        reply = subprocess.run([program, "--device", "/dev/rtc0", "--utc", "--mode", "freeze", "--seconds", "20"],
                               capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass
    finally:
        readback = rtc_readback(identity, mem_sleep)  # Never clear an unknown alarm.
    try:
        after = linux_sample()
    except (OSError, ValueError):
        raise RTCReturnRefused(readback) from None
    if (reply is None or type(reply.returncode) is not int or reply.returncode != 0
            or readback != {"device": "unchanged", "alarm": "disabled", "mem_sleep": "unchanged"}):
        raise RTCReturnRefused(readback)
    slept = (after["boot"] - before["boot"]) - (after["mono"] - before["mono"])
    if not 15_000_000_000 <= slept <= 30_000_000_000:
        raise RTCReturnRefused(readback)
    return {"platform": "linux", "status": "returned_unqualified", "before": before, "after": after}


def windows_once(selected):
    program = binary(ROOT / "windows_s3_once.exe", selected["primitive_sha256"])
    reply = subprocess.run([program, "--execute", "C09-Windows-S3-once-20-v1"],
                           capture_output=True, check=False, timeout=90)
    require(type(reply.returncode) is int and reply.returncode == 0
            and reply.stderr == b"", "windows_return_unconfirmed")
    value = decode(reply.stdout)
    require(set(value) == {"schema", "stage", "return_error", "returned", "timer_signaled",
                          "cleanup_failed", "due_filetime", "before", "after"}
            and value["schema"] == "vardr.nm2-c09-windows-observation/1"
            and value["stage"] == "returned_unqualified" and value["returned"] is True
            and value["timer_signaled"] is True and value["cleanup_failed"] is False
            and type(value["return_error"]) is int and value["return_error"] == 0
            and type(value["due_filetime"]) is int and value["due_filetime"] > 0, "windows_return_unconfirmed")
    for sample in (value["before"], value["after"]):
        require(type(sample) is dict and set(sample) == {"utc_before", "utc_after", "biased", "unbiased"}
                and all(type(n) is int and n > 0 for n in sample.values())
                and 0 <= sample["utc_after"] - sample["utc_before"] <= 500_000, "clock_sample_invalid")
    first, last = value["before"], value["after"]
    biased, unbiased = last["biased"] - first["biased"], last["unbiased"] - first["unbiased"]
    require(0 <= unbiased <= biased and 150_000_000 <= biased - unbiased <= 300_000_000
            and last["utc_before"] >= value["due_filetime"]
            and abs((last["utc_before"] - first["utc_before"]) - biased) <= 10_000_000, "sleep_interval_unconfirmed")
    return {"platform": "win32", "status": "returned_unqualified", "native": value}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--reviewed-selection-sha256")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "prepared_only"}))
        return 2
    try:
        require(args.selection is not None, "selection_invalid")
        selected = selection(args.selection, args.reviewed_selection_sha256)
        before = boot_identity()
        require(before == selected["boot_identity"], "boot_identity_changed")
        result = windows_once(selected) if sys.platform == "win32" else linux_once(selected)
        require(boot_identity() == before, "boot_identity_changed")
        result["boot_identity_sha256"] = hashlib.sha256(before.encode("ascii")).hexdigest()
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except RTCReturnRefused as error:
        print(json.dumps({"status": "held", "reason": "wake_operation_unconfirmed", "rtc_readback": error.readback}))
        return 1
    except (Refused, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "held", "reason": "wake_operation_unconfirmed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
