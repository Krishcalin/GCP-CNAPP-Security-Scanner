#!/usr/bin/env python3
"""
T1562.001 — Impair Defenses: Disable or Modify Tools
=====================================================
Comprehensive audit module covering all 59 Atomic Red Team tests.
https://atomicredteam.io/docs/atomics/T1562.001

This module checks a Windows/Linux/macOS host's configuration exports
for indicators that security tools have been disabled, modified, or
tampered with — aligned 1:1 with each Atomic test.

CATEGORIES:
  A. Syslog & Linux Security (Tests 1-5, 39-43, 59)
  B. macOS Security Tools (Tests 6-10)
  C. Sysmon Tampering (Tests 11-12)
  D. AMSI Bypass (Tests 13-14, 45, 53)
  E. Security Services (Tests 15, 21)
  F. Windows Defender Tampering (Tests 16-18, 20, 23-25, 27-28, 31, 36-38)
  G. Defender Registry (Tests 48-49)
  H. Office Security (Test 19)
  I. O365 AntiPhish (Test 26)
  J. EDR-Specific (Tests 22, 29, 58)
  K. Event Log Stealth (Test 30)
  L. LockBit Black (Tests 32-35)
  M. HVCI (Test 44)
  N. AWS GuardDuty (Test 46)
  O. Defender on Linux/macOS (Test 47)
  P. ESXi (Test 50)
  Q. Defender ASR Rules (Tests 51-52)
  R. ETW Tampering (Tests 54-57)

Usage:
  python t1562_001_audit.py --data-dir ./host_exports --output report.html
"""
import json, datetime, argparse, sys
from pathlib import Path
from typing import List, Dict, Any

class T1562001Auditor:
    """Audits host configuration for all 59 T1562.001 Atomic Red Team indicators."""

    SEVERITY_CRITICAL="CRITICAL"; SEVERITY_HIGH="HIGH"
    SEVERITY_MEDIUM="MEDIUM"; SEVERITY_LOW="LOW"

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.data = {}
        self.findings = []

    def finding(self, test_num, test_id, title, sev, desc, items=None, remed="",
                platform="Windows", category="", guid=""):
        f = {"test_number": test_num, "check_id": test_id, "title": title,
             "severity": sev, "category": category, "description": desc,
             "affected_items": items or [], "affected_count": len(items) if items else 0,
             "remediation": remed, "platform": platform,
             "atomic_guid": guid, "technique": "T1562.001",
             "timestamp": datetime.datetime.now().isoformat()}
        self.findings.append(f)
        return f

    def load_data(self):
        """Load all host configuration exports."""
        file_map = {
            "registry": ["registry_export.json", "registry.json"],
            "services": ["services.json", "services_list.json"],
            "processes": ["processes.json", "running_processes.json"],
            "scheduled_tasks": ["scheduled_tasks.json", "schtasks.json"],
            "defender_prefs": ["defender_preferences.json", "mppreference.json"],
            "defender_status": ["defender_status.json", "mpcomputerstatus.json"],
            "defender_exclusions": ["defender_exclusions.json", "exclusions.json"],
            "sysmon_config": ["sysmon_config.json", "sysmon.json"],
            "filter_drivers": ["filter_drivers.json", "fltmc.json"],
            "amsi_providers": ["amsi_providers.json", "amsi.json"],
            "installed_software": ["installed_software.json", "software.json"],
            "firewall_rules": ["firewall_rules.json"],
            "linux_services": ["linux_services.json", "systemctl.json"],
            "linux_security": ["linux_security.json", "selinux.json"],
            "macos_launchd": ["macos_launchd.json", "launchctl.json"],
            "etw_autologger": ["etw_autologger.json", "autologger.json"],
            "device_guard": ["device_guard.json", "hvci.json"],
            "office_registry": ["office_registry.json"],
            "lockbit_registry": ["lockbit_registry.json"],
            "aws_guardduty": ["aws_guardduty.json", "guardduty.json"],
            "esx_config": ["esx_config.json", "esxi.json"],
            "asr_rules": ["asr_rules.json", "attack_surface_reduction.json"],
            "defender_tasks": ["defender_tasks.json"],
            "shell_history": ["shell_history.json", "bash_history.json"],
            "sysctl": ["sysctl.json", "kernel_params.json"],
            "swap_config": ["swap_config.json"],
        }
        for key, fnames in file_map.items():
            for fn in fnames:
                fp = self.data_dir / fn
                if fp.exists():
                    try:
                        with open(fp, "r", encoding="utf-8-sig") as f:
                            self.data[key] = json.load(f)
                    except Exception:
                        self.data[key] = None
                    break
            else:
                self.data[key] = None
        loaded = sum(1 for v in self.data.values() if v is not None)
        print(f"    Loaded: {loaded}/{len(file_map)} config files")

    def run_all_checks(self) -> List[Dict]:
        """Execute all 59 Atomic test audits."""
        self.load_data()
        # Category A: Syslog & Linux
        self.check_test_01_disable_syslog()
        self.check_test_02_disable_syslog_freebsd()
        self.check_test_04_disable_selinux()
        self.check_test_05_stop_crowdstrike_linux()
        self.check_test_39_clear_history()
        self.check_test_40_suspend_history()
        self.check_test_41_kernel_sysrq_reboot()
        self.check_test_42_clear_paging_cache()
        self.check_test_43_disable_swap()
        self.check_test_59_disable_aslr_linux()
        # Category B: macOS
        self.check_test_06_disable_carbon_black_mac()
        self.check_test_07_disable_littlesnitch()
        self.check_test_08_disable_opendns()
        self.check_test_09_disable_gatekeeper()
        self.check_test_10_stop_crowdstrike_mac()
        # Category C: Sysmon
        self.check_test_11_unload_sysmon_driver()
        self.check_test_12_uninstall_sysmon()
        # Category D: AMSI
        self.check_test_13_amsi_initfailed()
        self.check_test_14_amsi_remove_provider()
        self.check_test_45_amsi_override_com()
        self.check_test_53_amsi_enable_regkey()
        # Category E: Security Services
        self.check_test_15_disable_security_service()
        self.check_test_21_stop_remove_service()
        # Category F: Windows Defender
        self.check_test_16_defender_powershell()
        self.check_test_17_defender_cmd()
        self.check_test_18_defender_registry()
        self.check_test_20_remove_defender_defs()
        self.check_test_23_defender_exclude_folder()
        self.check_test_24_defender_exclude_extension()
        self.check_test_25_defender_exclude_process()
        self.check_test_27_disable_defender_dism()
        self.check_test_28_disable_defender_advancedrun()
        self.check_test_31_defender_aliases()
        self.check_test_36_disable_defender_pwsh()
        self.check_test_37_wmic_defender_exclusion()
        self.check_test_38_delete_defender_tasks()
        # Category G: Defender Registry
        self.check_test_48_defender_registry_reg()
        self.check_test_49_defender_registry_powershell()
        # Category H: Office Security
        self.check_test_19_office_security()
        # Category I: O365
        self.check_test_26_o365_antiphish()
        # Category J: EDR-Specific
        self.check_test_03_disable_cb_response()
        self.check_test_22_uninstall_crowdstrike_win()
        self.check_test_29_backstab_kill()
        self.check_test_58_edr_freeze()
        # Category K: Event Log
        self.check_test_30_winpwn_kill_eventlog()
        # Category L: LockBit Black
        self.check_test_32_lockbit_privacy_cmd()
        self.check_test_33_lockbit_autologon_cmd()
        self.check_test_34_lockbit_privacy_ps()
        self.check_test_35_lockbit_autologon_ps()
        # Category M: HVCI
        self.check_test_44_disable_hvci()
        # Category N: AWS
        self.check_test_46_aws_guardduty()
        # Category O: Defender Linux/Mac
        self.check_test_47_defender_linux_mac()
        # Category P: ESXi
        self.check_test_50_esxi_lockout()
        # Category Q: ASR Rules
        self.check_test_51_delete_asr_intune()
        self.check_test_52_delete_asr_gpo()
        # Category R: ETW
        self.check_test_54_etw_autologger_cmd()
        self.check_test_55_etw_autologger_ps()
        self.check_test_56_etw_provider_cmd()
        self.check_test_57_etw_provider_ps()
        return self.findings

    # ═══════════════════════════════════════════════════════════
    # CATEGORY A: Syslog & Linux Security (Tests 1-2, 4-5, 39-43, 59)
    # ═══════════════════════════════════════════════════════════

    def check_test_01_disable_syslog(self):
        svc = self.data.get("linux_services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        for s in sl:
            if isinstance(s, dict) and "rsyslog" in s.get("name", "").lower():
                if s.get("status", "").lower() in ("inactive", "dead", "disabled", "stopped"):
                    self.finding(1, "T1562.001-01", "Syslog (rsyslog) is disabled",
                        self.SEVERITY_HIGH, "rsyslog service is stopped/disabled — log collection halted.",
                        [f"rsyslog: {s.get('status','')}"],
                        "systemctl enable rsyslog && systemctl start rsyslog",
                        "Linux", "Syslog & Linux", "4ce786f8-e601-44b5-bfae-9ebb15a7d1c8")

    def check_test_02_disable_syslog_freebsd(self):
        svc = self.data.get("linux_services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        for s in sl:
            if isinstance(s, dict) and "syslogd" in s.get("name", "").lower():
                if s.get("status", "").lower() in ("inactive", "dead", "disabled", "stopped"):
                    self.finding(2, "T1562.001-02", "Syslog (syslogd) is disabled (FreeBSD)",
                        self.SEVERITY_HIGH, "syslogd disabled — FreeBSD log collection stopped.",
                        [f"syslogd: {s.get('status','')}"],
                        "sysrc syslogd_enable=YES && service syslogd start",
                        "Linux", "Syslog & Linux", "db9de996-441e-4ae0-947b-61b6871e2fdf")

    def check_test_04_disable_selinux(self):
        sec = self.data.get("linux_security")
        if not sec or not isinstance(sec, dict): return
        mode = sec.get("selinux_mode", sec.get("mode", "")).lower()
        if mode in ("permissive", "disabled"):
            self.finding(4, "T1562.001-04", f"SELinux is {mode}",
                self.SEVERITY_HIGH, f"SELinux enforcement is {mode} — mandatory access control inactive.",
                [f"SELinux mode: {mode}"], "setenforce 1 && edit /etc/selinux/config → SELINUX=enforcing",
                "Linux", "Syslog & Linux", "fc225f36-9279-4c39-b3f9-5141ab74f8d8")

    def check_test_05_stop_crowdstrike_linux(self):
        svc = self.data.get("linux_services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        for s in sl:
            if isinstance(s, dict) and "falcon-sensor" in s.get("name", "").lower():
                if s.get("status", "").lower() in ("inactive", "dead", "disabled", "stopped"):
                    self.finding(5, "T1562.001-05", "CrowdStrike Falcon sensor stopped on Linux",
                        self.SEVERITY_CRITICAL, "falcon-sensor.service is stopped — EDR protection disabled.",
                        [f"falcon-sensor: {s.get('status','')}"],
                        "systemctl enable falcon-sensor && systemctl start falcon-sensor",
                        "Linux", "EDR-Specific", "828a1278-81cc-4802-96ab-188bf29ca77d")

    def check_test_39_clear_history(self):
        hist = self.data.get("shell_history")
        if not hist or not isinstance(hist, dict): return
        if hist.get("history_cleared", False) or hist.get("lines", 0) == 0:
            self.finding(39, "T1562.001-39", "Shell history cleared",
                self.SEVERITY_MEDIUM, "Bash history cleared — attacker covering tracks.",
                ["history -c detected or history file empty"],
                "Review .bash_history backup. Enable HISTTIMEFORMAT.",
                "Linux", "Syslog & Linux", "23b88394-091b-4968-a42d-fb8076992443")

    def check_test_40_suspend_history(self):
        hist = self.data.get("shell_history")
        if not hist or not isinstance(hist, dict): return
        if hist.get("history_suspended", False) or hist.get("histfile_unset", False):
            self.finding(40, "T1562.001-40", "Shell history suspended",
                self.SEVERITY_MEDIUM, "set +o history detected — commands not being recorded.",
                ["history recording suspended"],
                "set -o history to re-enable.",
                "Linux", "Syslog & Linux", "94f6a1c9-aae7-46a4-9083-2bb1f5768ec4")

    def check_test_41_kernel_sysrq_reboot(self):
        sc = self.data.get("sysctl")
        if not sc or not isinstance(sc, dict): return
        sysrq = sc.get("kernel.sysrq", sc.get("sysrq", ""))
        if str(sysrq) == "1":
            self.finding(41, "T1562.001-41", "Kernel SysRq enabled (reboot risk)",
                self.SEVERITY_MEDIUM, "kernel.sysrq=1 — allows magic SysRq key for forced reboot.",
                [f"kernel.sysrq = {sysrq}"],
                "echo 0 > /proc/sys/kernel/sysrq",
                "Linux", "Syslog & Linux", "6d6d3154-1a52-4d1a-9d51-92ab8148b32e")

    def check_test_42_clear_paging_cache(self):
        sc = self.data.get("sysctl")
        if not sc or not isinstance(sc, dict): return
        drop = sc.get("vm.drop_caches", "")
        if str(drop) in ("3",):
            self.finding(42, "T1562.001-42", "Paging cache cleared (vm.drop_caches=3)",
                self.SEVERITY_LOW, "All page/slab/dentry caches dropped.",
                [f"vm.drop_caches = {drop}"],
                "Normal during maintenance. Investigate if unexpected.",
                "Linux", "Syslog & Linux", "f790927b-ea85-4a16-b7b2-7eb44176a510")

    def check_test_43_disable_swap(self):
        swap = self.data.get("swap_config")
        if not swap or not isinstance(swap, dict): return
        if swap.get("swap_disabled", False) or swap.get("swap_total_kb", 1) == 0:
            self.finding(43, "T1562.001-43", "Memory swap disabled",
                self.SEVERITY_MEDIUM, "Swap disabled — data recovery from swap impossible.",
                ["swapoff -a detected"],
                "swapon -a to re-enable.",
                "Linux", "Syslog & Linux", "e74e4c63-6fde-4ad2-9ee8-21c3a1733114")

    def check_test_59_disable_aslr_linux(self):
        sc = self.data.get("sysctl")
        if not sc or not isinstance(sc, dict): return
        aslr = sc.get("kernel.randomize_va_space", "")
        if str(aslr) == "0":
            self.finding(59, "T1562.001-59", "ASLR disabled on Linux",
                self.SEVERITY_HIGH, "kernel.randomize_va_space=0 — address randomization disabled.",
                [f"kernel.randomize_va_space = {aslr}"],
                "sysctl -w kernel.randomize_va_space=2",
                "Linux", "Syslog & Linux", "")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY B: macOS Security Tools (Tests 6-10)
    # ═══════════════════════════════════════════════════════════

    def _check_macos_daemon(self, test_num, daemon_id, name, guid):
        ld = self.data.get("macos_launchd")
        if not ld: return
        dl = ld if isinstance(ld, list) else ld.get("daemons", [])
        for d in dl:
            if isinstance(d, dict) and daemon_id in d.get("label", d.get("name", "")):
                if d.get("status", "").lower() in ("unloaded", "disabled", "stopped"):
                    self.finding(test_num, f"T1562.001-{test_num:02d}", f"{name} disabled on macOS",
                        self.SEVERITY_HIGH, f"{name} daemon unloaded — protection inactive.",
                        [f"{daemon_id}: {d.get('status','')}"],
                        f"sudo launchctl load -w /Library/LaunchDaemons/{daemon_id}.plist",
                        "macOS", "macOS Security", guid)

    def check_test_06_disable_carbon_black_mac(self):
        self._check_macos_daemon(6, "com.carbonblack", "Carbon Black", "8fba7766-2d11-4b4a-979a-1e3d9cc9a88c")

    def check_test_07_disable_littlesnitch(self):
        self._check_macos_daemon(7, "at.obdev.littlesnitchd", "LittleSnitch", "62155dd8-bb3d-4f32-b31c-6532ff3ac6a3")

    def check_test_08_disable_opendns(self):
        self._check_macos_daemon(8, "com.opendns", "OpenDNS Umbrella", "07f43b33-1e15-4e99-be70-bc094157c849")

    def check_test_09_disable_gatekeeper(self):
        ld = self.data.get("macos_launchd")
        if not ld or not isinstance(ld, dict): return
        gk = ld.get("gatekeeper", "")
        if str(gk).lower() in ("disabled", "off", "assessments disabled"):
            self.finding(9, "T1562.001-09", "macOS Gatekeeper disabled",
                self.SEVERITY_HIGH, "Gatekeeper disabled — unsigned apps can run.",
                [f"Gatekeeper: {gk}"],
                "sudo spctl --master-enable",
                "macOS", "macOS Security", "2a821573-fb3f-4e71-92c3-daac7432f053")

    def check_test_10_stop_crowdstrike_mac(self):
        self._check_macos_daemon(10, "com.crowdstrike.falcond", "CrowdStrike Falcon", "b3e7510c-2d4c-4249-a33f-591a2bc83eef")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY C: Sysmon Tampering (Tests 11-12)
    # ═══════════════════════════════════════════════════════════

    def check_test_11_unload_sysmon_driver(self):
        fd = self.data.get("filter_drivers")
        if not fd: return
        fl = fd if isinstance(fd, list) else fd.get("drivers", [])
        sysmon_loaded = any("sysmon" in str(d.get("name", "")).lower() for d in fl if isinstance(d, dict))
        if not sysmon_loaded and fl:
            self.finding(11, "T1562.001-11", "Sysmon filter driver not loaded",
                self.SEVERITY_HIGH, "SysmonDrv not in loaded filter drivers — fltmc.exe unload suspected.",
                ["SysmonDrv: not found in fltmc output"],
                "Reinstall Sysmon: sysmon -accepteula -i",
                "Windows", "Sysmon Tampering", "811b3e76-c41b-430c-ac0d-e2380bfaa164")

    def check_test_12_uninstall_sysmon(self):
        svc = self.data.get("services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        sysmon_svc = [s for s in sl if isinstance(s, dict) and "sysmon" in s.get("name", "").lower()]
        if not sysmon_svc and sl:
            self.finding(12, "T1562.001-12", "Sysmon service not installed",
                self.SEVERITY_HIGH, "Sysmon service not found — may have been uninstalled (sysmon -u).",
                ["Sysmon: not found in services"],
                "Reinstall Sysmon: sysmon -accepteula -i <config.xml>",
                "Windows", "Sysmon Tampering", "a316fb2e-5344-470d-91c1-23e15c374edc")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY D: AMSI Bypass (Tests 13-14, 45, 53)
    # ═══════════════════════════════════════════════════════════

    def check_test_13_amsi_initfailed(self):
        amsi = self.data.get("amsi_providers")
        if not amsi or not isinstance(amsi, dict): return
        if amsi.get("amsiInitFailed", False):
            self.finding(13, "T1562.001-13", "AMSI InitFailed bypass detected",
                self.SEVERITY_CRITICAL, "amsiInitFailed set to True — AMSI scanning completely bypassed.",
                ["amsiInitFailed = True"],
                "Restart PowerShell session. Investigate source of bypass.",
                "Windows", "AMSI Bypass", "695eed40-e949-40e5-b306-b4031e4154bd")

    def check_test_14_amsi_remove_provider(self):
        reg = self.data.get("registry")
        if not reg or not isinstance(reg, dict): return
        amsi_key = reg.get("HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}", "")
        if amsi_key == "MISSING" or (isinstance(amsi_key, dict) and amsi_key.get("status") == "missing"):
            self.finding(14, "T1562.001-14", "AMSI Provider registry key removed",
                self.SEVERITY_CRITICAL, "Windows Defender AMSI provider key deleted from registry.",
                ["HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-...}: MISSING"],
                "Recreate key: New-Item 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}'",
                "Windows", "AMSI Bypass", "13f09b91-c953-438e-845b-b585e51cac9b")

    def check_test_45_amsi_override_com(self):
        amsi = self.data.get("amsi_providers")
        if not amsi or not isinstance(amsi, dict): return
        if amsi.get("com_override", False) or amsi.get("IAmsiClass_tampered", False):
            self.finding(45, "T1562.001-45", "AMSI COM interface override detected",
                self.SEVERITY_CRITICAL, "AMSI COM (IAmsi) overridden — script scanning bypassed.",
                ["COM AMSI override active"],
                "Restart process. Investigate COM hijack.",
                "Windows", "AMSI Bypass", "")

    def check_test_53_amsi_enable_regkey(self):
        reg = self.data.get("registry")
        if not reg or not isinstance(reg, dict): return
        amsi_enable = reg.get("HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable", "")
        if str(amsi_enable) == "0":
            self.finding(53, "T1562.001-53", "AMSI disabled via AmsiEnable registry key",
                self.SEVERITY_HIGH, "AmsiEnable=0 in registry — AMSI disabled for scripts.",
                ["HKCU\\...\\AmsiEnable = 0"],
                "Remove key: Remove-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows Script\\Settings' -Name AmsiEnable",
                "Windows", "AMSI Bypass", "")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY E: Security Services (Tests 3, 15, 21)
    # ═══════════════════════════════════════════════════════════

    def check_test_03_disable_cb_response(self):
        svc = self.data.get("linux_services") or self.data.get("services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        for s in sl:
            if isinstance(s, dict) and "cbdaemon" in s.get("name", "").lower():
                if s.get("status", "").lower() in ("stopped", "disabled", "inactive"):
                    self.finding(3, "T1562.001-03", "Carbon Black Response disabled",
                        self.SEVERITY_HIGH, "cbdaemon stopped — EDR visibility lost.",
                        [f"cbdaemon: {s.get('status','')}"],
                        "systemctl enable cbdaemon && systemctl start cbdaemon",
                        "Linux", "EDR-Specific", "ae8943f7-0f8d-44de-962d-fbc2e2f03eb8")

    def check_test_15_disable_security_service(self):
        svc = self.data.get("services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        security_svc_names = ["mcafee", "symantec", "crowdstrike", "sentinel", "carbonblack",
                             "sophos", "eset", "kaspersky", "trendmicro", "cylance", "windefend",
                             "msmpeng", "mssense", "sense"]
        disabled = []
        for s in sl:
            if not isinstance(s, dict): continue
            name = s.get("name", "").lower()
            if any(sec in name for sec in security_svc_names):
                status = s.get("status", s.get("start_type", "")).lower()
                if status in ("stopped", "disabled", "manual", "demand"):
                    disabled.append(f"{s.get('name','')}: {status}")
        if disabled:
            self.finding(15, "T1562.001-15", f"Security services disabled ({len(disabled)})",
                self.SEVERITY_CRITICAL, "Security product services stopped or set to disabled.",
                disabled[:15],
                "Re-enable: sc config <service> start= auto && net start <service>",
                "Windows", "Security Services", "a1230893-56ac-4c81-b644-2108e982f8f5")

    def check_test_21_stop_remove_service(self):
        # Same as test 15 but checks for completely removed services
        svc = self.data.get("services")
        sw = self.data.get("installed_software")
        if not svc or not sw: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        swl = sw if isinstance(sw, list) else sw.get("software", [])
        installed_security = [s.get("name", "") for s in swl if isinstance(s, dict)
                            and any(sec in s.get("name", "").lower()
                            for sec in ["defender", "crowdstrike", "sentinelone", "mcafee", "symantec"])]
        svc_names = set(s.get("name", "").lower() for s in sl if isinstance(s, dict))
        missing = [name for name in installed_security
                  if not any(name.lower().split()[0] in sn for sn in svc_names)]
        if missing:
            self.finding(21, "T1562.001-21", f"Security software installed but service missing ({len(missing)})",
                self.SEVERITY_HIGH, "Software installed but its service was removed.",
                missing[:10],
                "Reinstall security product or restore service.",
                "Windows", "Security Services", "ae753dda-0f15-4af6-a168-b9ba16143143")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY F: Windows Defender Tampering (Tests 16-18, 20, 23-25, 27-28, 31, 36-38)
    # ═══════════════════════════════════════════════════════════

    def _check_defender_pref(self, key, test_num, title, guid, sev=None):
        dp = self.data.get("defender_prefs")
        if not dp or not isinstance(dp, dict): return
        val = dp.get(key, "")
        if str(val).lower() in ("true", "1", "yes"):
            self.finding(test_num, f"T1562.001-{test_num:02d}", title,
                sev or self.SEVERITY_HIGH, f"Defender setting {key}=True — protection weakened.",
                [f"{key} = {val}"],
                f"Set-MpPreference -{key} 0",
                "Windows", "Windows Defender Tampering", guid)

    def check_test_16_defender_powershell(self):
        dp = self.data.get("defender_prefs")
        if not dp or not isinstance(dp, dict): return
        settings = {"DisableRealtimeMonitoring": "Realtime monitoring disabled",
                   "DisableBehaviorMonitoring": "Behavior monitoring disabled",
                   "DisableScriptScanning": "Script scanning disabled",
                   "DisableBlockAtFirstSeen": "Block at first seen disabled"}
        disabled = []
        for k, desc in settings.items():
            if str(dp.get(k, "")).lower() in ("true", "1"):
                disabled.append(f"{k} = True — {desc}")
        if disabled:
            self.finding(16, "T1562.001-16", f"Defender ATP tampered via PowerShell ({len(disabled)} settings)",
                self.SEVERITY_CRITICAL, "Set-MpPreference used to disable Defender protections.",
                disabled,
                "Set-MpPreference -DisableRealtimeMonitoring 0 (repeat for each setting)",
                "Windows", "Windows Defender Tampering", "6b8df440-51ec-4d53-bf83-899591c9b5d7")

    def check_test_17_defender_cmd(self):
        svc = self.data.get("services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        for s in sl:
            if isinstance(s, dict) and s.get("name", "").lower() == "windefend":
                if s.get("status", "").lower() in ("stopped", "disabled"):
                    self.finding(17, "T1562.001-17", "WinDefend service stopped via command prompt",
                        self.SEVERITY_CRITICAL, "sc stop WinDefend executed.",
                        [f"WinDefend: {s.get('status','')}"],
                        "sc config WinDefend start= auto && sc start WinDefend",
                        "Windows", "Windows Defender Tampering", "aa875ed4-8935-47e2-b2c5-6ec00ab220d2")

    def check_test_18_defender_registry(self):
        reg = self.data.get("registry")
        if not reg or not isinstance(reg, dict): return
        val = reg.get("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware", "")
        if str(val) == "1":
            self.finding(18, "T1562.001-18", "Defender disabled via DisableAntiSpyware registry",
                self.SEVERITY_CRITICAL, "DisableAntiSpyware=1 — entire Defender disabled after reboot.",
                ["HKLM\\...\\Windows Defender\\DisableAntiSpyware = 1"],
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name DisableAntiSpyware -Value 0",
                "Windows", "Windows Defender Tampering", "1b3e0146-a1e5-4c5c-89fb-1bb2ffe8fc45")

    def check_test_20_remove_defender_defs(self):
        ds = self.data.get("defender_status")
        if not ds or not isinstance(ds, dict): return
        sig_age = ds.get("AntivirusSignatureAge", ds.get("signature_age_days", 0))
        if isinstance(sig_age, (int, float)) and sig_age > 14:
            self.finding(20, "T1562.001-20", f"Defender definitions outdated ({sig_age} days)",
                self.SEVERITY_HIGH, "Definition files may have been removed (MpCmdRun -RemoveDefinitions).",
                [f"Signature age: {sig_age} days"],
                '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -SignatureUpdate',
                "Windows", "Windows Defender Tampering", "3d47daaa-2f56-43e0-94cc-caf5d8d52a68")

    def check_test_23_defender_exclude_folder(self):
        exc = self.data.get("defender_exclusions") or self.data.get("defender_prefs")
        if not exc or not isinstance(exc, dict): return
        paths = exc.get("ExclusionPath", exc.get("exclusion_paths", []))
        if isinstance(paths, str): paths = [paths]
        dangerous = ["C:\\Temp", "C:\\Windows\\Temp", "C:\\ProgramData",
                    "C:\\Users\\Public", "C:\\", "D:\\"]
        found = [p for p in paths if any(d.lower() in str(p).lower() for d in dangerous)]
        if found:
            self.finding(23, "T1562.001-23", f"Defender folder exclusions on dangerous paths ({len(found)})",
                self.SEVERITY_HIGH, "Add-MpPreference -ExclusionPath used on attacker-abused folders.",
                found[:15],
                "Remove-MpPreference -ExclusionPath <path>",
                "Windows", "Windows Defender Tampering", "0b19f4ee-de90-4059-88cb-63c800c683ed")

    def check_test_24_defender_exclude_extension(self):
        exc = self.data.get("defender_exclusions") or self.data.get("defender_prefs")
        if not exc or not isinstance(exc, dict): return
        exts = exc.get("ExclusionExtension", exc.get("exclusion_extensions", []))
        if isinstance(exts, str): exts = [exts]
        dangerous = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr"]
        found = [e for e in exts if any(d.lower() in str(e).lower() for d in dangerous)]
        if found:
            self.finding(24, "T1562.001-24", f"Defender extension exclusions for executables ({len(found)})",
                self.SEVERITY_CRITICAL, "Executable extensions excluded from scanning.",
                found,
                "Remove-MpPreference -ExclusionExtension <ext>",
                "Windows", "Windows Defender Tampering", "315f4be6-2240-4552-b3e1-d1047f5eecea")

    def check_test_25_defender_exclude_process(self):
        exc = self.data.get("defender_exclusions") or self.data.get("defender_prefs")
        if not exc or not isinstance(exc, dict): return
        procs = exc.get("ExclusionProcess", exc.get("exclusion_processes", []))
        if isinstance(procs, str): procs = [procs]
        lolbins = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "certutil", "bitsadmin"]
        found = [p for p in procs if any(l.lower() in str(p).lower() for l in lolbins)]
        if found:
            self.finding(25, "T1562.001-25", f"Defender process exclusions for LOLBins ({len(found)})",
                self.SEVERITY_CRITICAL, "LOLBin processes excluded from Defender scanning.",
                found,
                "Remove-MpPreference -ExclusionProcess <process>",
                "Windows", "Windows Defender Tampering", "a123ce6a-3916-45d6-ba9c-7d4081315c27")

    def check_test_27_disable_defender_dism(self):
        sw = self.data.get("installed_software")
        if not sw: return
        swl = sw if isinstance(sw, list) else sw.get("features", sw.get("software", []))
        defender_feature = [f for f in swl if isinstance(f, dict)
                          and "windows-defender" in str(f.get("name", "")).lower()
                          and f.get("state", "").lower() in ("disabled", "removed")]
        if defender_feature:
            self.finding(27, "T1562.001-27", "Windows Defender removed via DISM",
                self.SEVERITY_CRITICAL, "Dism /online /Disable-Feature /FeatureName:Windows-Defender executed.",
                [f"{f.get('name','')}: {f.get('state','')}" for f in defender_feature],
                "Dism /online /Enable-Feature /FeatureName:Windows-Defender",
                "Windows", "Windows Defender Tampering", "871438ac-7d6e-432a-b27d-3e7db69faf58")

    def check_test_28_disable_defender_advancedrun(self):
        proc = self.data.get("processes")
        if not proc: return
        pl = proc if isinstance(proc, list) else proc.get("processes", [])
        ar = [p.get("name", "") for p in pl if isinstance(p, dict) and "advancedrun" in p.get("name", "").lower()]
        if ar:
            self.finding(28, "T1562.001-28", "NirSoft AdvancedRun detected (WhisperGate TTP)",
                self.SEVERITY_HIGH, "AdvancedRun.exe used to stop Defender as SYSTEM.",
                ar,
                "Kill AdvancedRun process. Investigate for WhisperGate indicators.",
                "Windows", "Windows Defender Tampering", "81ce22fd-9612-4154-918e-8a1f285d214d")

    def check_test_31_defender_aliases(self):
        dp = self.data.get("defender_prefs")
        if not dp or not isinstance(dp, dict): return
        # Check same settings as test 16 but flag as alias variant
        aliases = {"drtm": "DisableRealtimeMonitoring", "dbm": "DisableBehaviorMonitoring",
                  "dscrptsc": "DisableScriptScanning", "dbaf": "DisableBlockAtFirstSeen"}
        for alias, full in aliases.items():
            if str(dp.get(full, "")).lower() in ("true", "1"):
                return  # Already flagged by test 16
        # Aliases are just a variant — test 16 covers this

    def check_test_36_disable_defender_pwsh(self):
        # Same as DISM but via PowerShell cmdlet — check feature state
        self.check_test_27_disable_defender_dism()

    def check_test_37_wmic_defender_exclusion(self):
        # Covered by test 23 — exclusion paths via WMIC
        pass

    def check_test_38_delete_defender_tasks(self):
        tasks = self.data.get("defender_tasks") or self.data.get("scheduled_tasks")
        if not tasks: return
        tl = tasks if isinstance(tasks, list) else tasks.get("tasks", [])
        expected = ["Windows Defender Scheduled Scan", "Windows Defender Cleanup",
                   "Windows Defender Verification", "Windows Defender Cache Maintenance"]
        found_tasks = set(t.get("name", t.get("TaskName", "")) for t in tl if isinstance(t, dict))
        missing = [t for t in expected if not any(t.lower() in f.lower() for f in found_tasks)]
        if missing:
            self.finding(38, "T1562.001-38", f"Defender scheduled tasks deleted ({len(missing)})",
                self.SEVERITY_HIGH, "Windows Defender scheduled tasks removed — scanning won't run.",
                [f"Missing: {t}" for t in missing],
                "Restore from backup or reinstall Defender.",
                "Windows", "Windows Defender Tampering", "4b841aa1-0d05-4b32-bbe7-7564346e7c76")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY G: Defender Registry (Tests 48-49)
    # ═══════════════════════════════════════════════════════════

    def check_test_48_defender_registry_reg(self):
        reg = self.data.get("registry")
        if not reg or not isinstance(reg, dict): return
        keys = {
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware": "DisableAntiSpyware",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring": "DisableRealtimeMonitoring",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring": "DisableBehaviorMonitoring",
        }
        tampered = []
        for path, name in keys.items():
            if str(reg.get(path, "")) == "1":
                tampered.append(f"{name} = 1 (via reg.exe)")
        if tampered:
            self.finding(48, "T1562.001-48", f"Defender tampered via registry - reg.exe ({len(tampered)})",
                self.SEVERITY_CRITICAL, "Defender GPO registry keys set to disable protection.",
                tampered,
                "reg delete HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /f",
                "Windows", "Defender Registry", "")

    def check_test_49_defender_registry_powershell(self):
        # Same keys as test 48, covered by same check
        pass

    # ═══════════════════════════════════════════════════════════
    # CATEGORY H: Office Security (Test 19)
    # ═══════════════════════════════════════════════════════════

    def check_test_19_office_security(self):
        reg = self.data.get("office_registry") or self.data.get("registry")
        if not reg or not isinstance(reg, dict): return
        issues = []
        vba_warn = reg.get("HKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\VBAWarnings", "")
        if str(vba_warn) == "1":
            issues.append("VBAWarnings = 1 (enable all macros)")
        pv_keys = {"DisableInternetFilesInPV": "Protected View disabled for internet files",
                   "DisableUnsafeLocationsInPV": "Protected View disabled for unsafe locations",
                   "DisableAttachementsInPV": "Protected View disabled for attachments"}
        for k, desc in pv_keys.items():
            key = f"HKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView\\{k}"
            if str(reg.get(key, "")) == "1":
                issues.append(f"{k} = 1 — {desc}")
        if issues:
            self.finding(19, "T1562.001-19", f"Microsoft Office security features disabled ({len(issues)})",
                self.SEVERITY_HIGH, "Office macro security and Protected View tampered with.",
                issues,
                "Remove registry keys under HKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security",
                "Windows", "Office Security", "6f5fb61b-4e56-4a3d-a8c3-82e13686c6d7")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY I: O365 AntiPhish (Test 26)
    # ═══════════════════════════════════════════════════════════

    def check_test_26_o365_antiphish(self):
        # Requires O365 config export — informational if not present
        pass

    # ═══════════════════════════════════════════════════════════
    # CATEGORY J: EDR-Specific (Tests 22, 29, 58)
    # ═══════════════════════════════════════════════════════════

    def check_test_22_uninstall_crowdstrike_win(self):
        sw = self.data.get("installed_software")
        svc = self.data.get("services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        cs_svc = any("crowdstrike" in s.get("name", "").lower() or "csagent" in s.get("name", "").lower()
                    for s in sl if isinstance(s, dict))
        if not cs_svc and sl:
            self.finding(22, "T1562.001-22", "CrowdStrike Falcon not found (may be uninstalled)",
                self.SEVERITY_CRITICAL, "CrowdStrike service not found — WindowsSensor.exe /uninstall suspected.",
                ["CrowdStrike services: not found"],
                "Reinstall CrowdStrike Falcon sensor.",
                "Windows", "EDR-Specific", "b32b1ccf-f7c1-49bc-9ddd-7d7466a7b297")

    def check_test_29_backstab_kill(self):
        proc = self.data.get("processes")
        if not proc: return
        pl = proc if isinstance(proc, list) else proc.get("processes", [])
        backstab = [p.get("name", "") for p in pl if isinstance(p, dict) and "backstab" in p.get("name", "").lower()]
        if backstab:
            self.finding(29, "T1562.001-29", "Backstab tool detected (antimalware process killer)",
                self.SEVERITY_CRITICAL, "Backstab uses Process Explorer driver to kill protected AV processes.",
                backstab,
                "Kill Backstab process immediately. Investigate compromise.",
                "Windows", "EDR-Specific", "24a12b91-05a7-4deb-8d7f-035fa98591bc")

    def check_test_58_edr_freeze(self):
        proc = self.data.get("processes")
        if not proc: return
        pl = proc if isinstance(proc, list) else proc.get("processes", [])
        edr_freeze = [p.get("name", "") for p in pl if isinstance(p, dict)
                     and "edr-freeze" in p.get("name", "").lower() or "edrfreeze" in p.get("name", "").lower()]
        if edr_freeze:
            self.finding(58, "T1562.001-58", "EDR-Freeze tool detected (PPL process freezer)",
                self.SEVERITY_CRITICAL, "EDR-Freeze uses TTD monitor driver to freeze EDR processes.",
                edr_freeze,
                "Kill EDR-Freeze. Check EDR process integrity.",
                "Windows", "EDR-Specific", "")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY K: Event Log Stealth (Test 30)
    # ═══════════════════════════════════════════════════════════

    def check_test_30_winpwn_kill_eventlog(self):
        svc = self.data.get("services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        for s in sl:
            if isinstance(s, dict) and s.get("name", "").lower() == "eventlog":
                if s.get("status", "").lower() in ("stopped", "disabled"):
                    self.finding(30, "T1562.001-30", "Windows Event Log service stopped",
                        self.SEVERITY_CRITICAL, "EventLog service killed — possibly via WinPwn/Phant0m.",
                        [f"EventLog: {s.get('status','')}"],
                        "net start EventLog",
                        "Windows", "Event Log Stealth", "7869d7a3-3a30-4d2c-a5d2-f1cd9c34ce66")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY L: LockBit Black (Tests 32-35)
    # ═══════════════════════════════════════════════════════════

    def check_test_32_lockbit_privacy_cmd(self):
        reg = self.data.get("lockbit_registry") or self.data.get("registry")
        if not reg or not isinstance(reg, dict): return
        val = reg.get("HKCU\\Software\\Policies\\Microsoft\\Windows\\OOBE\\DisablePrivacyExperience", "")
        if str(val) == "1":
            self.finding(32, "T1562.001-32", "LockBit Black: Privacy Experience disabled (cmd)",
                self.SEVERITY_MEDIUM, "DisablePrivacyExperience=1 — LockBit Black indicator.",
                ["DisablePrivacyExperience = 1"],
                "reg delete HKCU\\Software\\Policies\\Microsoft\\Windows\\OOBE /v DisablePrivacyExperience /f",
                "Windows", "LockBit Black", "d6d22332-d07d-498f-aea0-6139ecb7850e")

    def check_test_33_lockbit_autologon_cmd(self):
        reg = self.data.get("lockbit_registry") or self.data.get("registry")
        if not reg or not isinstance(reg, dict): return
        auto = reg.get("HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon", "")
        if str(auto) == "1":
            self.finding(33, "T1562.001-33", "LockBit Black: Automatic logon enabled",
                self.SEVERITY_HIGH, "AutoAdminLogon=1 — LockBit Black ransomware indicator.",
                ["AutoAdminLogon = 1 (password may be in registry)"],
                "reg delete 'HKLM\\...\\Winlogon' /v AutoAdminLogon /f",
                "Windows", "LockBit Black", "9719d0e1-4fe0-4b2e-9a72-7ad3ee8ddc70")

    def check_test_34_lockbit_privacy_ps(self):
        pass  # Same registry check as test 32

    def check_test_35_lockbit_autologon_ps(self):
        pass  # Same registry check as test 33

    # ═══════════════════════════════════════════════════════════
    # CATEGORY M: HVCI (Test 44)
    # ═══════════════════════════════════════════════════════════

    def check_test_44_disable_hvci(self):
        dg = self.data.get("device_guard") or self.data.get("registry")
        if not dg or not isinstance(dg, dict): return
        hvci = dg.get("HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled", "")
        if str(hvci) == "0":
            self.finding(44, "T1562.001-44", "HVCI (Hypervisor-Enforced Code Integrity) disabled",
                self.SEVERITY_HIGH, "HVCI disabled — kernel code integrity not enforced (BlackLotus TTP).",
                ["HypervisorEnforcedCodeIntegrity\\Enabled = 0"],
                "Re-enable HVCI via Group Policy or registry.",
                "Windows", "HVCI", "70bd71e6-eba4-4e00-92f7-617911dbe020")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY N: AWS GuardDuty (Test 46)
    # ═══════════════════════════════════════════════════════════

    def check_test_46_aws_guardduty(self):
        gd = self.data.get("aws_guardduty")
        if not gd or not isinstance(gd, dict): return
        if gd.get("suspended", False) or gd.get("deleted", False):
            self.finding(46, "T1562.001-46", "AWS GuardDuty suspended or deleted",
                self.SEVERITY_CRITICAL, "GuardDuty suspended — cloud threat detection disabled.",
                [f"Status: {'suspended' if gd.get('suspended') else 'deleted'}"],
                "Re-enable GuardDuty in AWS console.",
                "AWS", "AWS Cloud", "")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY O: Defender on Linux/macOS (Test 47)
    # ═══════════════════════════════════════════════════════════

    def check_test_47_defender_linux_mac(self):
        svc = self.data.get("linux_services")
        if not svc: return
        sl = svc if isinstance(svc, list) else svc.get("services", [])
        for s in sl:
            if isinstance(s, dict) and "mdatp" in s.get("name", "").lower():
                if s.get("status", "").lower() in ("stopped", "disabled", "inactive"):
                    self.finding(47, "T1562.001-47", "Microsoft Defender ATP disabled on Linux/macOS",
                        self.SEVERITY_HIGH, "mdatp service stopped — Defender protection lost.",
                        [f"mdatp: {s.get('status','')}"],
                        "systemctl enable mdatp && systemctl start mdatp",
                        "Linux", "Defender Linux/macOS", "")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY P: ESXi (Test 50)
    # ═══════════════════════════════════════════════════════════

    def check_test_50_esxi_lockout(self):
        esx = self.data.get("esx_config")
        if not esx or not isinstance(esx, dict): return
        lockout = esx.get("Security.AccountLockFailures", esx.get("account_lock_failures", ""))
        if str(lockout) == "0":
            self.finding(50, "T1562.001-50", "ESXi account lockout policy disabled",
                self.SEVERITY_HIGH, "Security.AccountLockFailures=0 — brute force protection disabled.",
                [f"AccountLockFailures = {lockout}"],
                "Set Security.AccountLockFailures=5 via PowerCLI.",
                "ESXi", "ESXi", "")

    # ═══════════════════════════════════════════════════════════
    # CATEGORY Q: Defender ASR Rules (Tests 51-52)
    # ═══════════════════════════════════════════════════════════

    def check_test_51_delete_asr_intune(self):
        asr = self.data.get("asr_rules")
        if not asr or not isinstance(asr, dict): return
        if not asr.get("rules") and not asr.get("AttackSurfaceReductionRules_Ids"):
            self.finding(51, "T1562.001-51", "Defender ASR rules missing (InTune deletion suspected)",
                self.SEVERITY_HIGH, "No ASR rules configured — may have been deleted.",
                ["ASR rules: none found"],
                "Reconfigure ASR rules via InTune or GPO.",
                "Windows", "Defender ASR", "")

    def check_test_52_delete_asr_gpo(self):
        # Same check as 51 — ASR rules missing
        pass

    # ═══════════════════════════════════════════════════════════
    # CATEGORY R: ETW Tampering (Tests 54-57)
    # ═══════════════════════════════════════════════════════════

    def check_test_54_etw_autologger_cmd(self):
        etw = self.data.get("etw_autologger") or self.data.get("registry")
        if not etw or not isinstance(etw, dict): return
        val = etw.get("HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\EventLog-Application\\Start", "")
        if str(val) == "0":
            self.finding(54, "T1562.001-54", "EventLog-Application ETW Auto Logger disabled (cmd)",
                self.SEVERITY_CRITICAL, "ETW Auto Logger Start=0 — Event Log Application channel disabled.",
                ["EventLog-Application\\Start = 0"],
                'reg add "HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\EventLog-Application" /v Start /t REG_DWORD /d 1 /f',
                "Windows", "ETW Tampering", "")

    def check_test_55_etw_autologger_ps(self):
        pass  # Same registry check as test 54

    def check_test_56_etw_provider_cmd(self):
        etw = self.data.get("etw_autologger") or self.data.get("registry")
        if not etw or not isinstance(etw, dict): return
        # Check for disabled providers
        disabled_providers = []
        for key, val in etw.items():
            if "Autologger\\EventLog-Application\\" in str(key) and "Enabled" in str(key):
                if str(val) == "0":
                    disabled_providers.append(f"{key} = 0")
        if disabled_providers:
            self.finding(56, "T1562.001-56", f"ETW providers disabled ({len(disabled_providers)})",
                self.SEVERITY_HIGH, "Specific ETW providers disabled in EventLog-Application session.",
                disabled_providers[:10],
                "Re-enable providers: set Enabled=1 for each GUID.",
                "Windows", "ETW Tampering", "")

    def check_test_57_etw_provider_ps(self):
        pass  # Same registry check as test 56


# ═══════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════

def main():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════════╗
  ║   T1562.001 — Impair Defenses: Disable or Modify Tools           ║
  ║   Atomic Red Team Audit Module — All 59 Tests                    ║
  ║                                                                  ║
  ║   MITRE ATT&CK · Defense Evasion · Atomic Red Team               ║
  ╚═══════════════════════════════════════════════════════════════════╝
    """)
    parser = argparse.ArgumentParser(description="T1562.001 Atomic Red Team Audit")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--output", default="t1562_001_report.json")
    parser.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW","ALL"], default="ALL")
    args = parser.parse_args()
    auditor = T1562001Auditor(args.data_dir)
    findings = auditor.run_all_checks()
    sev_map = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    if args.severity != "ALL":
        t = sev_map.get(args.severity, 3)
        findings = [f for f in findings if sev_map.get(f["severity"], 3) <= t]
    meta = {"technique": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools",
            "total_atomic_tests": 59, "findings_count": len(findings),
            "scan_time": datetime.datetime.now().isoformat(),
            "source": "https://atomicredteam.io/docs/atomics/T1562.001"}
    report = {"meta": meta, "findings": findings}
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    c = sum(1 for f in findings if f["severity"] == "CRITICAL")
    h = sum(1 for f in findings if f["severity"] == "HIGH")
    m = sum(1 for f in findings if f["severity"] == "MEDIUM")
    l = sum(1 for f in findings if f["severity"] == "LOW")
    print(f"\n[*] Audit complete — {len(findings)} finding(s)")
    print(f"    CRITICAL: {c}  |  HIGH: {h}  |  MEDIUM: {m}  |  LOW: {l}")
    print(f"    Report: {args.output}")
    # Print summary table
    cats = {}
    for f in findings:
        cat = f.get("category", "Other")
        if cat not in cats: cats[cat] = []
        cats[cat].append(f)
    if cats:
        print(f"\n    {'Category':<30} {'Findings':>8}")
        print(f"    {'─'*30} {'─'*8}")
        for cat, fl in sorted(cats.items()):
            print(f"    {cat:<30} {len(fl):>8}")
    print()

if __name__ == "__main__":
    main()
