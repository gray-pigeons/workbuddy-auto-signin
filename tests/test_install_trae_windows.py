"""Exercise the real installer with fixture authentication and a fake scheduler."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SHELLS = [path for name in ("powershell.exe", "pwsh.exe")
          if (path := shutil.which(name))] if sys.platform == "win32" else []
TASK = "TraeSoloCNAutoSignin"

DOCTOR = r'''
import json, os, sys
from pathlib import Path
with Path(os.environ["TRAE_INSTALL_TRACE"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"kind": "doctor", "args": sys.argv[1:]}) + "\n")
scenario = os.environ["TRAE_INSTALL_SCENARIO"]
print(json.dumps({"result": "NO_AUTH" if scenario == "doctor-error" else "OK"}))
sys.exit(2 if scenario == "doctor-error" else 0)
'''

HARNESS = r'''
param($Installer, $TracePath, $Scenario, $Pythonw, $DataDir)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Import-Module Microsoft.PowerShell.Management
Import-Module Microsoft.PowerShell.Utility
# PowerShell 5.1 can choose a different initial provider location for bracketed cwd.
Set-Location -LiteralPath (Join-Path (Split-Path -LiteralPath $Installer) 'cwd')
$PSModuleAutoloadingPreference = 'None'
$fake = New-Module -ArgumentList $TracePath, $Scenario, $Pythonw -ScriptBlock {
    param($TracePath, $Scenario, $Pythonw)
    $script:ErrorActionPreference = 'Continue'
    $script:TracePath = $TracePath
    $script:Scenario = $Scenario
    $script:Pythonw = $Pythonw
    $script:Action = $null
    function Trace($Kind, $Name, $Value) {
        $line = @{kind=$Kind; name=$Name; value=$Value} | ConvertTo-Json -Compress -Depth 10
        [System.IO.File]::AppendAllText($script:TracePath, $line + [Environment]::NewLine)
    }
    function Get-Command {
        [CmdletBinding()] param($Name)
        if ($Name -ne 'pythonw') { throw "Unexpected command lookup: $Name" }
        [pscustomobject]@{Source=$script:Pythonw}
    }
    function New-ScheduledTaskPrincipal {
        [CmdletBinding()] param($UserId, $LogonType, $RunLevel)
        if ($script:Scenario -eq 'principal-error') { Write-Error 'Principal creation failed'; return }
        [pscustomobject]@{UserId=$UserId; LogonType=$LogonType; RunLevel=$RunLevel}
    }
    function New-ScheduledTaskAction {
        [CmdletBinding()] param($Execute, $Argument, $WorkingDirectory)
        [pscustomobject]@{Execute=$Execute; Arguments=$Argument; WorkingDirectory=$WorkingDirectory}
    }
    function New-ScheduledTaskTrigger {
        [CmdletBinding()] param([switch]$Daily, $At, [switch]$AtLogOn, $User)
        [pscustomobject]@{Daily=[bool]$Daily; At=$At; AtLogOn=[bool]$AtLogOn; User=$User; Delay=$null}
    }
    function New-ScheduledTaskSettingsSet {
        [CmdletBinding()] param([switch]$StartWhenAvailable, [switch]$Hidden,
            [switch]$DontStopIfGoingOnBatteries, [switch]$AllowStartIfOnBatteries,
            [timespan]$ExecutionTimeLimit, $MultipleInstances)
        [pscustomobject]@{Seconds=$ExecutionTimeLimit.TotalSeconds; Hidden=[bool]$Hidden;
            StartWhenAvailable=[bool]$StartWhenAvailable; MultipleInstances=$MultipleInstances}
    }
    function Register-ScheduledTask {
        [CmdletBinding()] param($TaskName, $TaskPath, $Action, $Trigger, $Settings,
            $Principal, $Description, [switch]$Force)
        Trace 'register' $TaskName @{path=$TaskPath; action=$Action; triggers=@($Trigger);
            settings=$Settings; principal=$Principal; force=[bool]$Force}
        $script:Action = $Action
        if ($script:Scenario -eq 'register-error') {
            Write-Error 'Access is denied (0x80070005)' -ErrorId 'HRESULT 0x80070005,Register-ScheduledTask'
            return
        }
        [pscustomobject]@{TaskName=$TaskName; State='Ready'}
    }
    function Get-ScheduledTask {
        [CmdletBinding()] param($TaskName, $TaskPath)
        Trace 'get' $TaskName $TaskPath
        if ($script:Scenario -eq 'get-error') { Write-Error 'Cannot read scheduled task'; return }
        if ($script:Scenario -eq 'missing-task') { return }
        if ($script:Scenario -eq 'wrong-action') { $script:Action.Arguments = 'old command' }
        [pscustomobject]@{TaskName=$TaskName; TaskPath=$TaskPath; State='Ready'; Actions=@($script:Action)}
    }
    function Get-ScheduledTaskInfo {
        [CmdletBinding()] param($TaskName, $TaskPath)
        Trace 'info' $TaskName $TaskPath
        if ($script:Scenario -eq 'info-error') { Write-Error 'Cannot read scheduled task info'; return }
        if ($script:Scenario -eq 'info-missing') { return }
        [pscustomobject]@{NextRunTime=[datetime]'2026-11-22T00:10:00'}
    }
    Export-ModuleMember -Function Get-Command, New-ScheduledTaskPrincipal,
        New-ScheduledTaskAction, New-ScheduledTaskTrigger, New-ScheduledTaskSettingsSet,
        Register-ScheduledTask, Get-ScheduledTask, Get-ScheduledTaskInfo
}
Import-Module $fake -Force
if ($DataDir) { & $Installer -AuthDir $DataDir } else { & $Installer }
exit $LASTEXITCODE
'''


def expected_times():
    now = datetime.now(timezone.utc)
    cn_midnight = datetime(now.year, now.month, now.day, tzinfo=timezone.utc) - timedelta(hours=8)
    return [(cn_midnight + timedelta(minutes=10)).astimezone().strftime("%H:%M")]


@unittest.skipUnless(SHELLS, "Windows PowerShell is required for installer tests")
class TraeWindowsInstallerTests(unittest.TestCase):
    def run_installer(self, shell, scenario="success", *, auth=False, env_auth=False,
                      prefix="trae installer 空格 [brackets] "):
        with tempfile.TemporaryDirectory(prefix=prefix) as temp:
            root = Path(temp).resolve()
            installer = root / "install-trae-windows.ps1"
            shutil.copyfile(ROOT / "install-trae-windows.ps1", installer)
            (root / "trae_signin.py").write_text(DOCTOR, encoding="utf-8")
            harness = root / "harness.ps1"
            harness.write_text(HARNESS, encoding="utf-8-sig")
            trace = root / "trace.jsonl"
            cwd = root / "cwd"
            cwd.mkdir()
            data = root / "auth data [cn]"
            data.mkdir()
            pythonw = Path(sys.executable).with_name("pythonw.exe")
            command = [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                       "-File", str(harness), "-Installer", str(installer), "-TracePath", str(trace),
                       "-Scenario", scenario, "-Pythonw", str(pythonw)]
            if auth:
                command += ["-DataDir", str(Path("..") / data.name)]
            env = dict(os.environ, TRAE_INSTALL_TRACE=str(trace), TRAE_INSTALL_SCENARIO=scenario,
                       TRAE_AUTH_DIR=str(data) if env_auth else "")
            result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                    encoding="utf-8", errors="replace", timeout=30)
            events = [json.loads(line) for line in trace.read_text(encoding="utf-8-sig").splitlines()] \
                if trace.exists() else []
            return result, events, str(data), str(root), str(pythonw)

    def assert_failed(self, result):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("定时任务已就位", result.stdout)
        self.assertIn("失败", result.stdout)

    def test_success_self_checks_and_registers_separate_task(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                result, events, _, root, pythonw = self.run_installer(shell)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("定时任务已就位", result.stdout)
                self.assertEqual([e["kind"] for e in events], ["doctor", "register", "get", "info"])
                self.assertEqual(events[0]["args"], ["doctor"])
                self.assertEqual([e["name"] for e in events[1:]], [TASK] * 3)
                value = events[1]["value"]
                self.assertEqual(value["path"], "\\")
                self.assertTrue(value["force"])
                self.assertEqual(value["principal"]["RunLevel"], "Limited")
                self.assertEqual(value["principal"]["LogonType"], "Interactive")
                self.assertIn("\\", value["principal"]["UserId"])
                self.assertEqual(value["settings"]["Seconds"], 300)
                self.assertTrue(value["settings"]["StartWhenAvailable"])
                self.assertTrue(value["settings"]["Hidden"])
                self.assertEqual(value["settings"]["MultipleInstances"], "IgnoreNew")
                self.assertEqual(value["action"]["Execute"], pythonw)
                self.assertEqual(value["action"]["WorkingDirectory"], root)
                self.assertEqual(value["action"]["Arguments"], '"' + root + '\\trae_signin.py" silent')
                self.assertEqual([t["At"] for t in value["triggers"][:-1]], expected_times())
                logon = value["triggers"][-1]
                self.assertTrue(logon["AtLogOn"])
                self.assertEqual(logon["User"], value["principal"]["UserId"])
                self.assertEqual(logon["Delay"], "PT1M")

    def test_auth_directory_is_absolute_and_persisted(self):
        for shell in SHELLS:
            for env_auth in (False, True):
                with self.subTest(shell=shell, env_auth=env_auth):
                    result, events, data, _, _ = self.run_installer(
                        shell, auth=not env_auth, env_auth=env_auth)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(events[0]["args"], ["doctor", "--auth-dir", data])
                    self.assertTrue(events[1]["value"]["action"]["Arguments"].endswith(
                        ' silent --auth-dir "' + data + '"'))

    def test_doctor_failure_does_not_register(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                result, events, _, _, _ = self.run_installer(shell, "doctor-error")
                self.assert_failed(result)
                self.assertEqual([e["kind"] for e in events], ["doctor"])

    def test_registration_error_not_masked_by_existing_task(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                result, events, _, _, _ = self.run_installer(shell, "register-error")
                self.assert_failed(result)
                self.assertEqual([e["kind"] for e in events], ["doctor", "register"])
                self.assertIn("0x80070005", result.stdout)

    def test_definition_and_readback_failures_never_print_success(self):
        scenarios = {"principal-error": ["doctor"],
                     "get-error": ["doctor", "register", "get"],
                     "missing-task": ["doctor", "register", "get"],
                     "wrong-action": ["doctor", "register", "get"],
                     "info-error": ["doctor", "register", "get", "info"],
                     "info-missing": ["doctor", "register", "get", "info"]}
        for shell in SHELLS:
            for scenario, expected in scenarios.items():
                with self.subTest(shell=shell, scenario=scenario):
                    result, events, _, _, _ = self.run_installer(shell, scenario)
                    self.assert_failed(result)
                    self.assertEqual([e["kind"] for e in events], expected)


if __name__ == "__main__":
    unittest.main()
