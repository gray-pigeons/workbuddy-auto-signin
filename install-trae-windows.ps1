# TRAE SOLO CN (TraeWork CN) 本地登录态自动签到任务。
# 作者：88lin
# 仓库：https://github.com/gray-pigeons/workbuddy-auto-signin
# 协议：MIT
# 用法：powershell -ExecutionPolicy Bypass -File .\install-trae-windows.ps1
# 可选：-AuthDir 'D:\TRAE Data'；数据目录会固化到任务参数。
[CmdletBinding()]
param([string]$AuthDir = $env:TRAE_AUTH_DIR)

$ErrorActionPreference = 'Stop'
$taskName = 'TraeSoloCNAutoSignin'

function Find-Pythonw {
    $command = Get-Command pythonw -ErrorAction SilentlyContinue
    if ($command -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) { return $command.Source }
    $command = Get-Command python -ErrorAction SilentlyContinue
    if ($command) {
        $candidate = Join-Path (Split-Path -LiteralPath $command.Source) 'pythonw.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    foreach ($pattern in @(
        'C:\Python3*\pythonw.exe',
        "$env:LOCALAPPDATA\Programs\Python\Python3*\pythonw.exe",
        'C:\Program Files\Python3*\pythonw.exe'
    )) {
        $candidate = Get-ChildItem $pattern -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    $launcher = Join-Path $env:SystemRoot 'py.exe'
    if (Test-Path -LiteralPath $launcher -PathType Leaf) {
        try {
            $python = & $launcher -3 -c 'import sys;print(sys.executable)' 2>$null | Select-Object -Last 1
            if ($python) {
                $candidate = Join-Path (Split-Path -LiteralPath $python.Trim()) 'pythonw.exe'
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
            }
        } catch { }
    }
    return $null
}

function Quote-WindowsArgument([string]$Value) {
    # Windows argv 约定：引号前的反斜杠，以及闭合引号前的反斜杠须加倍。
    return '"' + ($Value -replace '(\*)"', '$1$1\"' -replace '(\+)$', '$1$1') + '"'
}

Write-Host 'TRAE SOLO CN 自动签到 · 安装 Windows 任务' -ForegroundColor Cyan
$operation = '离线自检'
try {
    $pythonw = Find-Pythonw
    if (-not $pythonw) { throw '未找到 pythonw.exe，请先安装 Python 3 并加入 PATH。' }
    $pythonw = (Resolve-Path -LiteralPath $pythonw -ErrorAction Stop).Path
    $python = Join-Path (Split-Path -LiteralPath $pythonw) 'python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'pythonw.exe 同目录缺少 python.exe。' }
    $signin = Join-Path $PSScriptRoot 'trae_signin.py'
    if (-not (Test-Path -LiteralPath $signin -PathType Leaf)) { throw '请将本安装脚本与 trae_signin.py 放在同一目录。' }
    $signin = (Resolve-Path -LiteralPath $signin -ErrorAction Stop).Path
    $authArgs = @()
    if ($AuthDir) {
        # PowerShell 5.1 在带方括号的工作目录中解析相对 LiteralPath 会失败。
        if (-not [System.IO.Path]::IsPathRooted($AuthDir)) {
            $AuthDir = Join-Path (Get-Location).ProviderPath $AuthDir
        }
        $AuthDir = [System.IO.Path]::GetFullPath($AuthDir)
        if (-not (Test-Path -LiteralPath $AuthDir -PathType Container)) { throw 'AuthDir 必须指向已存在的 TRAE SOLO CN 数据目录。' }
        $AuthDir = (Resolve-Path -LiteralPath $AuthDir -ErrorAction Stop).Path
        $authArgs = @('--auth-dir', $AuthDir)
    }
    $doctorOutput = @(& $python -X utf8 $signin doctor @authArgs)
    if ($LASTEXITCODE -ne 0) {
        $doctorOutput | ForEach-Object { Write-Host $_ }
        throw '本地登录态自检失败；请先登录 TRAE SOLO CN，再重试安装。'
    }
    $doctor = ($doctorOutput -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop
    if ($doctor.result -ne 'OK') { throw 'doctor 未返回有效的成功结果，未创建任务。' }
    Write-Host '本地登录态自检通过（未联网、未签到）。' -ForegroundColor Green

    $operation = '创建'
    $userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited -ErrorAction Stop
    # 每天北京时间 00:10；另有用户登录触发器兜住关机错过的运行。
    $midnightUtc = [datetime]::SpecifyKind([datetime]::UtcNow.Date.AddHours(-8), [DateTimeKind]::Utc)
    $localTime = $midnightUtc.AddMinutes(10).ToLocalTime().ToString('HH:mm')
    $times = @($localTime)
    $triggers = @(New-ScheduledTaskTrigger -Daily -At $localTime -ErrorAction Stop)
    $logon = New-ScheduledTaskTrigger -AtLogOn -User $userId -ErrorAction Stop
    $logon.Delay = 'PT1M'
    $triggers += $logon
    $arguments = (Quote-WindowsArgument $signin) + ' silent'
    if ($AuthDir) { $arguments += ' --auth-dir ' + (Quote-WindowsArgument $AuthDir) }
    $action = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments -WorkingDirectory (Split-Path -LiteralPath $signin) -ErrorAction Stop
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -Hidden -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -ErrorAction Stop
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Description 'TRAE SOLO CN daily check-in using the current local desktop session' -Force -ErrorAction Stop | Out-Null

    $operation = '校验'
    $tasks = @(Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop)
    if ($tasks.Count -ne 1) { throw '未读取到唯一的 TRAE SOLO CN 任务。' }
    $actions = @($tasks[0].Actions)
    if ($actions.Count -ne 1 -or $actions[0].Execute -ne $pythonw -or $actions[0].Arguments -cne $arguments) { throw '任务的 Python 路径或签到参数回读不匹配。' }
    $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction Stop
    if ($null -eq $info -or $null -eq $info.NextRunTime -or $info.NextRunTime -eq [datetime]::MinValue) { throw '未读取到下次运行时间。' }
} catch {
    Write-Host "$operation $taskName 失败，安装未完成。" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($operation -eq '校验') { Write-Host '任务可能已注册；排除问题后重跑可更新同名任务。' -ForegroundColor Yellow }
    if ($operation -ne '离线自检') {
        Write-Host '若提示拒绝访问（0x80070005），请使用同一 Windows 账号以管理员身份打开 PowerShell 后重试。' -ForegroundColor Yellow
    }
    exit 1
}

Write-Host '定时任务已就位：' -ForegroundColor Green
Write-Host "  $taskName  $($tasks[0].State)"
Write-Host "  每天本机时间 $localTime（对应北京时间 00:10），另在登录 Windows 1 分钟后补跑。"
Write-Host "  下次运行 $($info.NextRunTime)"
Write-Host ("日志：" + (Join-Path (Split-Path -LiteralPath $signin) 'trae_signin.log'))
Write-Host '安装只做离线检查；需要立即签到可运行 python trae_signin.py auto。'
Write-Host '卸载：Unregister-ScheduledTask -TaskName "TraeSoloCNAutoSignin" -Confirm:$false'
