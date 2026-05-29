<#
.SYNOPSIS
    Максимально подробное удаление SSH-ключей с автоматическим логированием в текущую папку.
.PARAMETER WhatIf
    Показывает, что будет удалено, но не удаляет.
.PARAMETER AutoConfirm
    Автоматически подтверждает удаление (без запроса).
.PARAMETER LogPath
    Путь для сохранения лога (по умолчанию: текущая папка\SSH_Clean_YYYYMMDD_HHMMSS.log).
#>
param(
    [switch]$WhatIf,
    [switch]$AutoConfirm,
    [string]$LogPath
)

# ---------- Определение места для лога ----------
if (-not $LogPath) {
    $currentDir = (Get-Location).Path
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogPath = Join-Path $currentDir "SSH_Clean_${timestamp}.log"
}

$script:logLines = @()
function Write-Trace {
    param([string]$Message, [string]$Color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss.fff')] $Message"
    $script:logLines += $line
    Write-Host $line -ForegroundColor $Color
}

# ---------- Белый список путей ----------
$whiteListPaths = @()
$whiteListPaths += "C:\"
$whiteListPaths += "C:\ProgramData\ssh"
$whiteListPaths += "$env:USERPROFILE\.ssh"
$userDirs = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
foreach ($userDir in $userDirs) { $whiteListPaths += Join-Path $userDir.FullName ".ssh" }
# Добавляем корни всех фиксированных дисков (без рекурсии, только файлы в корне)
$fixedDrives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.DeviceID -ne "C:" } | Select-Object -ExpandProperty DeviceID
foreach ($drive in $fixedDrives) { $whiteListPaths += "$drive\" }
$whiteListPaths = $whiteListPaths | Select-Object -Unique

Write-Trace "=== TRACE: SSH key cleanup ===" -Color Cyan
Write-Trace "Log file: $LogPath" -Color Cyan
Write-Trace "White-list paths:" -Color Cyan
foreach ($p in $whiteListPaths) { Write-Trace "  $p" -Color Gray }

# ---------- Функция проверки публичного ключа ----------
function Test-SshPublicKey {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $firstLine = Get-Content $Path -TotalCount 1 -ErrorAction SilentlyContinue
    $isSsh = $firstLine -match '^ssh-(rsa|dss|ed25519|ecdsa) '
    if ($isSsh) { Write-Trace "    [VALID] SSH public key: $Path" -Color Green }
    else { Write-Trace "    [SKIP] Not SSH public key: $Path (first line: '$firstLine')" -Color DarkGray }
    return $isSsh
}

# ---------- Поиск ----------
$foundFiles = @()
$patterns = @("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
              "known_hosts", "authorized_keys", "config", "*.ppk")

foreach ($path in $whiteListPaths) {
    if (-not (Test-Path $path)) { Write-Trace "Path does not exist: $path" -Color DarkGray; continue }
    Write-Trace "Scanning: $path" -Color Yellow
    if ($path -match '^[A-Z]:\\$') {
        Write-Trace "  Non-recursive scan of drive root" -Color DarkCyan
        foreach ($pattern in $patterns) {
            $files = Get-ChildItem -Path $path -Filter $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Write-Trace "    Found file: $($file.FullName)" -Color DarkYellow
                if ($file.Extension -eq '.pub') {
                    if (Test-SshPublicKey $file.FullName) { $foundFiles += $file.FullName; Write-Trace "      -> WILL BE DELETED" -Color Red }
                    else { Write-Trace "      -> SKIPPED" -Color DarkGray }
                } else {
                    $foundFiles += $file.FullName
                    Write-Trace "      -> WILL BE DELETED" -Color Red
                }
            }
        }
    } else {
        Write-Trace "  Recursive scan of $path" -Color DarkCyan
        $items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            if ($item.PSIsContainer) { continue }
            $matched = $false
            foreach ($pattern in $patterns) { if ($item.Name -like $pattern) { $matched = $true; break } }
            if (-not $matched) { continue }
            Write-Trace "    Found file: $($item.FullName)" -Color DarkYellow
            if ($item.Extension -eq '.pub') {
                if (Test-SshPublicKey $item.FullName) { $foundFiles += $item.FullName; Write-Trace "      -> WILL BE DELETED" -Color Red }
                else { Write-Trace "      -> SKIPPED" -Color DarkGray }
            } elseif ($item.Name -match '^config$|^ssh_config$|^sshd_config$') {
                $content = Get-Content $item.FullName -TotalCount 10 -ErrorAction SilentlyContinue
                if ($content -match 'Host\s|IdentityFile|Port\s|Protocol\s|PermitRootLogin') {
                    $foundFiles += $item.FullName; Write-Trace "      -> WILL BE DELETED (SSH config)" -Color Red
                } else { Write-Trace "      -> SKIPPED (not SSH config)" -Color DarkGray }
            } else {
                $foundFiles += $item.FullName; Write-Trace "      -> WILL BE DELETED" -Color Red
            }
        }
    }
}

Write-Trace "`n=== SCAN COMPLETE ===" -Color Cyan
Write-Trace "Total files marked for deletion: $($foundFiles.Count)" -Color Yellow

if ($foundFiles.Count -eq 0) {
    Write-Trace "No SSH files found." -Color Green
} else {
    Write-Trace "Files to delete:" -Color Red
    foreach ($f in $foundFiles) { Write-Trace "  $f" -Color Red }
    if ($WhatIf) {
        Write-Trace "WHATIF mode: No files deleted." -Color Cyan
    } else {
        if (-not $AutoConfirm) { Read-Host "Press Enter to delete these files (or Ctrl+C to cancel)" }
        foreach ($f in $foundFiles) { Remove-Item -Path $f -Force; Write-Trace "Deleted: $f" -Color Green }
    }
}

# ---------- Очистка агента и истории (только не WhatIf) ----------
if (-not $WhatIf) {
    Write-Trace "`n=== Cleaning ssh-agent ===" -Color Cyan
    Stop-Service ssh-agent -Force -ErrorAction SilentlyContinue
    Set-Service ssh-agent -StartupType Disabled -ErrorAction SilentlyContinue
    Get-Process ssh-agent -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Trace "ssh-agent stopped and disabled." -Color Green

    Write-Trace "Cleaning command history..." -Color Cyan
    Clear-History
    $historyPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
    if ($historyPath -and (Test-Path $historyPath)) { Remove-Item $historyPath -Force; Write-Trace "PowerShell history deleted." -Color Green }
    $cmdHistory = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $cmdHistory) { Remove-Item $cmdHistory -Force; Write-Trace "CMD history cleared." -Color Green }

    Write-Trace "Cleaning temp files..." -Color Cyan
    Get-ChildItem $env:TEMP -Filter "ssh_*" -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem $env:TEMP -Filter "*.key" -File | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Trace "Temp files removed." -Color Green

    Write-Trace "`n=== Cleanup completed ===" -Color Cyan
    $reboot = Read-Host "Reboot now? (y/n)"
    if ($reboot -eq 'y') { Restart-Computer -Force }
} else {
    Write-Trace "`nWHATIF mode: No changes made." -Color Cyan
}

# Сохранение лога в текущую папку
$script:logLines | Out-File -FilePath $LogPath -Encoding UTF8
Write-Trace "Log saved to: $LogPath" -Color Green