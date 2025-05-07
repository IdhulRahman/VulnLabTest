# ===========================================
# SIMULASI KERENTANAN PADA WINDOWS 10 – V3
# By: idhul
# ===========================================

# Jalankan sebagai Administrator!
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[FAILED] Jalankan skrip ini sebagai Administrator!" -ForegroundColor Red
    exit
}

# Buat direktori untuk flag
$flagDir = "C:\Flags"
if (-not (Test-Path $flagDir)) {
    New-Item -Path $flagDir -ItemType Directory -Force | Out-Null
    Write-Host "[INFO] Direktori flag dibuat." -ForegroundColor Cyan
}

# ===============================
# LEVEL 1 – BASIC MISCONFIGURATION
# ===============================

try {
    $smbService = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    if ($smbService) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction SilentlyContinue
        "LEVEL 1: SMBv1 enabled" | Out-File "$flagDir\flag_LEVEL1_smbv1.txt"
        Write-Host "[SUCCESS] SMBv1 berhasil diaktifkan." -ForegroundColor Green
    } else {
        Write-Host "[FAILED] SMB Server service tidak ditemukan." -ForegroundColor Red
    }
} catch {
    Write-Host "[FAILED] Error SMBv1: $_" -ForegroundColor Red
}

try {
    Enable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    "LEVEL 1: Guest Account enabled" | Out-File "$flagDir\flag_LEVEL1_guest_account.txt"
    Write-Host "[SUCCESS] Akun Guest berhasil diaktifkan." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal mengaktifkan akun Guest: $_" -ForegroundColor Red
}

try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    "LEVEL 1: Windows Defender disabled" | Out-File "$flagDir\flag_LEVEL1_defender.txt"
    Write-Host "[SUCCESS] Windows Defender berhasil dinonaktifkan." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal menonaktifkan Defender: $_" -ForegroundColor Red
}

try {
    if ($smbService) {
        Set-SmbServerConfiguration -RequireSecuritySignature $false -Force -ErrorAction SilentlyContinue
        "LEVEL 1: SMB Signing disabled" | Out-File "$flagDir\flag_LEVEL1_smb_signing.txt"
        Write-Host "[SUCCESS] SMB Signing berhasil dinonaktifkan." -ForegroundColor Green
    }
} catch {
    Write-Host "[FAILED] Gagal menonaktifkan SMB Signing: $_" -ForegroundColor Red
}

try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 0 -ErrorAction SilentlyContinue
    "LEVEL 1: NTLMv1 used" | Out-File "$flagDir\flag_LEVEL1_ntlm.txt"
    Write-Host "[SUCCESS] LMCompatibilityLevel diatur ke NTLMv1." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal mengatur NTLM: $_" -ForegroundColor Red
}

# ===============================
# LEVEL 2 – MISCONFIG + PRIV ESC
# ===============================

try {
    Set-ExecutionPolicy Unrestricted -Force -ErrorAction SilentlyContinue
    "LEVEL 2: PowerShell Execution Policy set to Unrestricted" | Out-File "$flagDir\flag_LEVEL2_powershell.txt"
    Write-Host "[SUCCESS] Execution policy berhasil diubah ke Unrestricted." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal mengubah execution policy: $_" -ForegroundColor Red
}

try {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UnquotedService" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UnquotedService" -Name "UninstallString" -Value "C:\Program Files\VulnerableService\UnquotedService.exe" -ErrorAction SilentlyContinue
    "LEVEL 2: Unquoted Service Path created" | Out-File "$flagDir\flag_LEVEL2_service_path.txt"
    Write-Host "[SUCCESS] Unquoted Service Path berhasil dibuat." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal membuat Unquoted Service Path: $_" -ForegroundColor Red
}

try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue
    $rdpTcpPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $rdpTcpPath) {
        Set-ItemProperty -Path $rdpTcpPath -Name "UserAuthentication" -Value 0 -ErrorAction SilentlyContinue
    }
    "LEVEL 2: RDP without encryption" | Out-File "$flagDir\flag_LEVEL2_rdp.txt"
    Write-Host "[SUCCESS] RDP berhasil dikonfigurasi secara tidak aman." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal mengatur konfigurasi RDP: $_" -ForegroundColor Red
}

try {
    $taskAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Malicious Task Executed"
    $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    Unregister-ScheduledTask -TaskName "InsecureTask" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -Action $taskAction -Trigger $taskTrigger -TaskName "InsecureTask" -User "SYSTEM" -ErrorAction SilentlyContinue
    "LEVEL 2: Scheduled Task created" | Out-File "$flagDir\flag_LEVEL2_task.txt"
    Write-Host "[SUCCESS] Scheduled task berhasil dibuat." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal membuat Scheduled Task: $_" -ForegroundColor Red
}

try {
    $shortcutPath = "$env:USERPROFILE\Desktop\MaliciousShortcut.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
    $shortcut.Arguments = "/c echo Malicious Shortcut Executed"
    $shortcut.Save()
    "LEVEL 2: Malicious Shortcut created" | Out-File "$flagDir\flag_LEVEL2_shortcut.txt"
    Write-Host "[SUCCESS] Shortcut berbahaya berhasil dibuat." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal membuat shortcut: $_" -ForegroundColor Red
}

# ===============================
# LEVEL 3 – ADVANCED PERSISTENCE
# ===============================

try {
    $hijackPath = "C:\Windows\System32\example.dll"
    "Dummy DLL File untuk simulasi DLL Hijacking" | Out-File "$env:TEMP\dummy.dll"
    Copy-Item -Path "$env:TEMP\dummy.dll" -Destination $hijackPath -ErrorAction SilentlyContinue
    "LEVEL 3: DLL Hijacking registered" | Out-File "$flagDir\flag_LEVEL3_dll_hijack.txt"
    Write-Host "[SUCCESS] Simulasi DLL hijacking berhasil." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal melakukan simulasi DLL hijacking: $_" -ForegroundColor Red
}

try {
    $wmiSimFile = "$env:TEMP\wmi_persistence_simulation.txt"
    @"
# Kode WMI Persistence (simulasi)
"@ | Out-File $wmiSimFile
    "LEVEL 3: WMI Persistence set up" | Out-File "$flagDir\flag_LEVEL3_wmi.txt"
    Write-Host "[SUCCESS] Simulasi WMI persistence berhasil." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal membuat simulasi WMI: $_" -ForegroundColor Red
}

try {
    $disableLoggingSim = "$env:TEMP\disable_event_logging.txt"
    @"
# Simulasi nonaktifkan event logging
"@ | Out-File $disableLoggingSim
    "LEVEL 3: Event Logging disabled" | Out-File "$flagDir\flag_LEVEL3_event_log.txt"
    Write-Host "[SUCCESS] Simulasi nonaktifkan event logging berhasil." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal simulasi nonaktifkan logging: $_" -ForegroundColor Red
}

try {
    $payloadPath = "$env:TEMP\MaliciousPayload.sct"
    @"
<?XML version="1.0"?>
<scriptlet>
...
</scriptlet>
"@ | Out-File $payloadPath
    "regsvr32 /s /n /i:$payloadPath scrobj.dll" | Out-File "$env:TEMP\regsvr32_sim.cmd"
    "LEVEL 3: Regsvr32 payload simulated" | Out-File "$flagDir\flag_LEVEL3_regsvr32.txt"
    Write-Host "[SUCCESS] Simulasi regsvr32 berhasil dibuat." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal membuat simulasi regsvr32: $_" -ForegroundColor Red
}

try {
    $mimikatzSim = "$env:TEMP\mimikatz_simulation.txt"
    @"
# Simulasi Mimikatz Output
"@ | Out-File $mimikatzSim
    "LEVEL 3: LSASS credential dump prepared" | Out-File "$flagDir\flag_LEVEL3_lsass.txt"
    Write-Host "[SUCCESS] Simulasi dump kredensial LSASS berhasil." -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Gagal membuat simulasi LSASS dump: $_" -ForegroundColor Red
}

# ===============================
# CEK ACHIEVEMENT
# ===============================

try {
    if ((Test-Path "$flagDir\flag_LEVEL1_smbv1.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL2_service_path.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL3_event_log.txt")) {
        "BLUE TEAM: Achievement unlocked." | Out-File "$flagDir\blue_team_achievement.txt"
        Write-Host "[SUCCESS] Achievement Blue Team didapatkan." -ForegroundColor Green
    }

    if ((Test-Path "$flagDir\flag_LEVEL1_smbv1.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL2_task.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL3_lsass.txt")) {
        "ATTACKER: Achievement unlocked." | Out-File "$flagDir\attacker_achievement.txt"
        Write-Host "[SUCCESS] Achievement Attacker didapatkan." -ForegroundColor Green
    }
} catch {
    Write-Host "[FAILED] Gagal memeriksa achievement: $_" -ForegroundColor Red
}

# ===============================
# RINGKASAN
# ===============================
$level1Count = (Get-ChildItem "$flagDir\flag_LEVEL1_*.txt" -ErrorAction SilentlyContinue).Count
$level2Count = (Get-ChildItem "$flagDir\flag_LEVEL2_*.txt" -ErrorAction SilentlyContinue).Count
$level3Count = (Get-ChildItem "$flagDir\flag_LEVEL3_*.txt" -ErrorAction SilentlyContinue).Count

Write-Host "`n=============================================================" -ForegroundColor Yellow
Write-Host "Simulasi kerentanan selesai. Cek flag di $flagDir" -ForegroundColor Yellow
Write-Host "Simulasi file berbahaya dibuat di $env:TEMP" -ForegroundColor Yellow
Write-Host "Level 1: $level1Count/5" -ForegroundColor Yellow
Write-Host "Level 2: $level2Count/5" -ForegroundColor Yellow
Write-Host "Level 3: $level3Count/5" -ForegroundColor Yellow
Write-Host "=============================================================" -ForegroundColor Yellow
