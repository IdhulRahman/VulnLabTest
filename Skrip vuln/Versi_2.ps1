# ===========================================
# SIMULASI KERENTANAN PADA WINDOWS 10
# By: idhul
# ===========================================

# Jalankan sebagai Administrator!
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[WARNING] Jalankan skrip ini sebagai Administrator!" -ForegroundColor Yellow
    exit
}

# ===========================================
# Inisialisasi Direktori dan Log
# ===========================================

# Direktori untuk flag
$flagDir = "C:\Flags"
# Direktori sementara untuk file
$tempDir = "C:\Temp\VulnSim"

# Membuat direktori jika belum ada
function Initialize-Directories {
    if (-not (Test-Path $flagDir)) { 
        New-Item -Path $flagDir -ItemType Directory -Force | Out-Null 
        Write-Host "[INFO] Direktori flag dibuat." -ForegroundColor Cyan
    }
    if (-not (Test-Path $tempDir)) { 
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null 
        Write-Host "[INFO] Direktori temp dibuat." -ForegroundColor Cyan
    }
}

# ============================
# Fungsi Utama: Invoke-VulnAction
# ============================

function Invoke-VulnAction {
    param (
        [string]$Title,
        [string]$FlagPath,
        [ScriptBlock]$Action
    )

    try {
        & $Action
        if ($FlagPath) { $Title | Out-File -Encoding ASCII $FlagPath }
        Write-Host "[SUCCESS] $Title berhasil." -ForegroundColor Green
    } catch {
        Write-Host "[FAILED] $Title gagal: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================
# LEVEL 1 – BASIC MISCONFIGURATION
# ============================

function Exploit-Level1 {
    # Aktifkan SMBv1 (sangat rentan)
    Invoke-VulnAction -Title "SMBv1" -FlagPath "$flagDir\flag_LEVEL1_smbv1.txt" -Action {
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
    }

    # Aktifkan akun Guest
    Invoke-VulnAction -Title "Akun Guest" -FlagPath "$flagDir\flag_LEVEL1_guest_account.txt" -Action {
        Enable-LocalUser -Name "Guest" -ErrorAction Stop
    }

    # Nonaktifkan Windows Defender
    Invoke-VulnAction -Title "Windows Defender" -FlagPath "$flagDir\flag_LEVEL1_defender.txt" -Action {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    }

    # Nonaktifkan SMB Signing
    Invoke-VulnAction -Title "SMB Signing" -FlagPath "$flagDir\flag_LEVEL1_smb_signing.txt" -Action {
        Set-SmbServerConfiguration -RequireSecuritySignature $false -Force -ErrorAction Stop
    }

    # Set NTLM ke level terendah
    Invoke-VulnAction -Title "LMCompatibilityLevel diatur ke NTLMv1" -FlagPath "$flagDir\flag_LEVEL1_ntlm.txt" -Action {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 0 -ErrorAction Stop
    }
}

# ============================
# LEVEL 2 – MISCONFIGURATION + PRIVILEGE ESCALATION
# ============================

function Exploit-Level2 {
    # Set PowerShell Execution Policy ke Unrestricted
    Invoke-VulnAction -Title "PowerShell Execution Policy diatur ke Unrestricted" -FlagPath "$flagDir\flag_LEVEL2_powershell.txt" -Action {
        Set-ExecutionPolicy Unrestricted -Force -ErrorAction Stop
    }

    # Buat registry key untuk simulasi Unquoted Service Path
    Invoke-VulnAction -Title "Unquoted Service Path dibuat" -FlagPath "$flagDir\flag_LEVEL2_service_path.txt" -Action {
        $servicePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UnquotedService"
        if (-not (Test-Path $servicePath)) {
            New-Item -Path $servicePath -Force | Out-Null
        }
        Set-ItemProperty -Path $servicePath -Name "UninstallString" -Value "C:\Program Files\VulnerableService\UnquotedService.exe" -ErrorAction Stop
    }

    # Konfigurasi RDP tidak aman
    Invoke-VulnAction -Title "RDP tanpa enkripsi" -FlagPath "$flagDir\flag_LEVEL2_rdp.txt" -Action {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -ErrorAction Stop
    }

    # Buat scheduled task
    Invoke-VulnAction -Title "Scheduled Task dengan izin tidak aman dibuat" -FlagPath "$flagDir\flag_LEVEL2_task.txt" -Action {
        $taskName = "InsecureTask"
        $taskAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Malicious Task Executed > $tempDir\task_executed.txt"
        $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -Action $taskAction -Trigger $taskTrigger -TaskName $taskName -User "SYSTEM" -ErrorAction Stop
    }
}

# ============================
# LEVEL 3 – ADVANCED PERSISTENCE
# ============================

function Exploit-Level3 {
    # Nonaktifkan Event Logging
    Invoke-VulnAction -Title "Event Logging dinonaktifkan" -FlagPath "$flagDir\flag_LEVEL3_event_log.txt" -Action {
        $eventLogKeys = @(
            "HKLM:\System\CurrentControlSet\Services\EventLog\Application",
            "HKLM:\System\CurrentControlSet\Services\EventLog\System",
            "HKLM:\System\CurrentControlSet\Services\EventLog\Security"
        )
        
        foreach ($key in $eventLogKeys) {
            Set-ItemProperty -Path $key -Name "Retention" -Value 0 -ErrorAction Stop
        }
    }

    # Simulasi LSASS dumping
    Invoke-VulnAction -Title "Simulasi LSASS Dumping" -FlagPath "$flagDir\flag_LEVEL3_lsass.txt" -Action {
        $lsassDumpPath = "$tempDir\lsass_dump_sim.bin"
        "Simulated LSASS Dump - This would contain password hashes in a real attack" | Out-File -Encoding ASCII $lsassDumpPath -ErrorAction Stop
    }

    # Simulasi DLL Hijacking (tanpa file berbahaya)
    Invoke-VulnAction -Title "Kerentanan DLL Hijacking terdaftar" -FlagPath "$flagDir\flag_LEVEL3_dll_hijack.txt" -Action {
        "This is a simulated malicious DLL" | Out-File -Encoding ASCII "$tempDir\example.dll" -ErrorAction Stop
    }

    # Simulasi regsvr32 untuk payload execution
    Invoke-VulnAction -Title "Regsvr32 digunakan untuk eksekusi payload (simulasi)" -FlagPath "$flagDir\flag_LEVEL3_regsvr32.txt" -Action {
        $sctSimFile = "$tempDir\malicious_payload.sct"
        @"
<?XML version="1.0"?>
<scriptlet>
<registration 
    description="Windows Script Component"
    progid="SimulatedAttack"
    version="1.00">
    <script language="JScript">
        <![CDATA[
            var shell = new ActiveXObject("WScript.Shell");
            shell.Popup("Simulated Malicious SCT Payload", 10, "Vulnerability Simulation", 64);
        ]]>
    </script>
</registration>
</scriptlet>
"@ | Out-File -Encoding ASCII $sctSimFile -ErrorAction Stop
    }
}

# ============================
# CEK ACHIEVEMENT
# ============================

function Check-Achievements {
    # Cek untuk Blue Team Achievement
    if ((Test-Path "$flagDir\flag_LEVEL1_smbv1.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL2_service_path.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL3_event_log.txt")) {
        "BLUE TEAM: Successfully mitigated vulnerabilities at Level 1, 2, and 3. Achievement unlocked." | Out-File -Encoding ASCII "$flagDir\blue_team_achievement.txt"
        Write-Host "[ACHIEVEMENT] BLUE TEAM: Berhasil memitigasi kerentanan di Level 1, 2, dan 3!" -ForegroundColor Magenta
    }

    # Cek untuk Attacker Achievement
    if ((Test-Path "$flagDir\flag_LEVEL1_smbv1.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL2_task.txt") -and 
        (Test-Path "$flagDir\flag_LEVEL3_lsass.txt")) {
        "ATTACKER: Successfully exploited vulnerabilities at Level 1, 2, and 3. Achievement unlocked." | Out-File -Encoding ASCII "$flagDir\attacker_achievement.txt"
        Write-Host "[ACHIEVEMENT] ATTACKER: Berhasil mengeksploitasi kerentanan di Level 1, 2, dan 3!" -ForegroundColor Magenta
    }
}

# ============================
# Main Program Flow
# ============================

Initialize-Directories

Exploit-Level1
Exploit-Level2
Exploit-Level3
Check-Achievements

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "Simulasi kerentanan selesai. Ringkasan:" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$level1Count = (Get-ChildItem "$flagDir\flag_LEVEL1_*.txt" -ErrorAction SilentlyContinue).Count
$level2Count = (Get-ChildItem "$flagDir\flag_LEVEL2_*.txt" -ErrorAction SilentlyContinue).Count
$level3Count = (Get-ChildItem "$flagDir\flag_LEVEL3_*.txt" -ErrorAction SilentlyContinue).Count

Write-Host "[SUMMARY] Level 1 Exploit Count: $level1Count" -ForegroundColor Yellow
Write-Host "[SUMMARY] Level 2 Exploit Count: $level2Count" -ForegroundColor Yellow
Write-Host "[SUMMARY] Level 3 Exploit Count: $level3Count" -ForegroundColor Yellow