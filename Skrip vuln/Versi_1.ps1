# ===========================================
# SIMULASI KERENTANAN WINDOWS - REFACTORED
# By: idhul
# ===========================================

# Log hasil dengan status SUCCESS, FAILED, atau INFO
function Log-Result {
    param (
        [string]$Message,
        [string]$Status
    )
    $logMessage = "$Message - Status: $Status"
    $logMessage | Out-File -FilePath "C:\Flags\install_log.txt" -Append

    switch ($Status) {
        "SUCCESS" { Write-Host "[SUCCESS] $Message." -ForegroundColor Green }
        { $_ -like "FAILED*" } { Write-Host "[FAILED] $Message." -ForegroundColor Red }
        "INFO" { Write-Host "[INFO] $Message." -ForegroundColor Cyan }
        default { Write-Host "[INFO] $Message." -ForegroundColor Yellow }
    }
}

# Jalankan sebagai Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Harap jalankan skrip ini sebagai Administrator."
    exit
}

# Inisialisasi Direktori dan Log
$flagDir = "C:\Flags"
$tempDir = "C:\Temp\VulnSim"

function Initialize-Directories {
    if (-not (Test-Path $flagDir)) { 
        New-Item -Path $flagDir -ItemType Directory -Force | Out-Null
        Log-Result "Direktori flag dibuat" "INFO"
    }
    if (-not (Test-Path $tempDir)) { 
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        Log-Result "Direktori temp dibuat" "INFO"
    }
}

function Invoke-VulnAction {
    param (
        [string]$Title,
        [string]$FlagPath,
        [ScriptBlock]$Action
    )

    try {
        & $Action
        if ($FlagPath) { $Title | Out-File -Encoding ASCII $FlagPath }
        Log-Result "$Title berhasil" "SUCCESS"
    } catch {
        Log-Result "$Title gagal" "FAILED - $($_.Exception.Message)"
    }
}

# =========================
# LEVEL 1 – Basic Misconfiguration
# =========================

function Exploit-Level1 {
    Invoke-VulnAction -Title "SMBv1 berhasil diaktifkan" -FlagPath "$flagDir\flag_LEVEL1_smbv1.txt" -Action {
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
    }

    Invoke-VulnAction -Title "Akun labuser berhasil dibuat dan ditambahkan ke Administrator" -FlagPath "$flagDir\flag_LEVEL1_labuser.txt" -Action {
        net user labuser 123 /add
        net localgroup administrators labuser /add
    }

    Invoke-VulnAction -Title "Akun Guest berhasil diaktifkan" -FlagPath "$flagDir\flag_LEVEL1_guest_account.txt" -Action {
        net user guest /active:yes
    }

    Invoke-VulnAction -Title "RDP tanpa autentikasi berhasil diset" -FlagPath "$flagDir\flag_LEVEL1_rdp.txt" -Action {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -ErrorAction Stop
    }
}

# =========================
# LEVEL 2 – Misconfiguration + Privilege Escalation
# =========================

function Exploit-Level2 {
    Invoke-VulnAction -Title "Folder VulnScripts dibuat dengan akses penuh" -FlagPath "$flagDir\flag_LEVEL2_perm.txt" -Action {
        New-Item -Path "C:\VulnScripts" -ItemType Directory -Force | Out-Null
        icacls "C:\VulnScripts" /grant Everyone:F
    }

    Invoke-VulnAction -Title "PS Remoting diaktifkan tanpa enkripsi" -FlagPath "$flagDir\flag_LEVEL2_psremoting.txt" -Action {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
        Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
    }

    Invoke-VulnAction -Title "Autorun berhasil disimulasikan di registry" -FlagPath "$flagDir\flag_LEVEL2_autorun.txt" -Action {
        $autorunScript = "C:\VulnScripts\runme.bat"
        Set-Content -Path $autorunScript -Value "echo Simulasi autorun >> C:\autorun.log"
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Payload" -Value $autorunScript -PropertyType String -Force
    }

    Invoke-VulnAction -Title "Shortcut HelpPanel berhasil dibuat" -FlagPath "$flagDir\flag_LEVEL2_shortcut.txt" -Action {
        $shortcutPath = "C:\VulnScripts\HelpPanel.lnk"
        $WScriptShell = New-Object -ComObject WScript.Shell
        $shortcut = $WScriptShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
        $shortcut.Save()
    }
}

# =========================
# LEVEL 3 – Advanced Persistence
# =========================

function Exploit-Level3 {
    Invoke-VulnAction -Title "Windows Defender berhasil dinonaktifkan" -FlagPath "$flagDir\flag_LEVEL3_defender.txt" -Action {
        Set-MpPreference -DisableRealtimeMonitoring $true
    }

    Invoke-VulnAction -Title "Payload dan DLL berhasil disimulasikan" -FlagPath "$flagDir\flag_LEVEL3_payload.txt" -Action {
        $scriptPath = "C:\APT_Sim\payload.sct"
        @"
<script language='JScript'>
    var shell = new ActiveXObject('WScript.Shell');
    shell.Run('calc.exe');
</script>
"@ | Out-File -Encoding ASCII -FilePath $scriptPath
    }

    Invoke-VulnAction -Title "WMI Persistence berhasil dibuat" -FlagPath "$flagDir\flag_LEVEL3_wmi.txt" -Action {
        $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
            Name = 'APTFilter'
            EventNamespace = 'root\cimv2'
            QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 0"
        }

        $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
            Name = 'APTConsumer'
            CommandLineTemplate = 'powershell.exe -Command \"Start-Process calc.exe\"'
        }

        $Binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter = $Filter
            Consumer = $Consumer
        }
    }
}

# =========================
# ACHIEVEMENTS
# =========================

function Check-Achievements {
    Invoke-VulnAction -Title "BLUE TEAM Achievement dicapai" -FlagPath "$flagDir\blue_team_achievement.txt" -Action {
        if ((Test-Path "$flagDir\flag_LEVEL1_smbv1.txt") -and 
            (Test-Path "$flagDir\flag_LEVEL2_perm.txt") -and 
            (Test-Path "$flagDir\flag_LEVEL3_wmi.txt")) {
            "BLUE TEAM: Successfully mitigated vulnerabilities at Level 1, 2, and 3. Achievement unlocked." | Out-File -Encoding ASCII "$flagDir\blue_team_achievement.txt"
        }
    }

    Invoke-VulnAction -Title "ATTACKER Achievement dicapai" -FlagPath "$flagDir\attacker_achievement.txt" -Action {
        if ((Test-Path "$flagDir\flag_LEVEL1_smbv1.txt") -and 
            (Test-Path "$flagDir\flag_LEVEL2_perm.txt") -and 
            (Test-Path "$flagDir\flag_LEVEL3_wmi.txt")) {
            "ATTACKER: Successfully exploited vulnerabilities at Level 1, 2, and 3. Achievement unlocked." | Out-File -Encoding ASCII "$flagDir\attacker_achievement.txt"
        }
    }
}

# =========================
# Main Program Flow
# =========================

Initialize-Directories
Exploit-Level1
Exploit-Level2
Exploit-Level3
Check-Achievements

Write-Host "`n[DONE] Simulasi selesai. Cek log di C:\Flags\install_log.txt" -ForegroundColor Yellow
