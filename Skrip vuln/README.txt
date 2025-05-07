
🛠️ Simulasi Kerentanan Windows 10 
==================================

📁 Daftar Skrip
---------------
1. Versi_1.ps1 – Basic Vulnerability Level
2. Versi_2.ps1 – Intermediate Vulnerability Level
3. Versi_3.ps1 – Advanced Vulnerability Level

🔐 VERSI 1 – Basic
------------------
📌 Vuln 1: Guest Account Enabled
- Deskripsi: Mengaktifkan akun tamu (Guest), yang secara default dinonaktifkan di Windows 10.
- Risiko: Siapapun bisa login tanpa autentikasi kredensial kuat.
- Tool eksploitasi: RDP, SMB, local login.
- Remediasi: Jalankan `net user guest /active:no`.

📌 Vuln 2: Remote Desktop Enabled
- Deskripsi: Mengaktifkan RDP yang membuka port TCP 3389.
- Risiko: Dapat diakses attacker untuk brute-force RDP.
- Tool eksploitasi: Hydra, xfreerdp, Ncrack.
- Remediasi: Disable RDP via SystemPropertiesRemote.exe.

📌 Vuln 3: SMBv1 Protocol Diaktifkan
- Deskripsi: Mengaktifkan SMBv1 via registry.
- Risiko: Rentan terhadap eksploitasi EternalBlue (MS17-010).
- Tool eksploitasi: Metasploit (exploit/windows/smb/ms17_010_eternalblue).
- Remediasi: Jalankan `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.

✅ Cara Menjalankan Skrip:
```
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Versi_1.ps1
```

⚠️ VERSI 2 – Intermediate
--------------------------
📌 Vuln 1: UAC Disabled
- Deskripsi: Menonaktifkan User Account Control.
- Risiko: Eksekusi skrip berbahaya tanpa prompt.
- Tool eksploitasi: MalDocs, PowerShell Empire.
- Remediasi: Ubah registry EnableLUA ke 1.

📌 Vuln 2: Windows Defender Disabled
- Deskripsi: Mematikan real-time protection.
- Risiko: Sistem tidak mendeteksi malware/script.
- Tool eksploitasi: Shellter, msfvenom payloads.
- Remediasi: Jalankan `Set-MpPreference -DisableRealtimeMonitoring $false`.

📌 Vuln 3: Firewall Disabled
- Deskripsi: Mematikan Windows Firewall semua profile.
- Risiko: Lalu lintas jaringan tidak difilter.
- Tool eksploitasi: Nmap, Netcat, Meterpreter.
- Remediasi: Jalankan `Set-NetFirewallProfile -Enabled True`.

✅ Cara Menjalankan Skrip:
```
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Versi_2.ps1
```

☠️ VERSI 3 – Advanced
----------------------
📌 Vuln 1: Membuat User Admin Backdoor
- Deskripsi: Menambahkan user admin2 dan memasukkannya ke grup Administrators.
- Risiko: Privilege escalation permanen.
- Tool eksploitasi: RDP, remote shell login.
- Remediasi: Jalankan `net user admin2 /delete`.

📌 Vuln 2: Registry Allow RDP Null Sessions
- Deskripsi: Mengubah registry untuk memperbolehkan koneksi RDP tanpa autentikasi penuh.
- Risiko: RDP bisa diakses tanpa kredensial.
- Tool eksploitasi: Rdesktop, xfreerdp tanpa password.
- Remediasi: Set registry DisablePasswordSaving dan AllowSavedCredentialsWhenNTLMOnly ke 0.

📌 Vuln 3: File Sharing Tanpa Password
- Deskripsi: Mengizinkan akses file sharing tanpa login.
- Risiko: Data bisa dicuri tanpa autentikasi.
- Tool eksploitasi: SMBClient, metasploit modules.
- Remediasi: Atur HKLM\SYSTEM\CurrentControlSet\Control\Lsa → LimitBlankPasswordUse = 1.

✅ Cara Menjalankan Skrip:
```
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Versi_3.ps1
```

🔁 Alur Penyelesaian Umum
--------------------------
1. Identifikasi vuln via Wazuh – Misalnya dari event log, registry change, service status.
2. Koreksi manual atau otomatis via policy/script.
3. Verifikasi dengan `Get-ItemProperty`, `netsh advfirewall`, atau `Get-MpPreference`.
4. Reboot jika registry critical diubah.

🧰 Tools Kali Linux untuk Eksploitasi
--------------------------------------
Berikut adalah tools yang umum digunakan attacker untuk mengeksploitasi kerentanan pada skrip ini:

- 🔍 Nmap: Pemindaian port dan identifikasi layanan.
- 🛠️ Metasploit Framework: Eksploitasi SMBv1, privilege escalation, dll.
- 🧪 Hydra / Ncrack: Brute-force RDP, SMB, dan login protokol lainnya.
- 📡 xfreerdp / rdesktop: Remote desktop exploit.
- 🐚 Netcat (nc): Reverse shell atau koneksi langsung ke port.
- 💣 msfvenom: Payload generator untuk menyisipkan malware via backdoor.
- 🧬 PowerShell Empire: Remote command execution dan post-exploitation framework.
- 💼 SMBClient: Akses SMB share tanpa autentikasi.
- 📄 Shellter: Membuat executable backdoor dari file legitimate.
