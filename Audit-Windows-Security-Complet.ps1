$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$baseDir = "C:\script_audit\Resultats"
$auditDir = Join-Path $baseDir "Audit-$timestamp"
@("Systeme", "Comptes", "ActiveDirectory", "Authentification", "Reseau", "Services", "SecuritOS", "Journalisation") | ForEach-Object {
    New-Item -Path (Join-Path $auditDir $_) -ItemType Directory -Force | Out-Null
}
Write-Host "[*] Audit demarre: $auditDir" -ForegroundColor Cyan

# ============================================================================
# SECTION 1: AUDIT SYSTEME
# ============================================================================
Write-Host "[*] Audit systeme..." -ForegroundColor Cyan
$systemDir = Join-Path $auditDir "Systeme"
$osInfo = Get-CimInstance Win32_OperatingSystem

@"
=== INFORMATIONS SYSTEME ===
Nom: $($osInfo.Caption)
Version: $($osInfo.Version)
Build: $($osInfo.BuildNumber)
Architecture: $($osInfo.OSArchitecture)
Installation: $($osInfo.InstallDate)
Dernier boot: $($osInfo.LastBootUpTime)
"@ | Out-File "$systemDir\os_info.txt" -Encoding UTF8

Get-HotFix | Select-Object HotFixID, Description, InstalledOn | Export-Csv "$systemDir\hotfixes.csv" -NoTypeInformation -Encoding UTF8

$uptime = (Get-Date) - $osInfo.LastBootUpTime
"Uptime: $($uptime.Days) jours, $($uptime.Hours) heures" | Out-File "$systemDir\uptime.txt"

Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, VolumeStatus | Export-Csv "$systemDir\bitlocker.csv" -NoTypeInformation -Encoding UTF8

# ============================================================================
# SECTION 2: COMPTES LOCAUX & PRIVILEGES
# ============================================================================
Write-Host "[*] Audit comptes..." -ForegroundColor Cyan
$comptesDir = Join-Path $auditDir "Comptes"

Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordExpires, PasswordLastSet, LastLogon | Export-Csv "$comptesDir\local_users.csv" -NoTypeInformation -Encoding UTF8

Get-LocalGroup | Select-Object Name, Description | Export-Csv "$comptesDir\local_groups.csv" -NoTypeInformation -Encoding UTF8

Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass | Export-Csv "$comptesDir\administrators.csv" -NoTypeInformation -Encoding UTF8

# Verifier comptes desactives
$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
$guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
@"
=== VERIFICATION COMPTES PRIVILEGIES ===
Administrateur actif: $($adminAccount.Enabled)
Guest actif: $($guestAccount.Enabled)
"@ | Out-File "$comptesDir\privileged_accounts.txt" -Encoding UTF8

$uac = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
@"
=== UAC CONFIGURATION ===
EnableLUA: $($uac.EnableLUA)
ConsentPromptBehaviorAdmin: $($uac.ConsentPromptBehaviorAdmin)
PromptOnSecureDesktop: $($uac.PromptOnSecureDesktop)
FilterAdministratorToken: $($uac.FilterAdministratorToken)
"@ | Out-File "$comptesDir\uac.txt" -Encoding UTF8

net accounts | Out-File "$comptesDir\password_policy.txt" -Encoding UTF8

# ============================================================================
# SECTION 3: ACTIVE DIRECTORY
# ============================================================================
Write-Host "[*] Audit Active Directory..." -ForegroundColor Cyan
$adDir = Join-Path $auditDir "ActiveDirectory"

$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4

if ($isDC) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    if (Get-Module ActiveDirectory) {
        $domain = Get-ADDomain
        @"
=== DOMAINE AD ===
Nom: $($domain.DNSRoot)
NetBIOS: $($domain.NetBIOSName)
Niveau: $($domain.DomainMode)
"@ | Out-File "$adDir\domain_info.txt" -Encoding UTF8

        Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem, IPv4Address | Export-Csv "$adDir\domain_controllers.csv" -NoTypeInformation -Encoding UTF8

        Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, LastLogonDate | Select-Object Name, Enabled, PasswordLastSet, LastLogonDate | Export-Csv "$adDir\ad_users.csv" -NoTypeInformation -Encoding UTF8

        Get-ADGroupMember "Domain Admins" | Select-Object Name | Export-Csv "$adDir\domain_admins.csv" -NoTypeInformation -Encoding UTF8
    }
} else {
    "Machine non DC" | Out-File "$adDir\not_dc.txt"
}

# ============================================================================
# SECTION 4: AUTHENTIFICATION
# ============================================================================
Write-Host "[*] Audit authentification..." -ForegroundColor Cyan
$authDir = Join-Path $auditDir "Authentification"

# NTLM
$ntlm = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
@"
=== NTLM CONFIGURATION ===
LMCompatibilityLevel: $($ntlm.LmCompatibilityLevel)
NoLMHash: $($ntlm.NoLMHash)
"@ | Out-File "$authDir\ntlm.txt" -Encoding UTF8

# Base SAM
$samDB = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
@"
=== SECURITE BASE SAM ===
NoLMHash: $($samDB.NoLMHash)
RestrictAnonymous: $($samDB.RestrictAnonymous)
EveryoneIncludesAnonymous: $($samDB.EveryoneIncludesAnonymous)
ForceGuest: $($samDB.ForceGuest)
"@ | Out-File "$authDir\sam_security.txt" -Encoding UTF8

# Parametres LSA avances
$lsaParams = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
@"
=== PARAMETRES LSA AVANCES ===
RunAsPPL: $($lsaParams.RunAsPPL)
DisableRestrictedAdmin: $($lsaParams.DisableRestrictedAdmin)
NullSessionPipes: $($lsaParams.NullSessionPipes)
"@ | Out-File "$authDir\lsa_advanced.txt" -Encoding UTF8

# WDigest
$wdigest = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue
"WDigest UseLogonCredential: $($wdigest.UseLogonCredential)" | Out-File "$authDir\wdigest.txt" -Encoding UTF8

# LAPS
$laps = Get-ItemProperty "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
if ($laps) { 
    "LAPS: Active" | Out-File "$authDir\laps.txt" 
} else { 
    "LAPS: Non configure" | Out-File "$authDir\laps.txt" 
}

# Credential Guard
$deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
"Credential Guard: $($deviceGuard.SecurityServicesRunning -join ', ')" | Out-File "$authDir\credential_guard.txt"

# Passport/Windows Hello
$passport = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue
@"
=== AUTHENTIFICATION BIOMETRIQUE ===
PassportForWork Enabled: $($passport.Enabled)
UsePassportForWork: $($passport.UsePassportForWork)
"@ | Out-File "$authDir\passport_biometric.txt" -Encoding UTF8

# ============================================================================
# SECTION 5: RESEAU
# ============================================================================
Write-Host "[*] Audit reseau..." -ForegroundColor Cyan
$reseauDir = Join-Path $auditDir "Reseau"

Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Export-Csv "$reseauDir\firewall_profiles.csv" -NoTypeInformation -Encoding UTF8

Get-NetFirewallRule -Enabled True | Where-Object Direction -eq "Inbound" | Select-Object Name, DisplayName, Action | Export-Csv "$reseauDir\firewall_rules.csv" -NoTypeInformation -Encoding UTF8

Get-NetAdapter | Select-Object Name, Status, MacAddress | Export-Csv "$reseauDir\network_adapters.csv" -NoTypeInformation -Encoding UTF8

$smbServer = Get-SmbServerConfiguration
@"
=== SMB CONFIGURATION ===
EnableSMB1Protocol: $($smbServer.EnableSMB1Protocol)
EncryptData: $($smbServer.EncryptData)
RequireSecuritySignature: $($smbServer.RequireSecuritySignature)
EnableSecuritySignature: $($smbServer.EnableSecuritySignature)
"@ | Out-File "$reseauDir\smb_config.txt" -Encoding UTF8

Get-SmbShare | Select-Object Name, Path | Export-Csv "$reseauDir\smb_shares.csv" -NoTypeInformation -Encoding UTF8

# LLMNR et NetBIOS
$llmnr = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
$netbios = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters" -ErrorAction SilentlyContinue
@"
=== PROTOCOLES MULTICAST ===
LLMNR Enabled: $($llmnr.EnableMulticast)
NetBIOS NoNameReleaseOnDemand: $($netbios.NoNameReleaseOnDemand)
"@ | Out-File "$reseauDir\multicast_protocols.txt" -Encoding UTF8

# IPv6
$ipv6 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ErrorAction SilentlyContinue
"IPv6 DisabledComponents: $($ipv6.DisabledComponents)" | Out-File "$reseauDir\ipv6_status.txt" -Encoding UTF8

# ============================================================================
# SECTION 6: SERVICES
# ============================================================================
Write-Host "[*] Audit services..." -ForegroundColor Cyan
$servicesDir = Join-Path $auditDir "Services"

Get-Service | Where-Object Status -eq "Running" | Select-Object Name, DisplayName, StartType | Export-Csv "$servicesDir\running_services.csv" -NoTypeInformation -Encoding UTF8

$rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$rdpNLA = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
@"
=== RDP CONFIGURATION ===
fDenyTSConnections: $($rdp.fDenyTSConnections)
SecurityLayer: $($rdpNLA.SecurityLayer)
UserAuthentication: $($rdpNLA.UserAuthentication)
MinEncryptionLevel: $($rdpNLA.MinEncryptionLevel)
"@ | Out-File "$servicesDir\rdp_config.txt" -Encoding UTF8

# Restricted Admin pour RDP
$rdpRestrictedAdmin = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\LSA" -ErrorAction SilentlyContinue
"RDP DisableRestrictedAdmin: $($rdpRestrictedAdmin.DisableRestrictedAdmin)" | Out-File "$servicesDir\rdp_restricted_admin.txt"

$winrm = Get-Service WinRM
"WinRM: $($winrm.Status) - $($winrm.StartType)" | Out-File "$servicesDir\winrm.txt"

# Configuration WinRM
winrm get winrm/config 2>$null | Out-File "$servicesDir\winrm_config.txt" -Encoding UTF8

Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Export-Csv "$servicesDir\listening_ports.csv" -NoTypeInformation -Encoding UTF8

# Autorun USB
$usbAutorun = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue
"USB AutoRun NoDriveTypeAutoRun: $($usbAutorun.NoDriveTypeAutoRun)" | Out-File "$servicesDir\usb_autorun.txt" -Encoding UTF8

# ============================================================================
# SECTION 7: SECURITE OS
# ============================================================================
Write-Host "[*] Audit securite OS..." -ForegroundColor Cyan
$secuDir = Join-Path $auditDir "SecuritOS"

$lsass = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
@"
=== LSASS PROTECTION ===
RunAsPPL: $($lsass.RunAsPPL)
"@ | Out-File "$secuDir\lsass.txt" -Encoding UTF8

$defender = Get-MpPreference
@"
=== WINDOWS DEFENDER ===
DisableRealtimeMonitoring: $($defender.DisableRealtimeMonitoring)
DisableBehaviorMonitoring: $($defender.DisableBehaviorMonitoring)
DisableIOAVProtection: $($defender.DisableIOAVProtection)
"@ | Out-File "$secuDir\defender.txt" -Encoding UTF8

$secureBoot = Confirm-SecureBootUEFI
"Secure Boot: $secureBoot" | Out-File "$secuDir\secure_boot.txt" -Encoding UTF8

$psPolicy = Get-ExecutionPolicy
"PowerShell Execution Policy: $psPolicy" | Out-File "$secuDir\powershell_execution_policy.txt" -Encoding UTF8

Get-AppLockerPolicy -Effective -Xml | Out-File "$secuDir\applocker.xml" -Encoding UTF8

# BitLocker
$bitlocker = Get-BitLockerVolume
@"
=== BITLOCKER STATUS ===
$($bitlocker | ForEach-Object { "Volume: $($_.MountPoint) - Status: $($_.VolumeStatus)" } -join "`n")
"@ | Out-File "$secuDir\bitlocker_status.txt" -Encoding UTF8

# ============================================================================
# SECTION 8: JOURNALISATION
# ============================================================================
Write-Host "[*] Audit journalisation..." -ForegroundColor Cyan
$logDir = Join-Path $auditDir "Journalisation"

auditpol /get /category:* | Out-File "$logDir\auditpol.txt" -Encoding UTF8

Get-WinEvent -ListLog Application, System, Security -ErrorAction SilentlyContinue | Select-Object LogName, RecordCount, IsLogFull | Export-Csv "$logDir\eventlogs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName Security -MaxEvents 1000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv "$logDir\security_events.csv" -NoTypeInformation -Encoding UTF8

$sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($sysmon) {
    "Sysmon: Installe - Status: $($sysmon.Status)" | Out-File "$logDir\sysmon.txt"
} else {
    "Sysmon: Non installe" | Out-File "$logDir\sysmon.txt"
}

# Mises a jour
$wsus = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
@"
=== CONFIGURATION WSUS ===
WUServer: $($wsus.WUServer)
UseWUServer: $($wsus.UseWUServer)
"@ | Out-File "$logDir\wsus_config.txt" -Encoding UTF8

# ============================================================================
# SECTION 9: APPLICATIONS ET CONFIGURATIONS
# ============================================================================
Write-Host "[*] Audit applications..." -ForegroundColor Cyan
$appDir = Join-Path $auditDir "Applications"
New-Item -Path $appDir -ItemType Directory -Force | Out-Null

Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate | Export-Csv "$appDir\installed_applications.csv" -NoTypeInformation -Encoding UTF8

# ============================================================================
# RESUME
# ============================================================================
Write-Host "[*] Generation resume..." -ForegroundColor Cyan
$fileCount = (Get-ChildItem -Path $auditDir -Recurse -File).Count
@"
=== RESUME AUDIT ===
Date: $(Get-Date)
Fichiers generes: $fileCount
Repertoire: $auditDir
"@ | Out-File "$auditDir\RESUME.txt" -Encoding UTF8

Write-Host "[+] Audit termine !" -ForegroundColor Green
Write-Host "[+] Resultats: $auditDir" -ForegroundColor Green
