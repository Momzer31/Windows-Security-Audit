$basePath = "C:\Users\compt\Desktop\audit_results"
# Trouver le dernier dossier Audit-*
$latestAudit = Get-ChildItem -Path $basePath -Directory -Filter "Audit-*" | Sort-Object Name -Descending | Select-Object -First 1
if ($latestAudit) {
    $auditDir = $latestAudit.FullName
} else {
    $auditDir = $basePath
}

$htmlFile = "$basePath\rapport_audit_anssi_complet.html"
$pdfFile = "$basePath\rapport_audit_anssi_complet.pdf"

# Lire les donnees
$osInfo = (Get-Content "$auditDir\Systeme\os_info.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$uptime = (Get-Content "$auditDir\Systeme\uptime.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$hotfixes = Import-Csv "$auditDir\Systeme\hotfixes.csv" -ErrorAction SilentlyContinue
$bitlockerStatus = (Get-Content "$auditDir\SecuritOS\bitlocker_status.txt" -Raw -ErrorAction SilentlyContinue).Trim()

$localUsers = Import-Csv "$auditDir\Comptes\local_users.csv" -ErrorAction SilentlyContinue
$admins = Import-Csv "$auditDir\Comptes\administrators.csv" -ErrorAction SilentlyContinue
$privilegedAccounts = (Get-Content "$auditDir\Comptes\privileged_accounts.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$uac = (Get-Content "$auditDir\Comptes\uac.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$passwordPolicy = (Get-Content "$auditDir\Comptes\password_policy.txt" -Raw -ErrorAction SilentlyContinue).Trim()

$ntlm = (Get-Content "$auditDir\Authentification\ntlm.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$samSecurity = (Get-Content "$auditDir\Authentification\sam_security.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$lsaAdvanced = (Get-Content "$auditDir\Authentification\lsa_advanced.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$wdigest = (Get-Content "$auditDir\Authentification\wdigest.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$laps = (Get-Content "$auditDir\Authentification\laps.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$credGuard = (Get-Content "$auditDir\Authentification\credential_guard.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$passportBiometric = (Get-Content "$auditDir\Authentification\passport_biometric.txt" -Raw -ErrorAction SilentlyContinue).Trim()

$firewallProfiles = Import-Csv "$auditDir\Reseau\firewall_profiles.csv" -ErrorAction SilentlyContinue
$smbConfig = (Get-Content "$auditDir\Reseau\smb_config.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$multicastProtocols = (Get-Content "$auditDir\Reseau\multicast_protocols.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$ipv6Status = (Get-Content "$auditDir\Reseau\ipv6_status.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$smbShares = Import-Csv "$auditDir\Reseau\smb_shares.csv" -ErrorAction SilentlyContinue

$runningServices = Import-Csv "$auditDir\Services\running_services.csv" -ErrorAction SilentlyContinue
$rdp = (Get-Content "$auditDir\Services\rdp_config.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$rdpRestrictedAdmin = (Get-Content "$auditDir\Services\rdp_restricted_admin.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$winrm = (Get-Content "$auditDir\Services\winrm.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$usbAutorun = (Get-Content "$auditDir\Services\usb_autorun.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$listeningPorts = Import-Csv "$auditDir\Services\listening_ports.csv" -ErrorAction SilentlyContinue

$lsass = (Get-Content "$auditDir\SecuritOS\lsass.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$defender = (Get-Content "$auditDir\SecuritOS\defender.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$secureBoot = (Get-Content "$auditDir\SecuritOS\secure_boot.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$psPolicy = (Get-Content "$auditDir\SecuritOS\powershell_execution_policy.txt" -Raw -ErrorAction SilentlyContinue).Trim()

$auditpol = (Get-Content "$auditDir\Journalisation\auditpol.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$wsusConfig = (Get-Content "$auditDir\Journalisation\wsus_config.txt" -Raw -ErrorAction SilentlyContinue).Trim()
$sysmon = (Get-Content "$auditDir\Journalisation\sysmon.txt" -Raw -ErrorAction SilentlyContinue).Trim()

# SCORING ET FINDINGS COMPLET ANSSI
$findings = @()
$totalScore = 0
$maxScore = 0

# === COMPTES ET IDENTITES ===

# Check 1: Comptes Admin/Guest desactives
$maxScore += 10
if ($privilegedAccounts -match "Administrator.*False" -or $privilegedAccounts -match "Guest.*False") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "CRITIQUE"
        Title = "Comptes Administrator ou Guest actifs"
        Description = "Les comptes privilegies par defaut ne sont pas desactives. Risque d'acces non autorise."
        Remediation = "Disable-LocalUser -Name Administrator`nDisable-LocalUser -Name Guest"
        CVSS = 8.0
        Category = "Comptes"
    }
}

# Check 2: UAC - EnableLUA
$maxScore += 10
if ($uac -match "EnableLUA: 1") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "CRITIQUE"
        Title = "UAC desactive"
        Description = "User Account Control est desactive. Elevation de privileges facile pour malwares."
        Remediation = "Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
        CVSS = 8.5
        Category = "Comptes"
    }
}

# Check 3: UAC - ConsentPromptBehaviorAdmin
$maxScore += 5
if ($uac -match "ConsentPromptBehaviorAdmin: 1" -or $uac -match "ConsentPromptBehaviorAdmin: 2") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "UAC ConsentPromptBehaviorAdmin faible"
        Description = "Niveau de notification UAC insuffisant pour les administrateurs."
        Remediation = "Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 1"
        CVSS = 6.0
        Category = "Comptes"
    }
}

# Check 4: LAPS configuration
$maxScore += 10
if ($laps -notmatch "Non configure") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "LAPS non configure"
        Description = "Local Admin Password Solution absent. Mots de passe admin non geres."
        Remediation = "# Installer LAPS depuis Microsoft`n# Configurer via GPO ou registre`nSet-ItemProperty 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -Name AdmPwdEnabled -Value 1"
        CVSS = 7.5
        Category = "Comptes"
    }
}

# Check 5: Restrict Anonymous
$maxScore += 5
if ($samSecurity -match "RestrictAnonymous: [1-9]") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "RestrictAnonymous non configure"
        Description = "Acces anonyme trop permissif au registre et partages."
        Remediation = "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1"
        CVSS = 6.5
        Category = "Comptes"
    }
}

# Check 6: NoLMHash
$maxScore += 5
if ($samSecurity -match "NoLMHash: 1") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "Base SAM stocke les hashes LM"
        Description = "LM Hashes actifs. Faiblesse cryptographique permettant les attaques offline."
        Remediation = "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1"
        CVSS = 7.0
        Category = "Comptes"
    }
}

# === AUTHENTIFICATION ===

# Check 7: LSASS Protection (RunAsPPL)
$maxScore += 10
if ($lsass -match "RunAsPPL: 1" -or $lsass -match "RunAsPPL: 2") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "LSASS Protection desactivee"
        Description = "RunAsPPL non active. Risque d'extraction de credentials via mimikatz."
        Remediation = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL /t REG_DWORD /d 1 /f`nREDEMARRAGE REQUIS"
        CVSS = 8.5
        Category = "Authentification"
    }
}

# Check 8: WDigest
$maxScore += 5
if ($wdigest -match "UseLogonCredential: 0" -or $wdigest -eq "WDigest UseLogonCredential: " -or [string]::IsNullOrWhiteSpace($wdigest)) {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "WDigest stocke les mots de passe en clair"
        Description = "WDigest peut extraire les mots de passe en memoire."
        Remediation = "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
        CVSS = 7.0
        Category = "Authentification"
    }
}

# Check 9: Credential Guard
$maxScore += 5
if ($credGuard -match "CredentialGuard") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MINEUR"
        Title = "Credential Guard non active"
        Description = "Protection avancee des credentials non activee."
        Remediation = "# Hypervisor-Protected Code Integrity requis`nReg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' /v Enabled /t REG_DWORD /d 1 /f"
        CVSS = 4.5
        Category = "Authentification"
    }
}

# Check 10: Passport/Windows Hello
$maxScore += 3
if ($passportBiometric -match "PassportForWork Enabled: 1" -or $passportBiometric -match "UsePassportForWork: 1") {
    $totalScore += 3
} else {
    $findings += [PSCustomObject]@{
        Severity = "MINEUR"
        Title = "Windows Hello/Passport non configure"
        Description = "Authentification biometrique ou PIN non active."
        Remediation = "# Windows Hello requiert une TPM 2.0 ou capteur biometrique"
        CVSS = 2.0
        Category = "Authentification"
    }
}

# === RESEAU ET SERVICES ===

# Check 11: Firewall actif
$maxScore += 10
$fwEnabled = $firewallProfiles | Where-Object { $_.Enabled -eq "True" }
if ($fwEnabled.Count -eq 3) {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "CRITIQUE"
        Title = "Firewall Windows desactive"
        Description = "Pare-feu desactive sur un ou plusieurs profils. Exposition reseau totale."
        Remediation = "Set-NetFirewallProfile -All -Enabled True"
        CVSS = 9.5
        Category = "Reseau"
    }
}

# Check 12: SMBv1 desactive
$maxScore += 10
if ($smbConfig -match "EnableSMB1Protocol: False") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "CRITIQUE"
        Title = "SMBv1 active"
        Description = "SMBv1 actif. Vulnerabilite EternalBlue critique. Exposition au ransomware."
        Remediation = "Disable-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -NoRestart"
        CVSS = 9.8
        Category = "Reseau"
    }
}

# Check 13: SMB Signature requise
$maxScore += 5
if ($smbConfig -match "RequireSecuritySignature: True") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "Signature SMB non requise"
        Description = "Communications SMB non signees. Risque d'interception et modification."
        Remediation = "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
        CVSS = 6.5
        Category = "Reseau"
    }
}

# Check 14: RDP avec NLA
$maxScore += 10
if ($rdp -match "UserAuthentication: 1") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "RDP sans Network Level Authentication"
        Description = "RDP vulnerable aux attaques brute-force sans NLA."
        Remediation = "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        CVSS = 8.0
        Category = "Reseau"
    }
}

# Check 15: RDP SecurityLayer TLS
$maxScore += 5
if ($rdp -match "SecurityLayer: 2") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "RDP SecurityLayer non TLS"
        Description = "RDP n'utilise pas le chiffrement TLS. Communications non securisees."
        Remediation = "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -Value 2"
        CVSS = 7.0
        Category = "Reseau"
    }
}

# Check 16: RDP Restricted Admin
$maxScore += 5
if ($rdpRestrictedAdmin -match "DisableRestrictedAdmin: 0" -or [string]::IsNullOrWhiteSpace($rdpRestrictedAdmin)) {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MINEUR"
        Title = "RDP Restricted Admin desactive"
        Description = "Mode Restricted Admin non active. Risque de Pass-The-Hash via RDP."
        Remediation = "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -Value 0"
        CVSS = 4.0
        Category = "Reseau"
    }
}

# Check 17: LLMNR desactive
$maxScore += 5
if ($multicastProtocols -match "LLMNR Enabled: 0") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "LLMNR actif (spoofing DNS possible)"
        Description = "LLMNR non desactif. Risque de spoofing et MITM."
        Remediation = "Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0"
        CVSS = 6.0
        Category = "Reseau"
    }
}

# Check 18: NetBIOS securise
$maxScore += 3
if ($multicastProtocols -match "NetBIOS NoNameReleaseOnDemand: 1") {
    $totalScore += 3
} else {
    $findings += [PSCustomObject]@{
        Severity = "MINEUR"
        Title = "NetBIOS Name Release trop permissif"
        Description = "Risque de spoofing NetBIOS."
        Remediation = "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters' -Name NoNameReleaseOnDemand -Value 1"
        CVSS = 3.0
        Category = "Reseau"
    }
}

# Check 19: IPv6 desactive si non utilise
$maxScore += 3
if ($ipv6Status -match "DisabledComponents: 0xFF") {
    $totalScore += 3
} else {
    $findings += [PSCustomObject]@{
        Severity = "MINEUR"
        Title = "IPv6 actif (si non utilise)"
        Description = "IPv6 peut creer des vecteurs d'attaque inutiles si non utilise."
        Remediation = "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -Value 0xFF"
        CVSS = 2.5
        Category = "Reseau"
    }
}

# Check 20: USB Autorun desactive
$maxScore += 5
if ($usbAutorun -match "NoDriveTypeAutoRun: 0xFF" -or $usbAutorun -match "NoDriveTypeAutoRun: 255") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "USB Autorun actif"
        Description = "Risque d'infection par cles USB compromises."
        Remediation = "Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255"
        CVSS = 6.5
        Category = "Reseau"
    }
}

# === SECURITE OS ===

# Check 21: Windows Defender actif
$maxScore += 10
if ($defender -match "DisableRealtimeMonitoring: False") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "CRITIQUE"
        Title = "Windows Defender desactive"
        Description = "Protection antivirus absente. Exposition totale aux malwares."
        Remediation = "Set-MpPreference -DisableRealtimeMonitoring `$false"
        CVSS = 9.0
        Category = "Securite"
    }
}

# Check 22: Secure Boot
$maxScore += 10
if ($secureBoot -match "True") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "Secure Boot desactive ou non supporte"
        Description = "Risque de rootkit au demarrage sans Secure Boot."
        Remediation = "# ACTION MANUELLE: Redemarrer sur UEFI/BIOS et activer Secure Boot"
        CVSS = 7.5
        Category = "Securite"
    }
}

# Check 23: BitLocker
$maxScore += 10
if ($bitlockerStatus -match "Full" -or $bitlockerStatus -match "Used Space") {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "BitLocker non active"
        Description = "Disque non chiffre. Donnees sensibles accessibles sans protection."
        Remediation = "Enable-BitLocker -MountPoint C: -EncryptionMethod Aes256 -UsedSpaceOnly"
        CVSS = 8.0
        Category = "Securite"
    }
}

# Check 24: Ports dangereux
$maxScore += 10
$dangerousPorts = $listeningPorts | Where-Object { $_.LocalPort -in @("139", "445", "5985", "5986") }
if ($dangerousPorts.Count -eq 0) {
    $totalScore += 10
} else {
    $findings += [PSCustomObject]@{
        Severity = "MAJEUR"
        Title = "Ports sensibles exposes"
        Description = "SMB, WinRM exposes. Risque de pivots lateraux et attaques."
        Remediation = "New-NetFirewallRule -DisplayName 'Block Dangerous Ports' -Direction Inbound -Protocol TCP -LocalPort 139,445,5985,5986 -Action Block -Profile Public"
        CVSS = 8.5
        Category = "Securite"
    }
}

# === JOURNALISATION ===

# Check 25: Sysmon installe
$maxScore += 5
if ($sysmon -notmatch "Non installe") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MINEUR"
        Title = "Sysmon non installe"
        Description = "Journalisation avancee absente. Visibilite limitee."
        Remediation = "# Telecharger Sysmon depuis Microsoft`nSysmon64.exe -i -n -l"
        CVSS = 3.5
        Category = "Journalisation"
    }
}

# Check 26: WSUS configure
$maxScore += 5
if (-not [string]::IsNullOrWhiteSpace($wsusConfig) -and $wsusConfig -notmatch "WUServer: " -or $wsusConfig -match "WUServer: ") {
    $totalScore += 5
} else {
    $findings += [PSCustomObject]@{
        Severity = "MINEUR"
        Title = "WSUS non configure"
        Description = "Serveur de mise a jour non configure. Mises a jour non centralisees."
        Remediation = "# Configurer WSUS via GPO ou registre"
        CVSS = 2.0
        Category = "Journalisation"
    }
}

# Calcul score final
$scorePercent = [Math]::Round(($totalScore / $maxScore) * 100)
$scoreColor = if ($scorePercent -ge 80) { "#3fb950" } elseif ($scorePercent -ge 50) { "#f85149" } else { "#da3633" }
$scoreLabel = if ($scorePercent -ge 80) { "BON" } elseif ($scorePercent -ge 50) { "MOYEN" } else { "FAIBLE" }

# Compter par severite
$criticalCount = ($findings | Where-Object Severity -eq "CRITIQUE").Count
$majorCount = ($findings | Where-Object Severity -eq "MAJEUR").Count
$minorCount = ($findings | Where-Object Severity -eq "MINEUR").Count

# Generer tables
$hotfixesTable = if ($hotfixes) { $hotfixes | Select-Object -First 10 | ConvertTo-Html -Fragment } else { "<p>Aucun hotfix</p>" }
$usersTable = if ($localUsers) { $localUsers | ConvertTo-Html -Fragment } else { "<p>Aucun utilisateur</p>" }
$adminsTable = if ($admins) { $admins | ConvertTo-Html -Fragment } else { "<p>Aucun admin</p>" }
$firewallTable = if ($firewallProfiles) { $firewallProfiles | ConvertTo-Html -Fragment } else { "<p>Aucun profil firewall</p>" }
$servicesTable = if ($runningServices) { $runningServices | Select-Object -First 20 | ConvertTo-Html -Fragment } else { "<p>Aucun service</p>" }
$portsTable = if ($listeningPorts) { $listeningPorts | ConvertTo-Html -Fragment } else { "<p>Aucun port</p>" }

# Generer findings HTML avec echappement
$findingsHtml = ""
foreach ($finding in $findings | Sort-Object CVSS -Descending) {
    $severityClass = switch ($finding.Severity) {
        "CRITIQUE" { "badge-critical" }
        "MAJEUR" { "badge-major" }
        "MINEUR" { "badge-minor" }
    }
    
    $remedTitle = [System.Security.SecurityElement]::Escape($finding.Remediation)
    
    $findingsHtml += @"
        <div class="finding finding-$($finding.Severity.ToLower())">
            <div class="finding-header">
                <span class="finding-category">[$($finding.Category)]</span>
                <span class="finding-title">$($finding.Title)</span>
                <span class="finding-badge $severityClass">$($finding.Severity)</span>
                <span class="finding-badge badge-cvss">CVSS $($finding.CVSS)</span>
            </div>
            <div class="finding-content">
                <p><strong>Description:</strong> $($finding.Description)</p>
                <p><strong>Remediation:</strong></p>
                <pre>$remedTitle</pre>
            </div>
        </div>
"@
}

$timestamp = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>Rapport Audit Securite ANSSI Complet</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        header { background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border-bottom: 4px solid #da3633; padding: 30px; text-align: center; margin-bottom: 30px; border-radius: 8px; }
        h1 { color: #da3633; font-size: 2.2em; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; }
        h2 { color: #da3633; margin: 20px 0 15px 0; font-size: 1.4em; border-bottom: 2px solid #da3633; padding-bottom: 10px; }
        .subtitle { color: #58a6ff; font-size: 0.9em; margin-top: 10px; }
        .container { max-width: 1400px; margin: 0 auto; }
        
        /* SCORE */
        .score-container { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); padding: 40px; margin: 30px 0; border-radius: 8px; border: 3px solid $scoreColor; text-align: center; }
        .score-circle { width: 220px; height: 220px; border-radius: 50%; border: 12px solid $scoreColor; display: inline-flex; align-items: center; justify-content: center; flex-direction: column; margin: 20px; }
        .score-number { font-size: 4em; font-weight: bold; color: $scoreColor; }
        .score-label { font-size: 1.3em; color: #8b949e; margin-top: 10px; }
        .score-status { font-size: 1.6em; color: $scoreColor; font-weight: bold; margin-top: 15px; }
        
        /* STATS */
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-box { background: #161b22; padding: 25px; border-radius: 4px; text-align: center; border-left: 5px solid #da3633; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
        .stat-number { font-size: 2.8em; font-weight: bold; margin: 10px 0; }
        .stat-label { color: #8b949e; font-size: 0.95em; }
        .critical { color: #da3633; }
        .major { color: #f85149; }
        .minor { color: #f1c40f; }
        
        /* FINDINGS */
        .finding { background: #161b22; border-left: 5px solid; margin: 15px 0; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
        .finding-critique { border-left-color: #da3633; }
        .finding-majeur { border-left-color: #f85149; }
        .finding-mineur { border-left-color: #f1c40f; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; padding: 15px; background: #0d1117; border-radius: 4px 4px 0 0; flex-wrap: wrap; gap: 10px; }
        .finding-category { background: #30363d; color: #58a6ff; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }
        .finding-title { flex-grow: 1; font-weight: bold; font-size: 1.1em; }
        .finding-badge { padding: 4px 12px; border-radius: 3px; font-weight: bold; margin-left: 10px; font-size: 0.85em; }
        .badge-critical { background: #da3633; color: white; }
        .badge-major { background: #f85149; color: white; }
        .badge-minor { background: #f1c40f; color: #0d1117; }
        .badge-cvss { background: #30363d; color: #da3633; }
        .finding-content { padding: 15px; border-top: 1px solid #30363d; }
        .finding-content p { margin: 10px 0; }
        
        /* SECTIONS */
        .section { background: #161b22; padding: 20px; margin: 20px 0; border-left: 5px solid #da3633; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
        .section h3 { color: #58a6ff; margin: 15px 0 10px 0; font-size: 1.1em; }
        pre { background: #0d1117; padding: 15px; border-radius: 4px; overflow-x: auto; border: 1px solid #30363d; font-size: 0.9em; white-space: pre-wrap; word-break: break-word; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 0.85em; }
        th { background: #0d1117; color: #da3633; padding: 10px; text-align: left; border-bottom: 2px solid #da3633; }
        td { padding: 8px; border-bottom: 1px solid #30363d; }
        tr:hover { background: #1c2128; }
    </style>
</head>
<body>
    <header>
        <h1>RAPPORT AUDIT SECURITE ANSSI COMPLET</h1>
        <div class="subtitle">Audit Windows conforme aux recommandations ANSSI, CIS et Microsoft Security Baseline</div>
        <div class="subtitle">Genere: $timestamp | Machine: $($osInfo.Split("`n")[0].Trim())</div>
    </header>
    
    <div class="container">
        
        <!-- SCORE GLOBAL -->
        <div class="score-container">
            <h2 style="color: #da3633; font-size: 1.8em; margin-bottom: 20px; border: none; padding-bottom: 0;">SCORE DE SECURITE GLOBAL</h2>
            <div class="score-circle">
                <div class="score-number">$scorePercent%</div>
                <div class="score-label">$totalScore / $maxScore points</div>
            </div>
            <div class="score-status">Niveau: $scoreLabel</div>
        </div>
        
        <!-- STATS FINDINGS -->
        <div class="grid">
            <div class="stat-box">
                <div class="stat-number critical">$criticalCount</div>
                <div class="stat-label">Findings CRITIQUES</div>
            </div>
            <div class="stat-box">
                <div class="stat-number major">$majorCount</div>
                <div class="stat-label">Findings MAJEURS</div>
            </div>
            <div class="stat-box">
                <div class="stat-number minor">$minorCount</div>
                <div class="stat-label">Findings MINEURS</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #58a6ff;">$($findings.Count)</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        <!-- FINDINGS & REMEDIATIONS -->
        <div class="section">
            <h2>Findings Securite et Remediations ANSSI</h2>
            $findingsHtml
        </div>

        <!-- SYSTEME -->
        <div class="section">
            <h2>Systeme</h2>
            <h3>Informations OS</h3>
            <pre>$osInfo</pre>
            <h3>Uptime Systeme</h3>
            <pre>$uptime</pre>
            <h3>BitLocker Status</h3>
            <pre>$bitlockerStatus</pre>
            <h3>Derniers Hotfixes</h3>
            $hotfixesTable
        </div>

        <!-- COMPTES -->
        <div class="section">
            <h2>Comptes et Identites</h2>
            <h3>Comptes Privilegies</h3>
            <pre>$privilegedAccounts</pre>
            <h3>Utilisateurs Locaux</h3>
            $usersTable
            <h3>Groupe Administrateurs</h3>
            $adminsTable
            <h3>Configuration UAC</h3>
            <pre>$uac</pre>
            <h3>Politique de Mots de Passe</h3>
            <pre>$passwordPolicy</pre>
        </div>

        <!-- AUTHENTIFICATION -->
        <div class="section">
            <h2>Authentification</h2>
            <h3>Configuration NTLM</h3>
            <pre>$ntlm</pre>
            <h3>Securite Base SAM</h3>
            <pre>$samSecurity</pre>
            <h3>Parametres LSA Avances</h3>
            <pre>$lsaAdvanced</pre>
            <h3>WDigest Credentials</h3>
            <pre>$wdigest</pre>
            <h3>LAPS Configuration</h3>
            <pre>$laps</pre>
            <h3>Credential Guard</h3>
            <pre>$credGuard</pre>
            <h3>Authentification Biometrique</h3>
            <pre>$passportBiometric</pre>
        </div>

        <!-- RESEAU -->
        <div class="section">
            <h2>Reseau et Services</h2>
            <h3>Profils Firewall</h3>
            $firewallTable
            <h3>Configuration SMB</h3>
            <pre>$smbConfig</pre>
            <h3>Protocoles Multicast</h3>
            <pre>$multicastProtocols</pre>
            <h3>Statut IPv6</h3>
            <pre>$ipv6Status</pre>
            <h3>Configuration RDP</h3>
            <pre>$rdp</pre>
            <h3>RDP Restricted Admin</h3>
            <pre>$rdpRestrictedAdmin</pre>
            <h3>Statut WinRM</h3>
            <pre>$winrm</pre>
            <h3>Autorun USB</h3>
            <pre>$usbAutorun</pre>
            <h3>Ports en Ecoute</h3>
            $portsTable
        </div>

        <!-- SECURITE OS -->
        <div class="section">
            <h2>Securite OS</h2>
            <h3>LSASS Protection</h3>
            <pre>$lsass</pre>
            <h3>Windows Defender</h3>
            <pre>$defender</pre>
            <h3>Secure Boot</h3>
            <pre>$secureBoot</pre>
        </div>

        <!-- JOURNALISATION -->
        <div class="section">
            <h2>Journalisation et Audit</h2>
            <h3>Audit Policy</h3>
            <pre>$auditpol</pre>
            <h3>Configuration WSUS</h3>
            <pre>$wsusConfig</pre>
            <h3>Sysmon</h3>
            <pre>$sysmon</pre>
        </div>

    </div>
</body>
</html>
"@

# Exporter en UTF-8 correct
[System.IO.File]::WriteAllText($htmlFile, $html, [System.Text.Encoding]::UTF8)

Write-Host "[+] Rapport HTML genere avec succes: $htmlFile" -ForegroundColor Green

# Generer PDF
try {
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    
    if (Test-Path $edgePath) {
        $browserPath = $edgePath
    } elseif (Test-Path $chromePath) {
        $browserPath = $chromePath
    } else {
        $browserPath = $null
    }
    
    if ($browserPath) {
        Write-Host "[*] Generation du PDF en cours..." -ForegroundColor Cyan
        & $browserPath --headless --disable-gpu --print-to-pdf="$pdfFile" $htmlFile
        Start-Sleep -Seconds 2
        
        if (Test-Path $pdfFile) {
            Write-Host "[+] PDF genere avec succes: $pdfFile" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "[!] Erreur PDF: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[+] Score de securite: $scorePercent% ($scoreLabel)" -ForegroundColor $(if ($scorePercent -ge 80) { "Green" } elseif ($scorePercent -ge 50) { "Yellow" } else { "Red" })
Write-Host "[+] Findings: $criticalCount CRITIQUES, $majorCount MAJEURS, $minorCount MINEURS" -ForegroundColor Yellow
Write-Host "[+] Total fichiers: $($findings.Count) problemes de securite detectes" -ForegroundColor Yellow

Invoke-Item $htmlFile
