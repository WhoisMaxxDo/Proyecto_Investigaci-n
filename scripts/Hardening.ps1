#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string]$PlanPath,
    [switch]$Apply,
    [switch]$LocalConsoleAcknowledged,
    [string]$BackupPath = (Join-Path $PSScriptRoot 'hardening-backup.json'),
    [string]$RecoveryDirectory
)
$ErrorActionPreference='Stop'
$allowed = @('expireStandardPassword','disableGuest','disableBuiltInAdmin','disableRdp','disableWinRm','disableSshd','disableSmb1','enableFirewall','blockInbound','enableBitLocker')
$plan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json
if ($plan.schemaVersion -ne '1.0') { throw 'Plan incompatible.' }
$selected = @($plan.actions | Where-Object { $_ -is [string] } | Select-Object -Unique)
if (@($plan.actions).Count -ne $selected.Count) { throw 'Plan contiene acciones repetidas o inválidas.' }
foreach($action in $selected) { if ($allowed -notcontains $action) { throw "Acción no permitida: $action" } }
if ($selected -contains 'expireStandardPassword' -and ($plan.userName -notmatch '^[A-Za-z][A-Za-z0-9_-]{1,18}$' -or $plan.userName -ieq 'LabAdmin')) { throw 'userName inválido para exigir cambio de contraseña.' }
if (-not $Apply) { Write-Host 'DRY RUN. No se modificará Windows.'; $selected | ForEach-Object { Write-Host "PLAN: $_" }; return }
if (-not $LocalConsoleAcknowledged) { throw 'Para aplicar, confirme con -LocalConsoleAcknowledged que tiene acceso a la consola de la VM y un punto de recuperación.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Ejecute PowerShell como administrador.' }
if ($selected -contains 'disableBuiltInAdmin') {
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Where-Object { $_.PrincipalSource -eq 'Local' -and -not $_.SID.Value.EndsWith('-500') })
    $enabled = @($admins | Where-Object { try { (Get-LocalUser -SID $_.SID -ErrorAction Stop).Enabled } catch { $false } })
    if ($enabled.Count -lt 1) { throw 'No se deshabilitará Administrador: falta otra cuenta administradora local habilitada.' }
}
if ($selected -contains 'enableBitLocker') {
    if (-not $RecoveryDirectory) { throw 'BitLocker requiere -RecoveryDirectory en otra unidad, preferiblemente un medio externo seguro.' }
    $dest = [IO.Path]::GetFullPath($RecoveryDirectory)
    if ([IO.Path]::GetPathRoot($dest).TrimEnd('\') -ieq $env:SystemDrive) { throw 'No guarde la clave de recuperación en el volumen del sistema.' }
    if (-not (Test-Path -LiteralPath $dest -PathType Container)) { throw 'La carpeta de recuperación externa no existe.' }
    if (-not (Get-Tpm -ErrorAction Stop).TpmReady) { throw 'TPM no disponible o no preparado.' }
    $vol=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($vol.ProtectionStatus -eq 'On') { throw 'BitLocker ya está activo; revise el estado manualmente.' }
}
$backup=[ordered]@{ schemaVersion='1.0'; capturedAt=(Get-Date).ToUniversalTime().ToString('o'); computer=$env:COMPUTERNAME; accounts=@{}; services=@{}; rdp=$null; firewall=@(); smb1=$null; standardUser=$plan.userName; bitlockerInitiallyOn=$false; actions=$selected }
foreach($rid in @('-500','-501')) { $u=Get-LocalUser | Where-Object { $_.SID.Value.EndsWith($rid) } | Select-Object -First 1; if($u){$backup.accounts[$rid]=[ordered]@{name=$u.Name;enabled=$u.Enabled}} }
foreach($name in @('WinRM','sshd')) { $s=Get-Service $name -ErrorAction SilentlyContinue; if($s){$backup.services[$name]=[ordered]@{status=[string]$s.Status;startType=[string]$s.StartType}} }
$backup.rdp=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$backup.firewall=@(Get-NetFirewallProfile | ForEach-Object { [ordered]@{name=[string]$_.Name;enabled=[bool]$_.Enabled;defaultInbound=[string]$_.DefaultInboundAction} })
if ($selected -contains 'disableSmb1') { try { $backup.smb1=[string](Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch { $backup.smb1='NotPresent' } }
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { try { $backup.bitlockerInitiallyOn=((Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus -eq 'On') } catch { $backup.bitlockerInitiallyOn=$null } }
if (Test-Path -LiteralPath $BackupPath) { throw "El respaldo ya existe: $BackupPath. Elija otro nombre." }
$backup | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BackupPath -Encoding UTF8
Write-Host "Estado anterior respaldado en $BackupPath"
if (-not $PSCmdlet.ShouldContinue('Se aplicarán cambios en la VM. Revise la lista y mantenga la consola local disponible.','Confirmar endurecimiento')) { return }
foreach($action in $selected) {
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,$action)) { continue }
    switch($action) {
        'expireStandardPassword' { $u=Get-LocalUser -Name $plan.userName -ErrorAction Stop; $member=@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID -eq $u.SID }); if($member.Count){throw 'El usuario indicado pertenece a Administradores.'}; $adsi=[ADSI]("WinNT://$env:COMPUTERNAME/$($plan.userName),user"); $adsi.Put('PasswordExpired',1); $adsi.SetInfo() }
        'disableGuest' { $u=Get-LocalUser | Where-Object {$_.SID.Value.EndsWith('-501')} | Select-Object -First 1; if($u){Disable-LocalUser -InputObject $u} }
        'disableBuiltInAdmin' { $u=Get-LocalUser | Where-Object {$_.SID.Value.EndsWith('-500')} | Select-Object -First 1; if($u){Disable-LocalUser -InputObject $u} }
        'disableRdp' { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 }
        'disableWinRm' { Stop-Service WinRM -Force -ErrorAction SilentlyContinue; Set-Service WinRM -StartupType Disabled }
        'disableSshd' { $s=Get-Service sshd -ErrorAction SilentlyContinue; if($s){Stop-Service sshd -Force -ErrorAction SilentlyContinue; Set-Service sshd -StartupType Disabled} }
        'disableSmb1' { if($backup.smb1 -eq 'Enabled'){Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null; Write-Warning 'Reinicie y audite de nuevo para confirmar SMBv1.'}else{Write-Host "SMB1Protocol no estaba habilitado: $($backup.smb1)"} }
        'enableFirewall' { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True }
        'blockInbound' { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block }
        'enableBitLocker' {
            $vol=Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmProtector -ErrorAction Stop
            $vol=Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop
            $key=($vol.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -Last 1).RecoveryPassword
            if (-not $key) { throw 'No se pudo leer la clave de recuperación. Abra el panel de BitLocker y resguárdela antes de reiniciar.' }
            $path=Join-Path $dest ("BitLocker-$($env:COMPUTERNAME)-recovery.txt")
            if (Test-Path -LiteralPath $path) { throw 'El archivo de recuperación ya existe; no se sobrescribirá.' }
            Set-Content -LiteralPath $path -Value $key -Encoding ASCII
            Write-Warning "Clave de recuperación guardada en $path. Protégela y verifica una copia accesible. El cifrado no se revierte automáticamente."
        }
    }
    Write-Host "APLICADO: $action"
}
