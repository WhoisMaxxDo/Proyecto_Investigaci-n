#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory=$true)][string]$BackupPath,[switch]$Apply,[switch]$LocalConsoleAcknowledged)
$ErrorActionPreference='Stop'
$b=Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
if($b.schemaVersion -ne '1.0' -or $b.computer -ne $env:COMPUTERNAME){throw 'Respaldo incompatible o de otra máquina.'}
if(-not $Apply){Write-Host 'DRY RUN. Se restaurarían cuentas, servicios, RDP y firewall del respaldo. BitLocker requiere revisión manual.';return}
if(-not $LocalConsoleAcknowledged){throw 'Confirme acceso a consola local con -LocalConsoleAcknowledged.'}
$p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Requiere administrador.'}
if(-not $PSCmdlet.ShouldContinue('Se restaurarán controles del respaldo.','Confirmar restauración')){return}
foreach($rid in @('-500','-501')) { $entry=$b.accounts.PSObject.Properties[$rid].Value; if($entry){$u=Get-LocalUser | Where-Object {$_.SID.Value.EndsWith($rid)} | Select-Object -First 1; if($u -and $PSCmdlet.ShouldProcess($u.Name,'Restaurar estado de cuenta')){if($entry.enabled){Enable-LocalUser -InputObject $u}else{Disable-LocalUser -InputObject $u}}} }
if($b.actions -contains 'expireStandardPassword' -and $b.standardUser -match '^[A-Za-z][A-Za-z0-9_-]{1,18}$' -and $PSCmdlet.ShouldProcess($b.standardUser,'Quitar cambio obligatorio de contraseña')){ $adsi=[ADSI]("WinNT://$env:COMPUTERNAME/$($b.standardUser),user"); $adsi.Put('PasswordExpired',0); $adsi.SetInfo() }
if($PSCmdlet.ShouldProcess('RDP','Restaurar valor')){Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value ([int]$b.rdp)}
foreach($name in @('WinRM','sshd')) { $entry=$b.services.$name; if($entry -and (Get-Service $name -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess($name,'Restaurar servicio')){Set-Service $name -StartupType $entry.startType; if($entry.status -eq 'Running'){Start-Service $name -ErrorAction Stop}else{Stop-Service $name -Force -ErrorAction SilentlyContinue}} }
if($b.smb1 -eq 'Enabled' -and $PSCmdlet.ShouldProcess('SMB1Protocol','Restaurar característica previa')){Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null; Write-Warning 'SMBv1 fue reactivado por solicitud de restauración. Reinicie y evalúe el riesgo.'}
foreach($profile in $b.firewall){if($PSCmdlet.ShouldProcess($profile.name,'Restaurar firewall')){Set-NetFirewallProfile -Profile $profile.name -Enabled ([bool]$profile.enabled) -DefaultInboundAction $profile.defaultInbound}}
Write-Warning 'Restauración terminada. BitLocker y cambios externos no se revierten automáticamente. Ejecute Audit.ps1 de nuevo.'
