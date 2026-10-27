#requires -Version 5.1
<#
.SYNOPSIS
Mide la superficie y los controles de una VM Windows 11 del Tema 1.
.DESCRIPTION
Solo lee configuracion local y guarda un JSON. No cambia cuentas, servicios,
firewall ni opciones del sistema. Ejecute el mismo script antes y despues
en la misma VM, desde Windows PowerShell 5.1 de 64 bits y preferiblemente
como administrador, para que las consultas tengan el mismo alcance.

Profile es una etiqueta proporcionada por quien ejecuta el script; el script
no puede deducir si la VM fue endurecida. El JSON incluye los ocho campos
minimos de la guia: equipo, fecha, perfil, servicios, puertos, usuarios,
firewall y caracteristicas opcionales. Una consulta fallida se registra como
null o unknown; nunca se interpreta como cero ni como cumplimiento.
.PARAMETER OutputPath
Ruta del JSON. Se crea el directorio padre si no existe. Un archivo con el
mismo nombre se reemplaza; use rutas distintas para antes y despues.
.PARAMETER Profile
Etiqueta por_defecto o endurecida. Se copia a perfil y al alias profile
usado por la aplicacion web. Ambas propiedades deben coincidir.
.EXAMPLE
.\Audit.ps1 -Profile por_defecto -OutputPath .\evidence\before.json
.EXAMPLE
.\Audit.ps1 -Profile endurecida -OutputPath .\evidence\after.json
.NOTES
Contrato: datos/esquema.md y schema/audit.schema.json. Los conteos de
puertos y reglas son observaciones locales: no prueban accesibilidad desde
otra maquina ni reduccion de riesgo. Ejecute el script en Windows antes
de presentar resultados como evidencia.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,
    [Parameter(Mandatory=$true)]
    [ValidateSet('por_defecto','endurecida')]
    [string]$Profile
)
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$controls = New-Object System.Collections.Generic.List[object]
# Cada control conserva la observacion que justifica su estado. La app solo
# puntua pass y fail; na y unknown quedan fuera del denominador.
function Add-Control([string]$Id,[string]$Status,[string]$Observed,[string]$Reason='') {
    $controls.Add([ordered]@{ id=$Id; status=$Status; observed=$Observed; reason=$Reason })
}
function Unknown([string]$Id,[object]$Err) { Add-Control $Id 'unknown' ('Consulta falló: ' + $Err.Exception.Message) 'No se incluye en el puntaje.' }
# Firewall: comprobar los tres perfiles y su regla de entrada predeterminada.
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $ok = $profiles.Count -eq 3 -and @($profiles | Where-Object { $_.Enabled -ne $true }).Count -eq 0
    Add-Control 'firewall' $(if($ok){'pass'}else{'fail'}) (($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join '; ')
} catch { Unknown 'firewall' $_ }
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $ok = $profiles.Count -eq 3 -and @($profiles | Where-Object { $_.DefaultInboundAction -ne 'Block' }).Count -eq 0
    Add-Control 'inbound' $(if($ok){'pass'}else{'fail'}) (($profiles | ForEach-Object { "$($_.Name)=$($_.DefaultInboundAction)" }) -join '; ')
} catch { Unknown 'inbound' $_ }
# Identificar cuentas integradas por RID evita depender de nombres localizados
# o renombrados. No se modifica ninguna cuenta.
foreach ($item in @(@{id='guest';rid='-501'},@{id='admin';rid='-500'})) {
    try {
        $u = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value.EndsWith($item.rid) } | Select-Object -First 1
        if ($null -eq $u) { Add-Control $item.id 'unknown' 'Cuenta RID no encontrada.' }
        else { Add-Control $item.id $(if(-not $u.Enabled){'pass'}else{'fail'}) ("$($u.Name): Enabled=$($u.Enabled)") }
    } catch { Unknown $item.id $_ }
}
# RDP: en una VM que lo necesite, explique la excepcion al interpretar fail.
try {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
    if ($os.Caption -match 'Home') { Add-Control 'rdp' 'na' ("$($os.Caption); fDenyTSConnections=$v") 'La edición Home no actúa como host RDP.' }
    else { Add-Control 'rdp' $(if($v -eq 1){'pass'}else{'fail'}) ("fDenyTSConnections=$v") 'Si RDP es imprescindible, registre una excepción y marque este control como no aplicable en el análisis.' }
} catch { Unknown 'rdp' $_ }
# WinRM y sshd: se observa el estado y el tipo de inicio. La ausencia de
# OpenSSH Server cumple porque no ofrece ese servidor de entrada.
try {
    $svc = Get-Service WinRM -ErrorAction Stop
    $listeners = if ($svc.Status -eq 'Running') { @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop) } else { @() }
    $safe = $svc.Status -ne 'Running' -and $svc.StartType -eq 'Disabled'
    Add-Control 'winrm' $(if($safe){'pass'}else{'fail'}) ("Service=$($svc.Status); StartType=$($svc.StartType); configured listeners=$($listeners.Count)") 'Un listener configurado pero con servicio deshabilitado no recibe conexiones; documente si permanece.'
} catch { Unknown 'winrm' $_ }
try {
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Add-Control 'sshd' 'pass' 'Servicio sshd no instalado.' }
    else { Add-Control 'sshd' $(if($svc.Status -ne 'Running' -and $svc.StartType -eq 'Disabled'){'pass'}else{'fail'}) ("Status=$($svc.Status); StartType=$($svc.StartType)") }
} catch { Unknown 'sshd' $_ }
# BitLocker: cifrado completo y proteccion activa son condiciones separadas.
try {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { Add-Control 'bitlocker' 'unknown' 'Módulo BitLocker no disponible.' }
    else {
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $ok = $vol.ProtectionStatus -eq 'On' -and $vol.VolumeStatus -eq 'FullyEncrypted'
        Add-Control 'bitlocker' $(if($ok){'pass'}else{'fail'}) ("Protection=$($vol.ProtectionStatus); Volume=$($vol.VolumeStatus)")
    }
} catch { Unknown 'bitlocker' $_ }
# Windows Update disponible no demuestra que los parches esten instalados.
try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction Stop
    if ($null -eq $svc) { Add-Control 'updates' 'unknown' 'Servicio Windows Update no encontrado.' }
    else { Add-Control 'updates' $(if($svc.StartMode -ne 'Disabled'){'pass'}else{'fail'}) ("wuauserv StartMode=$($svc.StartMode)") 'Disponibilidad no confirma que los parches estén instalados.' }
} catch { Unknown 'updates' $_ }
# Superficie descriptiva: puertos TCP fuera de loopback y reglas entrantes
# habilitadas Allow. No equivale a un escaneo desde otra maquina.
$exposure=[ordered]@{ tcpListeningPorts=$null; inboundAllowRules=$null; note='Indicadores descriptivos. Un puerto en escucha no prueba que sea accesible desde otra máquina.' }
try { $exposure.tcpListeningPorts=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1') } | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) } catch { $exposure.note += " Consulta TCP falló: $($_.Exception.Message)" }
try { $exposure.inboundAllowRules=@(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop).Count } catch { $exposure.note += " Consulta firewall falló: $($_.Exception.Message)" }
# Inventario minimo de la guia: [] significa consulta exitosa sin elementos;
# null significa que la consulta fallo.
$services=$null; $users=$null; $features=$null; $fw=$null
try { $services=@(Get-Service -ErrorAction Stop | Where-Object Status -eq 'Running' | Select-Object -ExpandProperty Name | Sort-Object -Unique) } catch { Write-Warning "Servicios no disponibles: $($_.Exception.Message)" }
try { $users=@(Get-LocalUser -ErrorAction Stop | ForEach-Object { [ordered]@{ nombre=$_.Name; habilitado=[bool]$_.Enabled; sid=[string]$_.SID } }) } catch { Write-Warning "Usuarios no disponibles: $($_.Exception.Message)" }
try { $features=@(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object State -eq 'Enabled' | Select-Object -ExpandProperty FeatureName | Sort-Object -Unique) } catch { Write-Warning "Características opcionales no disponibles: $($_.Exception.Message)" }
try { $fw=@(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ perfil=[string]$_.Name; activo=[bool]$_.Enabled; entrada=[string]$_.DefaultInboundAction } }) } catch { Write-Warning "Firewall no disponible: $($_.Exception.Message)" }
# La misma fecha UTC alimenta los dos campos. source=measured declara origen
# local; no implica verificacion independiente desde otro equipo.
$capturedAt = (Get-Date).ToUniversalTime().ToString('o')
$result = [ordered]@{ schemaVersion='1.0'; kind='windows-image-audit'; capturedAt=$capturedAt; source='measured'; perfil=$Profile; profile=$Profile; equipo=$env:COMPUTERNAME; fecha=$capturedAt; machine=[ordered]@{ name=$env:COMPUTERNAME; os=$os.Caption; version=$os.Version }; controls=@($controls.ToArray()); exposure=$exposure; servicios_en_ejecucion=$services; puertos_escuchando=$exposure.tcpListeningPorts; usuarios_locales=$users; firewall=$fw; caracteristicas_opcionales=$features }
# UTF-8 conserva los nombres y las observaciones en espanol.
$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host "Auditoría guardada en $OutputPath"
