# Imagen Windows desatendida y endurecida — Tema 1

Proyecto de ISW-612, Unidad III. Autores: Derri Umaña y Donald Miranda.

## Qué contiene

- `web/index.html`: app HTML/CSS/JS sin servidor. Genera `Autounattend.xml` y un plan JSON, carga dos auditorías, compara conteos, muestra controles y recomendaciones, y exporta JSON o PDF mediante impresión.
- `scripts/Audit.ps1`: mide cada VM y exporta el contrato JSON documentado en `schema/audit.schema.json`.
- `scripts/Hardening.ps1` y `Restore.ps1`: aplicación y reversión de controles con respaldo, simulación y confirmación.
- `examples/before.json` y `after.json`: datos **simulados**, solo para probar la app.

El repositorio excluye mediante `.gitignore` el XML generado, planes locales, respaldos y archivos de evidencia de la VM. Revise siempre el contenido antes de publicarlo.

## Dos VM en Parallels

Cree dos VM propias y aisladas con **la misma ISO, edición, hardware virtual y configuración de red**. Etiquete una `por_defecto` y otra `endurecida`. Use instantáneas y no ejecute el archivo de instalación en un equipo con datos. El generador borra por completo el **disco 0** de la VM endurecida si se usa el XML generado.

1. Instale la primera VM manualmente con valores predeterminados. Abra Windows PowerShell 5.1 **como administrador**, desde la consola de Parallels, y ejecute:

   ```powershell
   .\scripts\Audit.ps1 -Profile por_defecto -OutputPath .\evidence\before.json
   ```

2. Abra `web/index.html` directamente en el navegador. Indique nombre, usuario estándar, idioma, zona e índice correcto de la imagen de la ISO (`DISM /Get-WimInfo`). Revise la opción de borrado del disco 0 y los términos de licencia antes de marcarlos. Genere y descargue `Autounattend.xml` y `hardening-plan.json`.
3. El XML contiene **dos contraseñas temporales aleatorias**, visibles al generar: una para el usuario estándar y otra para `LabAdmin`. No se pide ninguna contraseña real. Anótelas fuera de la VM, no publique el XML, elimínelo del medio de instalación y del equipo tras usarlo, y cambie ambas contraseñas. La codificación que ofrece Windows SIM **no cifra** las contraseñas. Verifique con Windows System Image Manager el XML contra la imagen exacta. La automatización puede variar según edición y medio; compruebe su funcionamiento en Parallels.
4. Instale la segunda VM UEFI/GPT con `Autounattend.xml` en el medio de instalación. El XML prepara EFI, MSR y Windows en el disco 0 e instala la imagen por índice. Si Setup muestra un error, deténgase y registre el mensaje. No se incluyen claves de producto ni bypass de Windows 11; use un medio legal de evaluación compatible. Este ejemplo no crea una partición WinRE separada: registre esa limitación.
5. Inicie sesión como `LabAdmin` en la consola de la segunda VM. Antes de que inicie sesión el usuario estándar, revise el plan. Ejecute primero el modo de simulación:

   ```powershell
   .\scripts\Hardening.ps1 -PlanPath .\hardening-plan.json
   ```

6. Si el plan corresponde a la VM, aplíquelo con acceso a consola e instantánea disponibles. El script solicita confirmación y guarda respaldo:

   ```powershell
   .\scripts\Hardening.ps1 -PlanPath .\hardening-plan.json -Apply -LocalConsoleAcknowledged -BackupPath .\evidence\backup.json
   ```

   Si seleccionó BitLocker, agregue `-RecoveryDirectory E:\Respaldo` usando **otra unidad** ya montada, idealmente externa y protegida. El script verifica TPM y guarda allí la clave de recuperación. No la suba al repositorio. BitLocker no se descifra automáticamente al restaurar.

7. Reinicie si deshabilitó SMBv1. En la VM endurecida ejecute:

   ```powershell
   .\scripts\Audit.ps1 -Profile endurecida -OutputPath .\evidence\after.json
   ```

8. En la web cargue `before.json` en **VM por defecto** y `after.json` en **VM endurecida**. Exporte el informe JSON o use **Guardar PDF / imprimir**. Registre por separado los tiempos de instalación, capturas y observaciones reales. Si no se ejecutaron las VM, use únicamente el botón **Cargar ejemplo simulado** y dígalo expresamente en la defensa.

Para restaurar estados respaldados de cuentas, servicios, RDP, SMBv1 y firewall en la VM endurecida:

```powershell
.\scripts\Restore.ps1 -BackupPath .\evidence\backup.json
.\scripts\Restore.ps1 -BackupPath .\evidence\backup.json -Apply -LocalConsoleAcknowledged
```

## Contrato JSON y método

Campos exigidos: `equipo`, `fecha`, `perfil` (`por_defecto` o `endurecida`), `servicios_en_ejecucion`, `puertos_escuchando`, `usuarios_locales`, `firewall` y `caracteristicas_opcionales`. El script incluye `profile` como alias técnico de `perfil`; deben coincidir. Los campos extra `controls` y `exposure` permiten un checklist y el número de reglas entrantes permitidas. Si una consulta falla, el dato es `null` o el control queda `unknown`; nunca se convierte en cumplimiento. El script tiene ayuda integrada: `Get-Help .\scripts\Audit.ps1 -Full`.

La app muestra conteos antes/después de servicios activos, puertos TCP en escucha, cuentas locales habilitadas, características opcionales y reglas entrantes permitidas. Una reducción de conteos **no equivale por sí sola a menor riesgo**: debe revisarse qué servicio, puerto o regla cambió y si sigue siendo accesible desde la red. El índice complementario es `pass / (pass + fail) × 100`, excluyendo `na` y `unknown`. El semáforo del checklist es verde con cero fallos, amarillo con uno o dos y rojo con tres o más; es una prioridad orientativa, no una probabilidad de ataque. Los ejemplos están marcados como simulados en la app y el informe.

La página no usa servidor, telemetría ni bibliotecas remotas. Procesa JSON en memoria; limita archivos a 1 MB e inserta datos con `textContent`. El XML temporal sí contiene credenciales de laboratorio y debe tratarse como secreto.

La validación del XML con Windows SIM y la ejecución de los scripts en ambas VM son necesarias para demostrar el experimento.

## Fuentes principales

- Microsoft. (s. f.). [Automate OOBE](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/automate-oobe?view=windows-11).
- Microsoft. (s. f.). [LocalAccount](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-useraccounts-localaccounts-localaccount).
- Microsoft. (s. f.). [Hide sensitive data in an answer file](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/hide-sensitive-data-in-an-answer-file).
- Microsoft. (s. f.). [UEFI/GPT-based hard drive partitions](https://learn.microsoft.com/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions?view=windows-11).
- Microsoft. (s. f.). [Windows optional features](https://learn.microsoft.com/windows/client-management/client-tools/add-remove-hide-features?pivots=windows-11&tabs=gpo).
- Microsoft. (s. f.). [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker).
