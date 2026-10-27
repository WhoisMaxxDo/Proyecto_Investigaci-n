# Imagen Windows desatendida y endurecida — Tema 1

Proyecto de ISW-612, Unidad III. Autores: Derri Umaña y Donald Miranda.

## Qué contiene

- `web/index.html`: app HTML/CSS/JS sin servidor. Genera `Autounattend.xml` y un plan JSON, carga dos auditorías, compara conteos, muestra controles y recomendaciones, y exporta JSON o PDF mediante impresión.
- `scripts/Audit.ps1`: mide la misma VM antes y después y exporta el contrato JSON documentado en `schema/audit.schema.json`.
- `scripts/Hardening.ps1` y `Restore.ps1`: aplicación y reversión de controles con respaldo, simulación y confirmación.
- `examples/before.json` y `after.json`: datos **simulados**, solo para probar la app.

El repositorio excluye mediante `.gitignore` el XML generado, planes locales, respaldos y archivos de evidencia de la VM. Revise siempre el contenido antes de publicarlo.

## Una VM en Parallels: antes y después

Use la única VM Windows 11 disponible. Copie esta carpeta a `C:\Lab\Windows-Image-Hardening-Lab` dentro de Windows y abra Windows PowerShell 5.1 **como administrador** desde la consola de Parallels. La etiqueta `por_defecto` significa **estado inicial observado**; no demuestra que Windows se instaló con todos los valores predeterminados.

1. Mida el estado inicial antes de cambiar opciones:

   ```powershell
   Set-Location C:\Lab\Windows-Image-Hardening-Lab
   .\scripts\Audit.ps1 -Profile por_defecto -OutputPath .\evidence\before.json
   Get-FileHash .\evidence\before.json -Algorithm SHA256
   ```

2. Cree una **instantánea de Parallels** y conserve acceso a la consola. Abra `web/index.html` en el navegador. Genere `Autounattend.xml` y `hardening-plan.json`. Copie el plan a la raíz de este proyecto en Windows y revíselo. El XML sirve para mostrar el diseño de la instalación desatendida; si dispone de Windows SIM, valídelo contra la ISO exacta. **No ejecute el XML en esta VM**: el archivo generado borra el disco 0. Con una sola VM, la comparación no prueba la instalación desatendida. El XML contiene contraseñas temporales de laboratorio; no lo publique.

3. Simule el plan, sin aplicar cambios:

   ```powershell
   .\scripts\Hardening.ps1 -PlanPath .\hardening-plan.json
   ```

4. Si el plan corresponde a la VM, aplíquelo con instantánea y acceso a consola disponibles. El script solicita confirmación y guarda respaldo:

   ```powershell
   $opciones = @{
     PlanPath = '.\hardening-plan.json'
     Apply = $true
     LocalConsoleAcknowledged = $true
     BackupPath = '.\evidence\backup.json'
   }
   .\scripts\Hardening.ps1 @opciones
   ```

   Si seleccionó BitLocker, agregue `RecoveryDirectory = 'E:\Respaldo'` al bloque `$opciones` usando **otra unidad** ya montada. El script verifica TPM y guarda allí la clave de recuperación. No la suba al repositorio. BitLocker no se descifra automáticamente al restaurar.

5. Reinicie si deshabilitó SMBv1. En la **misma VM** repita la auditoría:

   ```powershell
   .\scripts\Audit.ps1 -Profile endurecida -OutputPath .\evidence\after.json
   Get-FileHash .\evidence\after.json -Algorithm SHA256
   ```

6. En la web cargue `before.json` en **Antes** y `after.json` en **Después**. Exporte el informe JSON o use **Guardar PDF / imprimir**. Registre capturas y observaciones reales por separado. Si aún no ejecutó las auditorías, use solo el botón **Cargar ejemplo simulado** y dígalo expresamente en la defensa.

Para restaurar estados respaldados de cuentas, servicios, RDP, SMBv1 y firewall en la misma VM:

```powershell
.\scripts\Restore.ps1 -BackupPath .\evidence\backup.json
.\scripts\Restore.ps1 -BackupPath .\evidence\backup.json -Apply -LocalConsoleAcknowledged
```

## Contrato JSON y método

Campos exigidos: `equipo`, `fecha`, `perfil` (`por_defecto` o `endurecida`), `servicios_en_ejecucion`, `puertos_escuchando`, `usuarios_locales`, `firewall` y `caracteristicas_opcionales`. El script incluye `profile` como alias técnico de `perfil`; deben coincidir. Los campos extra `controls` y `exposure` permiten un checklist y el número de reglas entrantes permitidas. Si una consulta falla, el dato es `null` o el control queda `unknown`; nunca se convierte en cumplimiento. El script tiene ayuda integrada: `Get-Help .\scripts\Audit.ps1 -Full`.

La app muestra conteos antes/después de servicios activos, puertos TCP en escucha, cuentas locales habilitadas, características opcionales y reglas entrantes permitidas. Una reducción de conteos **no equivale por sí sola a menor riesgo**: debe revisarse qué servicio, puerto o regla cambió y si sigue siendo accesible desde la red. El índice complementario es `pass / (pass + fail) × 100`, excluyendo `na` y `unknown`. El semáforo del checklist es verde con cero fallos, amarillo con uno o dos y rojo con tres o más; es una prioridad orientativa, no una probabilidad de ataque. Los ejemplos están marcados como simulados en la app y el informe.

La página no usa servidor, telemetría ni bibliotecas remotas. Procesa JSON en memoria; limita archivos a 1 MB e inserta datos con `textContent`. El XML temporal sí contiene credenciales de laboratorio y debe tratarse como secreto.

**Valide** `Autounattend.xml` con Windows SIM antes de usarlo y ejecute los scripts en la VM para obtener resultados reales. El antes/después mide cambios por endurecimiento y puede incluir variación por reinicio; no mide el efecto independiente de la instalación desatendida.

## Fuentes principales

- Microsoft. (s. f.). [Automate OOBE](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/automate-oobe?view=windows-11).
- Microsoft. (s. f.). [LocalAccount](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-useraccounts-localaccounts-localaccount).
- Microsoft. (s. f.). [Hide sensitive data in an answer file](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/hide-sensitive-data-in-an-answer-file).
- Microsoft. (s. f.). [UEFI/GPT-based hard drive partitions](https://learn.microsoft.com/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions?view=windows-11).
- Microsoft. (s. f.). [Windows optional features](https://learn.microsoft.com/windows/client-management/client-tools/add-remove-hide-features?pivots=windows-11&tabs=gpo).
- Microsoft. (s. f.). [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker).
