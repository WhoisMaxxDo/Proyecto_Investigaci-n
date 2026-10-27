# Contrato de auditoría JSON

`Audit.ps1` genera UTF-8 con `schemaVersion: "1.0"` y `kind: "windows-image-audit"`. El esquema formal está en `../schema/audit.schema.json`.

| Campo | Tipo | Descripción |
| --- | --- | --- |
| `equipo` | texto | Nombre local del equipo |
| `fecha` | fecha ISO 8601 | Momento UTC de la auditoría |
| `perfil` | `por_defecto` o `endurecida` | Etiqueta exigida por la guía y asignada al ejecutar el script |
| `profile` | `por_defecto` o `endurecida` | Alias técnico para la app; debe coincidir con `perfil` |
| `servicios_en_ejecucion` | lista de textos o `null` | Nombres de servicios activos; `null` si falló la consulta |
| `puertos_escuchando` | lista de enteros o `null` | Puertos TCP en escucha fuera de loopback, sin duplicados |
| `usuarios_locales` | lista de objetos o `null` | Nombre, estado habilitado y SID |
| `firewall` | lista de objetos o `null` | Perfil, estado activo y acción de entrada predeterminada |
| `caracteristicas_opcionales` | lista de textos o `null` | Características con estado Enabled |
| `controls` | nueve objetos | `id`, `status` (`pass`, `fail`, `na`, `unknown`), observación y razón |
| `exposure` | objeto | Puertos TCP, número de reglas entrantes Allow y nota de alcance |
| `source` | `measured` o `simulated` | Origen declarado; el ejemplo nunca debe presentarse como medición |

Un fallo de consulta se representa con `null` o `unknown`, nunca con cero. El puntaje excluye `na` y `unknown`. La comparación de dos perfiles debe interpretarse por elemento: la cantidad de servicios o puertos no es por sí sola una medida de riesgo.

El script usa `-Profile` solo para **etiquetar** la captura; no determina por sí mismo qué imagen se instaló. Se recomienda ejecutar el mismo script en Windows PowerShell 5.1 de 64 bits con permisos de administrador antes y después en la misma VM, guardar archivos distintos y registrar los cambios de configuración. Consulte `Get-Help .\scripts\Audit.ps1 -Full` para parámetros, ejemplos y alcance.
