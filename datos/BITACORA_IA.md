# Bitácora de uso de inteligencia artificial

**Proyecto:** Windows Image Hardening Lab — Tema 1: imagen Windows desatendida y endurecida  
**Curso:** ISW-612 — Administración de Sistemas Operativos de Red  
**Integrantes:** Donald Miranda y Derri Umaña  
**Fecha:** 26 de octubre de 2026  
**Herramienta de apoyo:** ChatGPT (OpenAI)

## 1. Objetivo de la bitácora

Registrar cómo se utilizó la inteligencia artificial como apoyo durante el desarrollo del laboratorio, qué decisiones se tomaron y qué aspectos deben comprobarse con pruebas reales. La IA se utilizó también para producir borradores y código, por lo que su participación fue más allá de resolver consultas puntuales.

## 2. Registro de actividades

| Etapa | Uso de IA y resultados | Decisiones y seguimiento del equipo |
| --- | --- | --- |
| Definición del tema | Se solicitó ayuda para interpretar el alcance del Tema 1 y organizar el laboratorio. | Se cambió el enfoque inicial de acceso remoto (Tema 6) al de instalación desatendida y endurecimiento (Tema 1). Se decidió trabajar con una sola VM Windows 11. |
| Diseño de la solución | Se utilizó IA para estructurar el flujo **PowerShell → JSON → HTML** y preparar la arquitectura y materiales. | Se adoptó la comparación **antes/después en una misma VM**, sin presentarla como comparación entre dos instalaciones. |
| Aplicación web | La IA colaboró en la generación y revisión del HTML, CSS y JavaScript, incluidos el generador de configuración, la carga de JSON y la visualización. | Se revisó la demostración y se identificó que el botón de ejemplo muestra información simulada, no mediciones de Windows. |
| Scripts de PowerShell | Se obtuvo apoyo para desarrollar y documentar `Audit.ps1`, `Hardening.ps1` y `Restore.ps1`, sus parámetros y controles de seguridad. | Se optó por ejecutar primero la auditoría y el modo `DRY RUN`, reservando `-Apply` para una prueba con instantánea y respaldo. |
| Instalación automatizada | Se analizó el propósito de `Autounattend.xml` y su diferencia con los scripts de posinstalación. | Se decidió **no ejecutar** el XML sobre la única VM: la configuración propuesta incluye borrado del disco 0. Esto limita lo que puede afirmarse sobre la instalación desatendida. |
| Documentación y exposición | Se utilizó IA para elaborar y revisar borradores del informe, presentación, guion y comentarios técnicos de los scripts. | Se corrigieron las referencias a dos VM y se simplificó el guion para explicar con claridad el alcance, los riesgos y las pruebas pendientes. |
| Comprobaciones | Se revisó la lógica de JavaScript y los ejemplos JSON en un entorno de desarrollo. | Queda pendiente comprobar los scripts en PowerShell dentro de la VM y documentar cualquier resultado real, error o ajuste necesario. |

## 3. Qué hace cada componente

- **`Autounattend.xml`:** archivo de respuestas destinado a automatizar partes de una instalación nueva de Windows. No se ejecutó en la VM utilizada.
- **`Audit.ps1`:** consulta el estado actual de controles y servicios de Windows sin cambiar su configuración. Puede producir `before.json` y `after.json`.
- **`Hardening.ps1`:** lee un plan JSON de medidas de seguridad. Sin `-Apply` muestra una simulación (`DRY RUN`); con `-Apply`, comprobaciones y confirmación, puede efectuar cambios reales.
- **`Restore.ps1`:** utiliza un respaldo para intentar recuperar configuraciones reversibles; no sustituye una instantánea completa.
- **Aplicación HTML:** genera archivos de configuración y presenta comparaciones a partir de JSON reales o de ejemplo, diferenciando ambos casos.

## 4. Verificación y limitaciones

**Realizado o preparado:** estructura del proyecto, prototipo web, scripts, documentación y ejemplos simulados para explicar el flujo. Hubo revisiones estáticas y comprobaciones de JavaScript.

**No demostrado todavía en la VM:** instalación mediante `Autounattend.xml`, ejecución real de endurecimiento, restauración efectiva ni mejora medida mediante dos auditorías tomadas antes y después de aplicar cambios.

Los datos de ejemplo **no representan resultados experimentales**. La auditoría real del estado inicial (`before.json`) puede obtenerse sin alterar Windows; para afirmar una mejora es necesario aplicar cambios de forma controlada y volver a medir (`after.json`) en la misma máquina.

## 5. Reflexión sobre el uso de IA

La IA ayudó a organizar ideas, proponer implementaciones, preparar documentación y detectar inconsistencias entre el alcance y el material de exposición. También generó parte del contenido técnico que el equipo debe entender y revisar antes de utilizarlo. El aprendizaje principal es que **un código generado o una simulación no equivalen a una prueba real**: los resultados deben verificarse en Windows y las limitaciones deben explicarse con transparencia.

## 6. Próximos pasos

1. Ejecutar `Audit.ps1` en la única VM y conservar el `before.json` real.
2. Crear una instantánea de Parallels, inspeccionar el plan y ejecutar `Hardening.ps1` en `DRY RUN`.
3. Si se autoriza la prueba real, aplicar el plan con respaldo y comprobar el estado con una segunda auditoría.
4. Cargar ambos JSON reales en la aplicación y registrar capturas, resultados y conclusiones.

> **Nota de transparencia:** Esta bitácora se redactó con apoyo de ChatGPT a partir del trabajo y las decisiones discutidas sobre el proyecto. Debe actualizarse cuando se ejecuten pruebas reales; no atribuye al equipo comprobaciones que todavía no se han realizado.
