# Plan de auditoría y optimización — 2026-10-31

Objetivo: determinar qué hacen los ejecutables y mejorar el minero de Ravencoin
sin confundir una prueba de laboratorio con una validación de la RX 9070 XT.
El usuario autorizó implementación, pruebas, commits y avisos por Telegram.

| Orden | Trabajo ejecutable | Criterio de aceptación | Estado |
| --- | --- | --- | --- |
| 1 | Control administrativo verificable, parada por Telegram y snapshot limpio | Prueba administrativa con reversión, sin NIC ni carpetas compartidas; parada persistente | Verificado |
| 2 | Actualizar Defender offline con paquete Microsoft firmado | Firma y hash registrados; firmas del día y protección activa en la VM | Verificado: 1.463.58.0 |
| 3 | Comparar upstream, original y fork desde el mismo snapshot | Hashes exactos, trazas de procesos/archivos/registro/red, detecciones y bloqueos documentados | Completado para cuatro muestras, incluida la optimizada; 16 fases y ocho análisis explícitos de Defender |
| 4 | Mejorar la fiabilidad del observador | Tiempo monotónico, códigos de salida y estado real; análisis de CSV sin cargar toda la traza en memoria | Implementado y probado |
| 5 | Ejecutar pruebas prolongadas del gobernador con sensores y reloj simulados | Pausa en 80 °C, reanudación en 60 °C, límites de actividad, fallos de sensores enclavados y ausencia de bloqueos | 960.000 lecturas; 114.535 pausas y 114.467 reanudaciones verificadas |
| 6 | Corregir problemas demostrados por esas pruebas y publicar commits separados | Pruebas de regresión y CI; conservar trazabilidad de la receta y no sustituir silenciosamente binarios auditados | Publicado a5de7a7; compilación Windows y pruebas de CI aprobadas |
| 7 | Mejorar diagnóstico y presentación de la integración | Distinguir preparación DAG, búsqueda, enfriamiento, fallo y datos ausentes; conservar consulta y parada por Telegram | Transiciones térmicas inmediatas implementadas; polling de UI conserva resolución de cinco segundos |
| 8 | Evaluar la salida al equipo principal | Informe con cobertura y limitaciones; ningún resultado offline equivale a descartar una alerta cloud | Evaluado: sin hallazgos en la cobertura observada; alerta del host no reproducida ni resuelta. Pendiente validación de la Radeon real |

Las muestras originales permanecen fijadas por SHA-256. Las mejoras de código se
prueban por separado: no se usará un resultado de una muestra para autorizar otra.
No se incrementarán los umbrales térmicos ni se simularán shares reales. Las
pruebas sintéticas permiten verificar política y estados, pero no ventiladores,
consumo, rendimiento KAWPOW ni compatibilidad del controlador AMD real.

Entregables: informe comparativo, resúmenes de trazas con hashes, pruebas
reproducibles y commits identificables en el fork y la integración. Telegram
recibirá hitos por etapa y alertas, sin credenciales ni mensajes por cada sondeo.

Trabajo ejecutado: corrección del gobernador en `a5de7a7`, compilación Windows
real, pruebas y CI, integración fijada a ese commit, cuatro observaciones con
Process Monitor y dos rondas de análisis Defender. La segunda ronda activó y
confirmó bloqueo PUA exclusivamente en la VM; ambas terminaron sin detecciones.
Se corrigió también el preflight del escáner para que un arranque incompleto de
Guest Additions no modifique el estado de la prueba ni monte muestras.

Siguiente etapa, condicionada a resolver la alerta del entorno principal:
contrastar el hash exacto de la compilación optimizada con Microsoft; después,
prueba supervisada de la GPU que mida preparación DAG, búsqueda, shares, sensores
y ventilación conservando pausa a 80 °C y reanudación a 60 °C. Un mock no puede
acreditar esa compatibilidad. No se ha iniciado minería desatendida en el host.
