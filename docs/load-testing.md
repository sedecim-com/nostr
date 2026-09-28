# Pruebas de carga del relay y del indexer (NFR005-02)

Este informe recoge el throughput y los límites del relay y del mirror/indexer. La herramienta está en
`scripts/load/`, el flujo de CI en `.github/workflows/load-test.yml` y el escalado horizontal del indexer en
[`architecture.md`](architecture.md#indexer--mirror-escalado-horizontal-nfr005-01).

> **Estado:** hay una línea base **local** (relay de prueba en memoria + indexer en proceso). Las cifras
> contra **Buzz + stack compose** salen del workflow `load-test` y todavía no se han volcado aquí (sección
> [Resultados en CI](#resultados-en-ci-buzz--stack-compose)). Hasta entonces, NFR005-02 queda parcial.

## Método

`scripts/load/run.ts` (tsx) lanza N clientes, cada uno con su identidad y su conexión autenticada por
NIP-42 (`RelayPool` con `authMode: 'auto'`). Todos se suscriben y publican a la vez:

1. **Preparación.** Crea `--channels` canales NIP-29 abiertos (kind 9007). Buzz asigna el id, publica el
   39000 y hace owner a quien lo crea. En un relay sin NIP-29 (el stack local) se publican el 39000 y una
   lista de miembros (39002) con el creador, firmados con la llave que hace de llave del relay (`groupKey`,
   anunciada en el NIP-11 `self` del relay de prueba). Cada cliente se une (9021) y abre una
   suscripción en vivo (`limit: 0`) a los mensajes de canal (`#h`) y a sus gift wraps (`#p` = él mismo).
   Con indexer, se publica un mensaje por canal y se espera a que el mirror lo devuelva: el
   descubrimiento de canales es periódico y no debe contar como lag.
2. **Carga en lazo abierto.** Cada cliente publica a `--rate` ev/s durante `--duration` s, sin esperar al
   OK del anterior (con un tope de `--max-inflight` en vuelo; lo que lo supera cuenta como descartado por
   contrapresión). Los kinds salen de la mezcla `--mix`: 9 (mensaje de canal) a un canal al azar, 1059 (gift
   wrap NIP-17 a otro cliente, sin jitter de timestamp porque Buzz rechaza el de 2 días) y 1 (nota).
   El contenido mide uno de los tamaños de `--sizes`.
3. **Medidas.**
   - *Latencia de ACK:* de `EVENT` a `OK` (p50/p95/p99/máx, global y por kind), OK/fallidos y errores
     agrupados por prefijo NIP-01 (`rate-limited`, `invalid`, `auth-required`…).
   - *Throughput:* eventos con OK por segundo frente al ofrecido (clientes × tasa).
   - *Entrega:* del inicio de la publicación a la llegada del evento a cada suscriptor que debe recibirlo.
     Un mensaje de canal va a todos los clientes (incluido el autor) y un gift wrap solo al destinatario.
     Se mide el porcentaje entregado y la latencia.
   - *Lag del indexer:* para una fracción `--lag-sample` de los eventos 9/1 con OK, el tiempo desde la
     publicación hasta que `GET /v1/events?ids=…` (NIP-98) los devuelve. Consulta como el creador de los
     canales, porque el espejo solo sirve un canal a sus miembros (FR014-05). Con varias réplicas se consultan
     por turnos, y cualquiera sirve las lecturas. Se sondea cada ~100 ms, así que la resolución es de
     unos 100–200 ms.
   - *Generador:* p99 del retardo del event loop del propio generador. Si sube de ~100 ms, el cuello de
     botella es el generador y no el objetivo.
4. **Vaciado.** Tras publicar, espera hasta `--drain` s a entregas e indexación pendientes. Lo que no llega
   cuenta como no entregado o no indexado.

Los clientes de carga no verifican firmas al recibir (`verifyEvents: false`), para medir el relay y no la
CPU del generador. El relay sí las verifica.

**Veredicto por paso** (`LIMITS` en `scripts/load/lib.ts`): un paso está saturado si el ACK p95 pasa de
2 s (el umbral de la alerta `RelayAckLatencyP95High`, [`slo.md`](slo.md)), si los errores superan el 1 %,
si la entrega baja del 99 %, si el indexer tiene p95 > 10 s o eventos sin indexar, o si el throughput
queda por debajo del 90 % de lo ofrecido. `--steps` recorre varias tasas por cliente (rampa) y el
informe marca el primer paso que cruza un límite.

Salida: `<out>.json` (todas las muestras agregadas y las opciones) y `<out>.md` (tabla resumen + detalle
por paso, en el formato de las tablas de abajo).

### Perfiles

| Perfil | Clientes | ev/s por cliente | Duración | Tamaños | Mezcla 9/1059/1 |
|---|---|---|---|---|---|
| `smoke` | 5 | 2 | 10 s | 256, 1024 B | 80/15/5 |
| `baseline` | 20 | 2 | 60 s | 256, 1024 B | 80/15/5 |
| `stress` | 50 | 5 | 60 s | 256, 1024, 4096 B | 80/15/5 |

Cualquier opción del perfil se puede sobrescribir por línea de comandos (`--clients`, `--rate`,
`--duration`, `--sizes`, `--mix 9=80,1059=15,1=5`, `--channels`, `--lag-sample`, `--drain`, `--steps`).

## Cómo ejecutarlo

Local, contra el relay de prueba y el indexer en proceso (el objetivo arranca en un proceso hijo,
`scripts/load/local-stack.ts`, para no compartir CPU con el generador):

```sh
npx tsx scripts/load/run.ts --local --local-indexers 2 --profile smoke --out load-local
# con Postgres (un pool por réplica) en lugar del repositorio en memoria:
npx tsx scripts/load/run.ts --local --local-indexers 2 --database-url postgres://… --profile baseline --steps 1,5,10,15
```

Contra el stack compose (Buzz + Postgres + indexer):

```sh
sh scripts/init-env.sh && docker compose up -d && sh scripts/wait-stack.sh
npx tsx scripts/load/run.ts --relay ws://localhost:3000 --indexer http://localhost:8081 --profile baseline --steps 1,2,5,10 --out load-1idx
docker compose --profile scale up -d indexer-2        # segunda réplica en :8091
npx tsx scripts/load/run.ts --relay ws://localhost:3000 --indexer http://localhost:8081,http://localhost:8091 --profile baseline --steps 1,2,5,10 --out load-2idx
```

En CI: **Actions → load-test → Run workflow** (perfil, rampa, clientes y duración configurables), y además
cada lunes. Hace lo mismo que el job `stack` de `ci.yml` y ejecuta la rampa con 1 réplica del indexer y
luego con 2. El resumen queda en la página del run y el artefacto `load-report` guarda los JSON/Markdown,
`docker stats` y los logs.

La prueba `tests/scripts/load.test.ts` ejecuta la herramienta en pequeño (3 clientes, 2 réplicas del
indexer) dentro de la suite normal.

## Línea base local (relay de prueba, no Buzz)

> Medida **local**: `packages/test-relay` (en memoria, modo Buzz: NIP-42 obligatorio y reparto de canal
> solo a `#h`) y el indexer en el mismo proceso hijo (un solo hilo). El generador corre en otro proceso de
> Node, en una máquina de 4 vCPU. Postgres 16 local. **No son cifras de Buzz ni de producción.** Sirven
> para validar la herramienta y como referencia de orden de magnitud.

Rampa `baseline`: 20 clientes, 20 s por paso, 4 canales, mezcla 80/15/5, 256/1024 B, lag muestreado al 20 %.

| Paso | Ofrecido ev/s | OK ev/s | Errores | ACK p50/p95/p99 ms | Entrega % | Entrega p50/p95/p99 ms | Lag indexer p50/p95/p99 ms | Bucle gen. p99 ms | Veredicto |
|---|---|---|---|---|---|---|---|---|---|
| memoria, 1 réplica · 20×1 | 20 | 20 | 0 | 3 / 9 / 29 | 100 | 3 / 9 / 26 | 45 / 103 / 118 | 29 | OK |
| memoria, 1 réplica · 20×5 | 100 | 97,2 | 0 | 4 / 23 / 39 | 100 | 4 / 22 / 35 | 76 / 134 / 164 | 51 | OK |
| memoria, 1 réplica · 20×10 | 200 | 173,1 | 0 | 19 / 574 / 1105 | 100 | 19 / 568 / 1091 | 132 / 4140 / 4709 | 64 | throughput < 90 % |
| memoria, 1 réplica · 20×25 | 500 | 187,4 | 0 | 237 / 2590 / 3702 | 100 | 236 / 2589 / 3754 | 8334 / 13570 / 14385 | 167 | ACK p95 > 2 s, lag, throughput |
| Postgres, 1 réplica · 20×1 | 20 | 20 | 0 | 3 / 7 / 24 | 100 | 3 / 7 / 14 | 48 / 117 / 133 | 31 | OK |
| Postgres, 1 réplica · 20×5 | 100 | 97,2 | 0 | 4 / 25 / 38 | 100 | 4 / 24 / 33 | 76 / 148 / 182 | 46 | OK |
| Postgres, 1 réplica · 20×10 | 200 | 165,6 | 0 | 14 / 46 / 71 | 100 | 13 / 45 / 66 | 120 / 212 / 258 | 84 | throughput < 90 % |
| Postgres, 1 réplica · 20×15 | 300 | 193,5 | 0 | 617 / 3499 / 4913 | 100 | 621 / 3482 / 4774 | 23281 / 28252 / 28912 (160 sin indexar tras 30 s) | 72 | ACK p95 > 2 s, lag, throughput |
| Postgres, 2 réplicas · 20×1 | 20 | 20 | 0 | 3 / 6 / 13 | 100 | 3 / 6 / 9 | 49 / 112 / 119 | 30 | OK |
| Postgres, 2 réplicas · 20×5 | 100 | 96,7 | 0 | 4 / 27 / 41 | 100 | 4 / 25 / 38 | 82 / 149 / 175 | 54 | OK |
| Postgres, 2 réplicas · 20×10 | 200 | 164,6 | 0 | 14 / 48 / 77 | 100 | 14 / 46 / 77 | 135 / 237 / 303 | 83 | throughput < 90 % |
| Postgres, 2 réplicas · 20×15 | 300 | 198,3 | 0 | 25 / 71 / 94 | 100 | 25 / 70 / 94 | 208 / 368 / 459 | 98 | throughput < 90 % |

Por kind (Postgres, 1 réplica, 20×10): kind 9 ACK p50/p95/p99 13/45/66 ms, kind 1059 16/54/84 ms. Los
gift wraps cuestan más al generador (dos cifrados NIP-44 y tres firmas por evento) pero no más al relay.

### Límites observados (local)

- **Hasta ~100 ev/s publicados** (20 clientes, unas 2000 entregas/s por el reparto a 20 suscriptores), todo
  holgado: ACK p95 < 30 ms, 100 % de entregas y lag del indexer p95 ≈ 150 ms, que es sobre todo la
  resolución del sondeo.
- **Techo del montaje en ~170–200 ev/s publicados** (~3500–4000 entregas/s). Por encima, lo ofrecido ya no
  se alcanza. Hay dos causas a la vez: el generador (un proceso de Node que firma y cifra; su event loop
  sube a p99 ≈ 80–170 ms) y el objetivo, porque el relay de prueba, el indexer y su API comparten un hilo.
  Cuando el objetivo se satura, el ACK p95 pasa de 2 s y el lag del indexer crece sin límite (cola de
  ingesta), aunque ninguna entrega se pierde. Es un límite del montaje local y no de Buzz.
- **Réplicas del indexer en local.** Las dos réplicas corren en el mismo proceso que el relay, así que no
  añaden CPU. Solo se comprueba que el reparto de shards no degrada nada (mismas cifras hasta 200 ev/s) y
  que las lecturas por cualquier réplica funcionan. El beneficio de escalar tiene que medirse en el stack
  (réplicas en contenedores separados).
- **Hallazgo corregido durante la medición.** Al crearse canales nuevos, la réplica reabría la
  suscripción de todos sus canales desde el checkpoint menos la ventana de solape (15 min) y releía
  historia ya indexada. En la rampa con 2 réplicas eso disparaba el lag (p95 ≈ 37 s). Ahora los canales que
  ya se seguían en vivo se resuscriben con solo 60 s de repetición y la nueva suscripción se abre antes de
  cerrar la anterior. Solo los canales tomados de otra réplica o nunca sincronizados parten del
  checkpoint.

## Resultados en CI (Buzz + stack compose)

_Pendiente: rellenar con el primer run del workflow `load-test` (artefacto `load-report`, resumen del
run)._

| Paso | Réplicas indexer | Ofrecido ev/s | OK ev/s | Errores | ACK p50/p95/p99 ms | Entrega % | Lag indexer p50/p95/p99 ms | Veredicto |
|---|---|---|---|---|---|---|---|---|
| _pendiente_ | 1 | | | | | | | |
| _pendiente_ | 2 | | | | | | | |

Qué mirar en ese run: el primer paso que cruza un límite con 1 y con 2 réplicas, los errores por prefijo
(p. ej. `rate-limited` de Buzz), si el lag del indexer baja con 2 réplicas y `docker stats` para saber qué
contenedor se satura primero (relay, Postgres o indexer). El runner de GitHub tiene 4 vCPU compartidas
por todo el stack y el generador, así que el techo absoluto es una cota inferior de la capacidad real.
