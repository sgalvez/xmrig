"""Panel HTTP local de solo lectura. No expone RPC, claves ni archivos privados."""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from dashboard import clean, coins, collect, number, rate
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "xmrig-personal-lab"))
from xmrig_personal.insights import explain

ASSETS = Path(__file__).resolve().parent / "web"


def obj(value):
    return value if isinstance(value, dict) else {}


def view(data):
    """Allowlisted presentation fields only; preserve amounts as strings."""
    now = float(data["now"])
    config = obj(data.get("config"))
    miner = obj(data.get("miner"))
    pool = obj(data.get("pool"))
    checked = number(pool.get("checked"))
    pool_age = now - float(checked) if checked is not None else None
    p = obj(pool.get("data"))
    pool_fresh = pool_age is not None and 0 <= pool_age <= 90 and not pool.get("error")
    workers = obj(p.get("workers")).get("list", [])
    workers = workers if isinstance(workers, list) else []
    probe_current = (miner.get('engine') == 'XMRig' and miner.get('running') is True
                     and miner.get('trial') is True and miner.get('address') == config.get('address')
                     and number(miner.get('updated')) is not None and 0 <= now-float(number(miner['updated'])) < 25)
    observed_worker = miner.get('worker') if probe_current else config.get('worker')
    matching = [w for w in workers if isinstance(w, dict) and w.get("name") == observed_worker]
    worker = max(matching, key=lambda w: number(w.get("lastShareTime")) or 0, default={})
    share = number(worker.get("lastShareTime"))
    share_age = now - float(share) if share and share > 0 else None
    updated = number(miner.get("updated"))
    miner_age = now - float(updated) if updated is not None else None
    heartbeat = miner_age is not None and 0 <= miner_age < 25
    engine_matches = miner.get("engine") == "XMRig"
    active = heartbeat and engine_matches and miner.get("running") is True
    address_matches = miner.get("address") == config.get("address") and bool(config)
    recent_work = pool_fresh and share_age is not None and 0 <= share_age < 180
    governor_stamp = number(miner.get('governor_updated'))
    cooling = (active and governor_stamp is not None and 0 <= now-float(governor_stamp) <= 5
               and miner.get('governor_state') == 'cooling' and number(miner.get('duty_percent')) == 0)


    if "security" in data:
        state, title, detail = "warning", "Inicio suspendido: bloqueo de antivirus", "Hay un bloqueo de seguridad pendiente para el motor actual. Conserva la cuarentena y revisa el Historial de protección."
    elif not config:
        state, title, detail = "idle", "Minería sin configurar", "Completa el arranque para crear la billetera y vincular tu dirección al pool."
    elif not miner:
        state, title, detail = "idle", "Sin señales del minero", "No hay registros de inicio. Ejecuta mine-start después de identificar tu GPU."
    elif not engine_matches:
        state, title, detail = "warning", "Registro de otro motor", "El registro no corresponde a XMRig. Comprueba miner-status e inicia el motor nuevo."
    elif not heartbeat and miner.get('running') is False:
        state, title, detail = "idle", "Último estado registrado: detenido", "El supervisor dejó constancia de la detención. No hay telemetría en vivo; usa miner-status para comprobar procesos actuales."
    elif not heartbeat:
        state, title, detail = "warning", "Estado del minero sin verificar", "El supervisor dejó de actualizar. Comprueba miner-status; un registro antiguo no confirma actividad."
    elif not miner.get("running"):
        state, title, detail = "idle", "Minero detenido", "El supervisor informa que XMRig está detenido."
    elif cooling and address_matches:
        state, title, detail = "waiting", "Minería pausada · enfriando", "No se envía trabajo a la GPU. Reanuda automáticamente cuando GPU, hotspot y memoria disponible estén a 60 °C o menos. Ctrl+C en la sesión de minería detiene todo."
    elif miner.get("trial") is True and address_matches:
        state, title, detail = "waiting", "Prueba de XMRig en curso", "Prueba de cinco minutos de búsqueda después de preparar el DAG, con un worker temporal. El arranque permanente espera confirmación del pool."
    elif not address_matches or miner.get("worker") != config.get("worker"):
        state, title, detail = "warning", "Revisa la dirección o el worker", "El proceso activo no coincide con la configuración del panel."
    elif recent_work:
        state, title, detail = "working", "Trabajo reciente registrado por el pool", "El proceso está activo y RavenMiner informa una share de tu worker en los últimos tres minutos."
    else:
        state, title, detail = "waiting", "Proceso activo · esperando shares recientes", "XMRig está ejecutándose. Falta confirmar trabajo reciente en el pool; revisa el registro."

    node = obj(data.get("node"))
    chain = obj(node.get("chain"))
    wallet = obj(node.get("wallet"))
    network = obj(node.get("network"))
    valid_wallet = chain.get("chain") == "main" and wallet.get("walletname") == "zerocool-rvn.dat"
    progress = number(chain.get("verificationprogress"))
    syncing = chain.get("initialblockdownload") is not False
    balance = obj(p.get("balance")) if pool_fresh else {}
    amount = number(wallet.get("balance")) if valid_wallet else None
    alerts = []
    if "historical_security" in data:
        alerts.append("Incidentes anteriores de SRBMiner/WildRig: conserva las cuarentenas. Motor seleccionado: XMRig.")
    if "security" in data:
        security = obj(data["security"])
        alerts.append("Detección reportada: " + clean(security.get("detection", "antivirus")) +
                      ". La billetera y este panel pueden seguir funcionando; la instalación y el inicio del minero están suspendidos.")
    for source, keys in ((data, ("node_error", "config_error")),
                         (node, ("chain_error", "wallet_error", "network_error")),
                         (pool, ("error",)), (miner, ("error",))):
        for key in keys:
            if source.get(key):
                alerts.append(clean(source[key])[:300])
    if chain and chain.get("chain") != "main":
        alerts.append("El nodo no está en mainnet; se ocultan los saldos.")
    if wallet and not valid_wallet:
        alerts.append("No se pudo verificar la billetera esperada; se ocultan los saldos.")
    if valid_wallet and "unlocked_until" not in wallet:
        alerts.append("La billetera todavía necesita cifrado: wallet create.")
    payout_coin = obj(obj(p.get("autoexchange")).get("payoutCoin")).get("symbol")
    if payout_coin and payout_coin != "RVN":
        alerts.append("El pool informa pago en otra moneda; revisa su configuración.")
    if p and not pool_fresh:
        alerts.append("Los datos del pool son antiguos; se ocultan hasta recibir una consulta válida.")
    def fresh_stamp(key, seconds):
        stamp = number(miner.get(key))
        return active and stamp is not None and 0 <= now - float(stamp) <= seconds

    sensor_fresh = fresh_stamp("temperature_updated", 30)
    rate_fresh = fresh_stamp("hashrate_updated", 35)
    started = number(miner.get("started"))
    uptime = max(0, int((now if active else float(updated or 0)) - float(started))) if started else None
    telemetry = {key: str(miner[key]) if sensor_fresh and number(miner.get(key)) is not None else None
                 for key in ("temperature", "edge_c", "hotspot_c", "memory_c", "power_w", "fan_rpm", "core_mhz", "memory_mhz")}
    for key in ("hashrate_10s_hs", "hashrate_60s_hs", "hashrate_15m_hs"):
        telemetry[key] = str(miner[key]) if rate_fresh and number(miner.get(key)) is not None else None
    governor_fresh = fresh_stamp("governor_updated", 5)
    telemetry.update({"governor_state": clean(miner.get("governor_state")) if governor_fresh else None,
                      "governor_phase": clean(miner.get("governor_phase")) if governor_fresh else None,
                      "duty_percent": str(miner["duty_percent"]) if governor_fresh and number(miner.get("duty_percent")) is not None else None,
                      "governor_time": float(number(miner.get("governor_updated")) or 0),
                      "dag_done": str(miner["dag_done"]) if governor_fresh and number(miner.get("dag_done")) is not None else None,
                      "dag_total": str(miner["dag_total"]) if governor_fresh and number(miner.get("dag_total")) is not None else None,
                      "sensor_source": clean(miner.get("sensor_source")) if sensor_fresh else None})
    telemetry.update({"sensor_fresh": sensor_fresh, "rate_fresh": rate_fresh,
                      "sensor_time": float(number(miner.get("temperature_updated")) or 0),
                      "sample_time": float(number(miner.get("hashrate_updated")) or 0),
                      "accepted": str(miner["accepted"]) if heartbeat and engine_matches and number(miner.get("accepted")) is not None else None,
                      "rejected": str(miner["rejected"]) if heartbeat and engine_matches and number(miner.get("rejected")) is not None else None,
                      "shares_note": "Contadores del log; pueden incluir donación. No equivalen a pagos."})
    transactions = []
    if valid_wallet and isinstance(node.get("transactions"), list):
        for tx in node["transactions"][-5:]:
            if isinstance(tx, dict):
                transactions.append({"category": clean(tx.get("category", "?")),
                                     "amount": coins(tx.get("amount")),
                                     "confirmations": str(tx.get("confirmations", "?")),
                                     "txid": clean(tx.get("txid", ""))})
    result = {
        "updated": now,
        "state": state, "title": title, "detail": detail,
        "miner": {"engine": "XMRig 6.26.0",
                  "process": "Activo" if active else ("Detenido" if heartbeat and engine_matches and miner.get("running") is False else "Sin verificar"),
                  "gpu": str(miner.get("gpu_id", "—")),
                  "pid": str(miner.get("miner_pid", "—")), "uptime": uptime,
                  "trial": miner.get("trial") is True, "worker": miner.get("worker"),
                  "active_seconds": str(miner['active_seconds']) if active and number(miner.get('active_seconds')) is not None else None,
                  "search_seconds": str(miner["search_seconds"]) if active and number(miner.get("search_seconds")) is not None else None,
                  "preparation_seconds": str(miner["preparation_seconds"]) if active and number(miner.get("preparation_seconds")) is not None else None,
                  "cooling_seconds": str(miner['cooling_seconds']) if active and number(miner.get('cooling_seconds')) is not None else None,
                  "age": max(0, int(miner_age)) if miner_age is not None else None},
        "telemetry": telemetry,
        "pool": {"fresh": pool_fresh, "worker": observed_worker, "hashrate": rate(worker.get("hr5m") if pool_fresh else None),
                 "hashrate_hs": str(worker["hr5m"]) if pool_fresh and number(worker.get("hr5m")) is not None else None,
                 "sample_time": float(checked or 0),
                 "last_share_age": max(0, int(share_age)) if pool_fresh and share_age is not None else None,
                 "cleared": coins(balance.get("cleared"), 12),
                 "pending": coins(balance.get("pending"), 12),
                 "minimum": coins(p.get("minPayout") if pool_fresh else None),
                 "age": max(0, int(pool_age)) if pool_age is not None else None},
        "wallet": {"available": coins(amount),
                   "units": str(int(amount * 100000000)) if amount is not None else "—",
                   "pending": coins(wallet.get("unconfirmed_balance") if valid_wallet else None),
                   "immature": coins(wallet.get("immature_balance") if valid_wallet else None),
                   "provisional": syncing or not valid_wallet},
        "node": {"status": "No disponible" if not chain else ("Sincronizando" if syncing else "Sincronizado"),
                 "percent": f"{progress * 100:.10f}%" if progress is not None else "—",
                 "blocks": str(chain.get("blocks", "—")), "headers": str(chain.get("headers", "—")),
                 "connections": str(network.get("connections", "—"))},
        "address": config.get("address", "Sin configurar"),
        "worker": config.get("worker", "Sin configurar"),
        "pool_url": "https://www.ravenminer.com/ravencoin/wallet/" + config["address"] if config else None,
        "alerts": alerts,
        "transactions": transactions,
        "logs": [clean(line)[:500] for line in data.get("logs", [])[-60:]],
    }

    result["insight"] = explain(result)
    return result


class Snapshot:
    def __init__(self, reader):
        self.reader = reader
        self.lock = threading.Lock()
        self.value = {"loading": True}

    def refresh(self):
        try:
            value = view(self.reader())
        except Exception:
            value = {"error": "No se pudo actualizar el estado. Reintentando…", "updated": time.time()}
        with self.lock:
            self.value = value

    def read(self):
        with self.lock:
            return json.dumps(self.value, ensure_ascii=False, allow_nan=False).encode()

    def poll(self, stop):
        while not stop.is_set():
            self.refresh()
            stop.wait(5)


def handler(snapshot, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, code, body, mime="text/plain; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
            if self.headers.get("Host", "").lower() not in allowed_hosts or self.headers.get("Sec-Fetch-Site") == "cross-site":
                return self.respond(403, b"Acceso local requerido.")
            path = urlsplit(self.path).path
            if path == "/api/status":
                return self.respond(200, snapshot.read(), "application/json; charset=utf-8")
            routes = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/styles.css": ("styles.css", "text/css; charset=utf-8")}
            if path not in routes:
                return self.respond(404, b"No encontrado.")
            filename, mime = routes[path]
            return self.respond(200, (ASSETS / filename).read_bytes(), mime)

        def do_POST(self):
            return self.respond(405, b"Panel de solo lectura.")

    return Handler


def serve(wallet_snapshot, runtime, port=8787):
    snapshot = Snapshot(lambda: collect(wallet_snapshot, runtime))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler(snapshot, port))
    server.daemon_threads = True
    stop = threading.Event()
    thread = threading.Thread(target=snapshot.poll, args=(stop,), daemon=True)
    thread.start()
    print(f"Panel Ravencoin: http://localhost:{port}\nCtrl+C cierra el panel; el minero sigue en segundo plano.", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
