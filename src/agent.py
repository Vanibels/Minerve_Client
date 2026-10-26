import argparse
import http.client
import json
import platform
import socket
import time
import urllib.error
import urllib.request
import uuid
from dotenv import load_dotenv
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import psutil

try: 
    from plyer import notification as desktop_notification
except ImportError:
    desktop_notification = None

load_dotenv()

BASE_DIR = Path.home() / ".local" / "share" / "MINERVE.CLIENT" if platform.system() != "Windows" else Path.home() / "AppData" / "Local" / "MINERVE.CLIENT"
CONFIG_FILE = BASE_DIR / "agent_config.json"
LOG_FILE = BASE_DIR / "agent.log"
QUEUE_FILE = BASE_DIR / "pending.jsonl"

API_BASE = "https://minerve-project.vanibels.fr"
BASE_DIR.mkdir(parents=True,exist_ok=True)

ENDPOINTS = {
    "register": "/api/agents/register",
    "measures": "/api/measures",
    "incidents": "/api/incidents",
    "status": "/api/agents/status",
}
API_TIMEOUT = 5

INTERVAL = 30
TIMEOUT = 3
SEND_INTERVAL = 300
FAILURE_THRESHOLD = 2
PUBLIC_INFO_TTL = 600
BANDWIDTH_INTERVAL = 1800
BANDWIDTH_BYTES = 2_000_000
MAX_QUEUE_LINES = 5000

# org ou isp
FAI_FIELD = "org"

TARGETS = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
]


def utc_now():
    return datetime.now(timezone.utc)

def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {}


def save_config(config):
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")

def guess_kind(name):
    lowered = name.lower()
    if any(key in lowered for key in ("wi-fi", "wifi", "wlan", "wireless")) or lowered.startswith("wl"):
        return "wifi"
    if "ethernet" in lowered or lowered.startswith(("eth", "en")):
        return "ethernet"
    return "unknown"


def get_interfaces():
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    interfaces = []

    for name, entries in addresses.items():
        ipv4 = [
            entry.address
            for entry in entries
            if entry.family == socket.AF_INET
            and not entry.address.startswith("127.")
        ]

        if ipv4:
            status = stats.get(name)
            interfaces.append({
                "name": name,
                "ip": ipv4[0],
                "up": status.isup if status else False,
                "kind": guess_kind(name),
            })

    return interfaces


def choose_interface(config, force=False):
    saved = config.get("interface")
    if saved and not force:
        return saved

    interfaces = get_interfaces()
    if not interfaces:
        raise RuntimeError("Aucune interface IPv4 disponible.")

    print("\nInterfaces réseau détectées :")
    for index, interface in enumerate(interfaces, start=1):
        state = "active" if interface["up"] else "inactive"
        print(
            f"{index}. {interface['name']} ({interface['kind']}) "
            f"| IP locale : {interface['ip']} | {state}"
        )

    while True:
        choice = input("\nNuméro de l'interface à surveiller : ")
        try:
            number = int(choice)
            if not 1 <= number <= len(interfaces):
                raise IndexError
            selected = interfaces[number - 1]
        except (ValueError, IndexError):
            print("Choix invalide. Réessaie.")
            continue

        if not selected["up"]:
            print("Cette interface est inactive.")
            continue

        config["interface"] = selected["name"]
        save_config(config)
        return selected["name"]


# --- Mesures ---------------------------------------------------------------
def http_get_json(host, path, local_ip, https):
    """GET JSON en sortant par l'interface surveillée (source_address)."""
    connection_class = http.client.HTTPSConnection if https else http.client.HTTPConnection
    connection = connection_class(host, timeout=TIMEOUT, source_address=(local_ip, 0))
    try:
        connection.request("GET", path, headers={"User-Agent": "Mozilla/5.0"})
        response = connection.getresponse()
        if response.status != 200:
            raise OSError(f"HTTP {response.status}")
        return json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def fetch_public_info(local_ip):
    try:
        data = http_get_json(
            "ip-api.com",
            "/json/?fields=status,query,isp,org,as,asname,city,country",
            local_ip,
            https=False,
        )
        if data.get("status") == "success":
            return {
                "public_ip": data.get("query"),
                "fai": data.get(FAI_FIELD) or data.get("isp"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": (data.get("as") or "").split(" ")[0] or None,
                "as_name": data.get("asname"),
                "localisation": f"{data.get('city')}, {data.get('country')}",
            }
    except (OSError, ValueError, http.client.HTTPException):
        pass

    try:
        data = http_get_json("ipapi.co", "/json/", local_ip, https=True)
        if "ip" in data:
            return {
                "public_ip": data.get("ip"),
                "fai": data.get("org"),
                "isp": None,
                "org": data.get("org"),
                "asn": data.get("asn"),
                "as_name": data.get("org"),
                "localisation": f"{data.get('city')}, {data.get('country_name')}",
            }
    except (OSError, ValueError, http.client.HTTPException):
        pass

    return None


def measure_bandwidth(local_ip):
    connection = http.client.HTTPSConnection(
        "speed.cloudflare.com", timeout=10, source_address=(local_ip, 0)
    )
    started = time.perf_counter()
    try:
        connection.request(
            "GET",
            f"/__down?bytes={BANDWIDTH_BYTES}",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        response = connection.getresponse()
        if response.status != 200:
            return None
        size = len(response.read())
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()

    elapsed = time.perf_counter() - started
    if elapsed <= 0 or size == 0:
        return None
    return round(size * 8 / elapsed / 1_000_000, 2)


def check_internet(interface_name):
    interface = next(
        (item for item in get_interfaces() if item["name"] == interface_name),
        None,
    )

    if interface is None or not interface["up"]:
        return {
            "status": "interface_unavailable",
            "latency_ms": None,
            "interface": interface_name,
        }

    local_ip = interface["ip"]
    latencies = []
    failed_targets = []

    for host, port in TARGETS:
        started = time.perf_counter()
        try:
            with socket.create_connection(
                (host, port),
                timeout=TIMEOUT,
                source_address=(local_ip, 0),
            ):
                latencies.append(round((time.perf_counter() - started) * 1000, 2))
        except OSError:
            failed_targets.append(f"{host}:{port}")

    return {
        "status": "online" if latencies else "offline",
        "latency_ms": min(latencies) if latencies else None,
        "interface": interface_name,
        "local_ip": local_ip,
        "failed_targets": failed_targets,
    }

class ApiClient:
    def __init__(self, uid, token=None):
        self.uid = uid
        self.token = token

    def post(self, path, payload):
        headers = {
            "Content-Type": "application/json",
            "X-Agent-UID": self.uid,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        request = urllib.request.Request(
            API_BASE + path,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
                raw = response.read().decode("utf-8")
                return "ok", (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as error:
            return ("retry" if error.code >= 500 else "rejected"), {"http_status": error.code}
        except (urllib.error.URLError, OSError, ValueError):
            return "retry", None

    def get(self, path):
        headers = {"X-Agent-UID": self.uid}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        request = urllib.request.Request(API_BASE + path, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
                raw = response.read().decode("utf-8")
                return "ok", (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as error:
            return ("retry" if error.code >= 500 else "rejected"), {"http_status": error.code}
        except (urllib.error.URLError, OSError, ValueError):
            return "retry", None


def enqueue(kind, payload):
    with QUEUE_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps({"kind": kind, "payload": payload}, ensure_ascii=False) + "\n")


def flush_queue(api):
    if not QUEUE_FILE.exists():
        return

    lines = QUEUE_FILE.read_text(encoding="utf-8").splitlines()
    remaining = []

    for index, line in enumerate(lines):
        try:
            item = json.loads(line)
            endpoint = ENDPOINTS[item["kind"]]
        except (ValueError, KeyError):
            continue

        state, _ = api.post(endpoint, item["payload"])
        if state == "retry":
            remaining = lines[index:]
            break

    remaining = remaining[-MAX_QUEUE_LINES:]
    if remaining:
        QUEUE_FILE.write_text("\n".join(remaining) + "\n", encoding="utf-8")
    else:
        QUEUE_FILE.unlink()


def notify(title, message):
    if desktop_notification is None:
        return
    try:
        desktop_notification.notify(
            title=title, message=message, app_name="Agent réseau", timeout=8
        )
    except Exception:
        pass

class Agent:
    def __init__(self, interface_name, config):
        self.interface_name = interface_name
        self.config = config
        self.api = ApiClient(config["uid"], config.get("token"))
        self.kind = guess_kind(interface_name)

        self.public_info = {}
        self.public_info_ip = None
        self.public_info_at = 0.0
        self.last_bandwidth_at = 0.0
        self.next_register_at = 0.0
        self.next_link_check_at = 0.0
        self.claim_opened = False
        self.last_send_at = time.monotonic()
        self.buffer = []

        self.failures = 0
        self.first_failure_at = None
        self.in_outage = False

        self.on_report = None

    def ensure_registered(self):
        if self.config.get("registered") or time.monotonic() < self.next_register_at:
            return
        self.next_register_at = time.monotonic() + 300

        state, data = self.api.post(ENDPOINTS["register"], {
            "uid": self.config["uid"],
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "interface": self.interface_name,
            "kind": self.kind,
        })
        if state == "ok":
            self.config["registered"] = True
            self.config["linked"] = False
            if isinstance(data, dict):
                self.config["token"] = data.get("token")
                self.config["claim_url"] = data.get("claim_url")
                self.api.token = data.get("token")
            save_config(self.config)
            self.open_claim_page()
        elif state == "rejected" and isinstance(data, dict) and data.get("http_status") == 409:
            self.config["uid"] = str(uuid.uuid4())
            self.api.uid = self.config["uid"]
            save_config(self.config)
        else:
            code = data.get("http_status") if isinstance(data, dict) else None
            cause = f"HTTP {code}" if code else "serveur injoignable"
            print(f"Enregistrement auprès du serveur impossible ({cause}), nouvel essai dans 5 min.")

    def open_claim_page(self):
        url = self.config.get("claim_url")
        if not url:
            return
        self.claim_opened = True
        print(f"\nPremière connexion : crée ton compte dans le navigateur pour lier cet appareil.\n{url}\n")
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def check_link(self, open_browser=False):
        """Vérifie que l'agent est lié à un compte ; sinon, rouvre la page de liaison au démarrage."""
        if self.config.get("linked") or not self.config.get("registered"):
            return
        if not open_browser and time.monotonic() < self.next_link_check_at:
            return
        self.next_link_check_at = time.monotonic() + 300

        state, data = self.api.get(ENDPOINTS["status"])
        if state == "ok" and isinstance(data, dict) and data.get("linked"):
            self.config["linked"] = True
            save_config(self.config)
            notify("Compte lié", "Cet appareil est lié à ton compte.")
        elif open_browser and state != "retry" and not self.claim_opened:
            self.open_claim_page()

    def refresh_public_info(self, local_ip):
        now = time.monotonic()
        fresh = now - self.public_info_at < PUBLIC_INFO_TTL
        if self.public_info and fresh and self.public_info_ip == local_ip:
            return

        info = fetch_public_info(local_ip)
        if info:
            self.public_info = info
            self.public_info_ip = local_ip
            self.public_info_at = now
        else:
            self.public_info_at = now - PUBLIC_INFO_TTL + 60

    def maybe_measure_bandwidth(self, local_ip):
        if time.monotonic() - self.last_bandwidth_at < BANDWIDTH_INTERVAL and self.last_bandwidth_at:
            return None
        self.last_bandwidth_at = time.monotonic()
        return measure_bandwidth(local_ip)

    def send(self, kind, payload):
        enqueue(kind, payload)
        flush_queue(self.api)

    def flush_measures(self):
        if not self.buffer:
            return
        self.send("measures", {"uid": self.config["uid"], "measures": self.buffer})
        self.buffer = []
        self.last_send_at = time.monotonic()

    def update_incident_state(self, report):
        now = utc_now()

        if report["status"] == "online":
            self.failures = 0
            if self.in_outage:
                duration = int((now - self.first_failure_at).total_seconds())
                self.send("incidents", {
                    "uid": self.config["uid"],
                    "type": "outage_end",
                    "started_at": self.first_failure_at.isoformat(),
                    "ended_at": now.isoformat(),
                    "duration_s": duration,
                    "interface": self.interface_name,
                    **self.public_info,
                })
                notify("Connexion rétablie", f"Coupure de {duration} s sur {self.interface_name}.")
                self.in_outage = False
            return

        self.failures += 1
        if self.failures == 1:
            self.first_failure_at = now

        if not self.in_outage and self.failures >= FAILURE_THRESHOLD:
            self.in_outage = True
            self.send("incidents", {
                "uid": self.config["uid"],
                "type": "outage_start",
                "started_at": self.first_failure_at.isoformat(),
                "reason": report["status"],
                "failed_targets": report.get("failed_targets", []),
                "interface": self.interface_name,
                **self.public_info,
            })
            notify("Connexion perdue", f"Incident détecté sur {self.interface_name}.")

    def run_once(self):
        self.ensure_registered()
        self.check_link()
        result = check_internet(self.interface_name)

        if result["status"] == "online":
            local_ip = result["local_ip"]
            self.refresh_public_info(local_ip)
            bandwidth = self.maybe_measure_bandwidth(local_ip)
            if bandwidth is not None:
                result["bandwidth_mbps"] = bandwidth

        report = {
            "timestamp": utc_now().isoformat(),
            "uid": self.config["uid"],
            "kind": self.kind,
            **result,
            **self.public_info,
        }

        with LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(report, ensure_ascii=False) + "\n")

        self.update_incident_state(report)

        self.buffer.append(report)
        if time.monotonic() - self.last_send_at >= SEND_INTERVAL:
            self.flush_measures()

        if self.on_report:
            self.on_report(report)

        return report


def main():
    parser = argparse.ArgumentParser(description="Minerve-Client")
    parser.add_argument("--choose", action="store_true", help="choisir à nouveau l'interface")
    parser.add_argument("--reset", action="store_true", help="oublier l'enregistrement et se lier à nouveau")
    args = parser.parse_args()

    config = load_config()
    if args.reset:
        for key in ("uid", "token", "registered", "linked", "claim_url"):
            config.pop(key, None)
    config.setdefault("uid", str(uuid.uuid4()))
    save_config(config)

    interface_name = choose_interface(config, force=args.choose)
    agent = Agent(interface_name, config)
    agent.ensure_registered()
    agent.check_link(open_browser=True)

    print(f"\nSurveillance de : {interface_name}")
    print(f"Intervalle : {INTERVAL} secondes | envoi groupé toutes les {SEND_INTERVAL} s")
    print("Appuie sur Ctrl+C pour arrêter.\n")

    try:
        while True:
            report = agent.run_once()
            print(
                f"[{report['timestamp']}] {report['status'].upper()} | "
                f"Latence : {report['latency_ms']} ms | "
                f"IP publique : {report.get('public_ip', 'Inconnue')} "
                f"({report.get('fai', 'Inconnu')})"
            )
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("\nLe programme c'est terminé correctement!.")
    finally:
        agent.flush_measures()


if __name__ == "__main__":
    main()