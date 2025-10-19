# app/core/scanner.py
from __future__ import annotations
import sys
import time
import socket
import ipaddress
import subprocess
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional


@dataclass
class ScanResult:
    ip: str
    status: str         # "UP" | "DOWN"
    rtt_ms: Optional[float]  # None si no aplica
    hostname: Optional[str]  # Reverse DNS si se habilita
    method: str         # "ICMP" | "TCP"
    timestamp: float


def parse_targets(text: str) -> List[str]:
    """
    Acepta:
      - CIDR: "192.168.1.0/24"
      - Rango: "192.168.1.10-192.168.1.50"
      - Única: "192.168.1.10"
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("Ingrese un rango o CIDR válido.")

    def ip_strs(network: ipaddress.IPv4Network) -> List[str]:
        # Incluye red y broadcast si quieres; aquí tomamos todos los hosts
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]

    if "/" in text:
        net = ipaddress.ip_network(text, strict=False)
        return ip_strs(net)

    if "-" in text:
        start, end = [p.strip() for p in text.split("-", 1)]
        ip_start = ipaddress.ip_address(start)
        ip_end = ipaddress.ip_address(end)
        if int(ip_end) < int(ip_start):
            raise ValueError("El rango final es menor que el inicial.")
        return [str(ipaddress.ip_address(i)) for i in range(int(ip_start), int(ip_end) + 1)]

    # Única IP
    ipaddress.ip_address(text)  # valida
    return [text]


def _ping_command(ip: str, timeout_ms: int) -> List[str]:
    """
    Construye el comando ping específico por plataforma.
    No dependemos del timeout del ping; usamos timeout de subprocess para cortar.
    """
    if sys.platform.startswith("win"):
        # -n 1: 1 eco, -w timeout en ms, -4 fuerza IPv4
        return ["ping", "-n", "1", "-w", str(timeout_ms), "-4", ip]
    else:
        # Linux/macOS/BSD: -c 1 (1 eco), -n (numérico)
        # Evitamos -W por diferencias entre distros; usamos timeout de subprocess
        return ["ping", "-c", "1", "-n", ip]


def _icmp_ping(ip: str, timeout_ms: int) -> tuple[bool, Optional[float]]:
    """
    Ejecuta ping al SO y mide RTT con time.monotonic() (aprox).
    Devuelve (alive, rtt_ms).
    """
    args = _ping_command(ip, timeout_ms)
    t0 = time.monotonic()
    try:
        # Cortamos el proceso si excede el timeout (seguridad)
        proc = subprocess.run(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_ms / 1000.0 + 1.0,
        )
        alive = proc.returncode == 0
    except subprocess.TimeoutExpired:
        alive = False
    rtt_ms = (time.monotonic() - t0) * 1000.0 if alive else None
    return alive, rtt_ms


def _tcp_fallback(ip: str, ports: Iterable[int], timeout_ms: int) -> bool:
    """
    Intenta detectar host 'up' con TCP connect en puertos comunes (445/80/3389).
    Útil cuando ICMP está bloqueado por firewall.
    """
    timeout = max(0.05, timeout_ms / 1000.0)
    for p in ports:
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _reverse_dns(ip: str, timeout_ms: int) -> Optional[str]:
    """
    Reverse DNS básico; no todos los DNS responden rápido.
    Lo ejecutamos con socket.gethostbyaddr; si se tarda, lo dejamos nulo.
    """
    socket.setdefaulttimeout(max(0.1, timeout_ms / 1000.0))
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def scan_batch(
    ips: List[str],
    timeout_ms: int = 800,
    max_workers: int = 64,
    resolve_names: bool = False,
    tcp_fallback: bool = False,
) -> List[ScanResult]:
    """
    Escanea una lista de IPs concurrentemente.
    """
    results: List[ScanResult] = []
    ts = time.time()

    def task(ip: str) -> ScanResult:
        alive, rtt = _icmp_ping(ip, timeout_ms)
        method = "ICMP"
        if not alive and tcp_fallback:
            # puertos típicos para “host up”
            alive = _tcp_fallback(ip, ports=(445, 3389, 80), timeout_ms=timeout_ms)
            method = "TCP" if alive else "ICMP"

        hostname = _reverse_dns(ip, timeout_ms) if (resolve_names and alive) else None
        return ScanResult(
            ip=ip, status=("UP" if alive else "DOWN"), rtt_ms=rtt, hostname=hostname, method=method, timestamp=ts
        )

    workers = min(max(1, max_workers), max(1, len(ips)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as ex:
        futures = {ex.submit(task, ip): ip for ip in ips}
        for fut in as_completed(futures):
            results.append(fut.result())
    return results
