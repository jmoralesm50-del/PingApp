# app/gui_app.py
from __future__ import annotations
import time
import threading
import tkinter as tk
from tkinter import ttk
from app.data import db
from tkinter import ttk, messagebox, filedialog

from app.core.scanner import parse_targets, scan_batch, ScanResult
from app.data import db
from app.reports.csv_export import export_to_csv


class PineoApp(tk.Tk):
    
    def __init__(self):
        super().__init__()
        self.title("Pineo Automático - MVP")
        self.geometry("900x560")
        self.minsize(860, 520)

        # Estado
        self._running = False
        self._after_id = None
        self._rows_map = {}  # ip -> item_id
        self._lock = threading.Lock()
        self._current_scan_id = None

        # --- UI superior (config) ---
        frm = ttk.Frame(self, padding=(10, 10))
        frm.pack(fill=tk.X)

        ttk.Label(frm, text="Rango/CIDR:").grid(row=0, column=0, sticky="w")
        self.var_range = tk.StringVar(value="192.168.1.1-192.168.1.50")
        ttk.Entry(frm, textvariable=self.var_range, width=35).grid(row=0, column=1, padx=5)

        ttk.Label(frm, text="Intervalo (s):").grid(row=0, column=2, padx=(10, 0))
        self.var_interval = tk.IntVar(value=120)
        ttk.Spinbox(frm, from_=10, to=3600, textvariable=self.var_interval, width=7).grid(row=0, column=3)

        ttk.Label(frm, text="Workers:").grid(row=0, column=4, padx=(10, 0))
        self.var_workers = tk.IntVar(value=64)
        ttk.Spinbox(frm, from_=1, to=512, textvariable=self.var_workers, width=7).grid(row=0, column=5)

        self.var_resolve = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Resolver nombres (DNS)", variable=self.var_resolve).grid(row=1, column=1, sticky="w", pady=5)

        self.var_tcp_fallback = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Fallback TCP si ICMP bloqueado", variable=self.var_tcp_fallback).grid(row=1, column=2, columnspan=2, sticky="w")

        # --- Botones ---
        btns = ttk.Frame(self, padding=(10, 0))
        btns.pack(fill=tk.X)

        self.btn_start = ttk.Button(btns, text="Iniciar", command=self.start)
        self.btn_start.pack(side=tk.LEFT)

        self.btn_stop = ttk.Button(btns, text="Detener", command=self.stop, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        ttk.Button(btns, text="Exportar CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Limpiar", command=self.clear_table).pack(side=tk.LEFT, padx=5)


        # --- Tabla ---
        table_frm = ttk.Frame(self, padding=10)
        table_frm.pack(fill=tk.BOTH, expand=True)

        columns = ("ip", "status", "rtt", "hostname", "timestamp", "method")
        self.tree = ttk.Treeview(table_frm, columns=columns, show="headings", height=20)
        self.tree.heading("ip", text="IP")
        self.tree.heading("status", text="Estado")
        self.tree.heading("rtt", text="RTT (ms)")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("method", text="Método")

        for c, w in [("ip", 140), ("status", 90), ("rtt", 80), ("hostname", 220), ("timestamp", 150), ("method", 90)]:
            self.tree.column(c, width=w, anchor=tk.W)

        vsb = ttk.Scrollbar(table_frm, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Estilos de filas por estado
        style = ttk.Style(self)
        # En algunos temas, mapear background no cambia; usamos tags
        self.tree.tag_configure("UP", background="#d1f5d3")    # verde claro
        self.tree.tag_configure("DOWN", background="#ffd7d7")  # rojo claro

        # DB
        db.init_db()

        # Cierre seguro
        self.protocol("WM_DELETE_WINDOW", self.on_close)


    # --- Acciones de UI ---
    def start(self):
        try:
            targets = parse_targets(self.var_range.get())
        except ValueError as e:
            messagebox.showerror("Entrada inválida", str(e))
            return
        self._running = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self._schedule_scan(initial=True)

    def stop(self):
        self._running = False
        if self._after_id is not None:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            title="Guardar resultados como CSV",
        )
        if not path:
            return

        # Recolecta filas actuales
        rows = []
        for iid in self.tree.get_children(""):
            vals = self.tree.item(iid, "values")
            # (ip, status, rtt, hostname, timestamp, method)
            rows.append(vals)
        try:
            export_to_csv(path, rows)
            messagebox.showinfo("Exportación", f"CSV guardado en:\n{path}")
        except Exception as ex:
            messagebox.showerror("Error al exportar", str(ex))

    def clear_table(self):
        self.tree.delete(*self.tree.get_children(""))
        self._rows_map.clear()

    def on_close(self):
        self.stop()
        self.destroy()

    # --- Lógica de escaneo/scheduler ---
    def _schedule_scan(self, initial: bool = False):
        if not self._running:
            return
        if initial:
            delay_ms = 100  # arranca de una vez
        else:
            delay_ms = max(50, self.var_interval.get() * 1000)
        self._after_id = self.after(delay_ms, self._do_scan_once)

    def _do_scan_once(self):
        if not self._running:
            return

        range_text = self.var_range.get().strip()
        try:
            ips = parse_targets(range_text)
        except ValueError as e:
            messagebox.showerror("Entrada inválida", str(e))
            self.stop()
            return

        started_at = time.time()
        self._current_scan_id = db.start_scan(started_at, range_text, self.var_interval.get())

        # Ejecuta escaneo en hilo aparte y actualiza UI con after()
        t = threading.Thread(
            target=self._scan_thread, args=(ips, self._current_scan_id, started_at), daemon=True
        )
        t.start()

    def _scan_thread(self, ips, scan_id, started_at):
        try:
            results = scan_batch(
                ips=ips,
                timeout_ms=800,
                max_workers=self.var_workers.get(),
                resolve_names=self.var_resolve.get(),
                tcp_fallback=self.var_tcp_fallback.get(),
            )
            # Persistencia en bloque
            db.save_results(
                scan_id,
                ((r.ip, r.status, r.rtt_ms, r.hostname, r.method, r.timestamp) for r in results),
            )
            # Actualiza UI
            self.after(0, self._apply_results_to_table, results)
        finally:
            db.end_scan(scan_id, time.time())
            # Programa siguiente ciclo
            self.after(0, self._schedule_scan, False)

    def _apply_results_to_table(self, results: list[ScanResult]):
        with self._lock:
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(results[0].timestamp)) if results else ""
            for r in results:
                values = (r.ip, r.status, f"{r.rtt_ms:.1f}" if r.rtt_ms is not None else "", r.hostname or "", ts_str, r.method)
                if r.ip in self._rows_map:
                    iid = self._rows_map[r.ip]
                    self.tree.item(iid, values=values, tags=(r.status,))
                else:
                    iid = self.tree.insert("", tk.END, values=values, tags=(r.status,))
                    self._rows_map[r.ip] = iid

