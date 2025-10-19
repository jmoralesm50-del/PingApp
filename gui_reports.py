import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from app.data import db
from app.reports.csv_export import export_to_csv

class ReportViewer(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Reportes anteriores")
        self.geometry("800x500")

        self.tree_scans = ttk.Treeview(self, columns=("id", "started", "ended", "range"), show="headings", height=8)
        for col in ("id", "started", "ended", "range"):
            self.tree_scans.heading(col, text=col.capitalize())
            self.tree_scans.column(col, width=150)
        self.tree_scans.pack(fill=tk.X, padx=10, pady=5)
        self.tree_scans.bind("<<TreeviewSelect>>", self.load_results)

        self.tree_results = ttk.Treeview(self, columns=("ip", "status", "rtt", "hostname", "timestamp", "method"), show="headings", height=15)
        for col in self.tree_results["columns"]:
            self.tree_results.heading(col, text=col.capitalize())
            self.tree_results.column(col, width=120)
        self.tree_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_export = ttk.Button(self, text="Exportar CSV", command=self.export_csv)
        btn_export.pack(pady=5)

        self.load_scans()

    def load_scans(self):
        with db._conn() as con:
            rows = con.execute("SELECT id, started_at, ended_at, range_text FROM scans ORDER BY started_at DESC").fetchall()
        for row in rows:
            self.tree_scans.insert("", tk.END, values=row)

    def load_results(self, event):
        selected = self.tree_scans.selection()
        if not selected:
            return
        scan_id = self.tree_scans.item(selected[0])["values"][0]
        with db._conn() as con:
            rows = con.execute("SELECT ip, status, rtt_ms, hostname, seen_at, method FROM scan_results WHERE scan_id = ?", (scan_id,)).fetchall()
        self.tree_results.delete(*self.tree_results.get_children())
        for row in rows:
            self.tree_results.insert("", tk.END, values=row)

    def export_csv(self):
        rows = [self.tree_results.item(iid)["values"] for iid in self.tree_results.get_children()]
        if not rows:
            messagebox.showinfo("Exportación", "No hay datos para exportar.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            export_to_csv(path, rows)
            messagebox.showinfo("Exportación", f"CSV guardado en:\n{path}")