#!/usr/bin/env python3
"""
tk_runner_internal.py
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from threading import Thread
import queue
import ipaddress
import time
import traceback

def parse_ips(text):
    raw = [s.strip() for s in text.replace(",", "\n").splitlines() if s.strip()]
    ips = []
    errors = []
    for i, val in enumerate(raw, start=1):
        try:
            ipaddress.ip_address(val)
            ips.append(val)
        except Exception:
            errors.append(f"Line {i}: '{val}' is not a valid IP")
    return ips, errors

def big_function(ips, checkbox_on, logger):
    """
    Example placeholder for a function.
    - ips: list of strings (IP addresses)
    - checkbox_on: boolean
    - logger: callable
    """
    logger("big_function: starting")
    logger(f"big_function: checkbox is {'ON' if checkbox_on else 'OFF'}")
    logger(f"big_function: received {len(ips)} IP(s): {', '.join(ips) if ips else '<none>'}")
    for i in range(1, 6):
        time.sleep(0.6)  # replace with real work
        logger(f"big_function: step {i}/5 complete")
    logger("big_function: finished successfully")
    return {"status": "ok", "processed_ips": len(ips)}


def script_a_impl(ips, checkbox_on, logger):
cript_a_impl: starting")
    result = big_function(ips, checkbox_on, logger)
    logger(f"script_a_impl: big_function returned: {result}")
    logger("script_a_impl: done")

def script_b_impl(ips, checkbox_on, logger):
    logger("script_b_impl: starting")
    for ip in ips:
        logger(f"script_b_impl: processing {ip}")
        time.sleep(0.4)   # pretend to do some per-IP work
        logger(f"script_b_impl: done {ip}")
    if not ips:
        logger("script_b_impl: no IPs provided; nothing done.")
    logger("script_b_impl: finished")

def run_internal_function(func, q, tag, checkbox_on, ips):
    def logger(msg):
        q.put(("log", tag, msg))

    q.put(("log", tag, f"--- Worker {tag} starting at {time.strftime('%H:%M:%S')} ---"))
    try:
        func(ips, checkbox_on, logger)
    except Exception as exc:
        tb = traceback.format_exc()
        q.put(("error", tag, f"Exception in worker {tag}: {exc}"))
        q.put(("error", tag, tb))
    finally:
        q.put(("log", tag, f"--- Worker {tag} finished at {time.strftime('%H:%M:%S')} ---"))
        q.put(("done", tag, 0))

# ---------- Tkinter App ----------
class RunnerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Tk Internal Script Runner")
        self.geometry("820x580")
        self.resizable(True, True)

        self.q = queue.Queue()
        self.active = {"A": False, "B": False}  # track running jobs

        self._build_ui()
        # startup log
        self._append_log("App started. Use 'Run Script A' or 'Run Script B' to execute internal functions.")
        self._poll_queue()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", **pad)

        self.toggle_var = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(top_frame, text="Enable feature (True/False)", variable=self.toggle_var)
        chk.grid(column=0, row=0, sticky="w")

        ttk.Label(self, text="Enter IPs (comma or newline separated):").pack(anchor="w", padx=8)
        self.ips_text = tk.Text(self, height=4, wrap="none")
        self.ips_text.pack(fill="x", padx=8)
        self.ips_text.insert("1.0", "192.168.1.1, 8.8.8.8")  # example default

        sframe = ttk.Frame(self)
        sframe.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Label(sframe, text="Script A (hardcoded):").grid(row=0, column=0, sticky="w")
        ttk.Label(sframe, text="(calls script_a_impl inside this file)").grid(row=0, column=1, sticky="w", padx=6)
        self.run_a_btn = ttk.Button(sframe, text="Run Script A", command=lambda: self._on_run("A"))
        self.run_a_btn.grid(row=1, column=0, padx=6, pady=6)

        sframe2 = ttk.Frame(self)
        sframe2.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Label(sframe2, text="Script B (hardcoded):").grid(row=0, column=0, sticky="w")
        ttk.Label(sframe2, text="(calls script_b_impl inside this file)").grid(row=0, column=1, sticky="w", padx=6)
        self.run_b_btn = ttk.Button(sframe2, text="Run Script B", command=lambda: self._on_run("B"))
        self.run_b_btn.grid(row=1, column=0, padx=6, pady=6)

        ctrl_frame = ttk.Frame(self)
        ctrl_frame.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Button(ctrl_frame, text="Validate IPs", command=self._validate_ips).pack(side="left")
        self.status_lbl = ttk.Label(ctrl_frame, text="Idle")
        self.status_lbl.pack(side="right")

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=8, pady=8)

        # Log area
        ttk.Label(self, text="Output / Log:").pack(anchor="w", padx=8)
        self.log = ScrolledText(self, height=18, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def _append_log(self, text, tag=None):
        prefix = f"[{tag}] " if tag else ""
        print(prefix + text)
        self.log.configure(state="normal")
        self.log.insert("end", prefix + text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _validate_ips(self):
        ips_text = self.ips_text.get("1.0", "end").strip()
        ips, errors = parse_ips(ips_text)
        if errors:
            self._append_log("IP validation failed:")
            for e in errors:
                self._append_log(e)
            self.status_lbl.config(text="IP validation failed")
        else:
            self._append_log("All IPs valid: " + (", ".join(ips) or "<none>"))
            self.status_lbl.config(text=f"{len(ips)} IP(s) valid")

    def _on_run(self, tag):
        """
        When Run Script A/B pressed:
        - validate IPs
        - pick right internal function
        - start a daemon thread to run run_internal_function(...)
        """
        if self.active[tag]:
            messagebox.showinfo("Already running", f"Script {tag} is already running.")
            return

        ips_text = self.ips_text.get("1.0", "end").strip()
        ips, errors = parse_ips(ips_text)
        if errors:
            self._append_log("IP validation failed, not starting script:")
            for e in errors:
                self._append_log(e)
            return

        func = script_a_impl if tag == "A" else script_b_impl

        self.active[tag] = True
        self.status_lbl.config(text=f"Running script {tag}...")
        if tag == "A":
            self.run_a_btn.config(state="disabled")
        else:
            self.run_b_btn.config(state="disabled")

        self._append_log(f"Starting background thread for script {tag}", tag)
        t = Thread(target=run_internal_function, args=(func, self.q, tag, self.toggle_var.get(), ips), daemon=True)
        t.start()

    def _poll_queue(self):
        try:
            while True:
                typ, tag, payload = self.q.get_nowait()
                if typ == "log":
                    self._append_log(payload, tag)
                elif typ == "error":
                    self._append_log("[ERROR] " + payload, tag)
                elif typ == "done":
                    self._append_log(f"Worker {tag} signalled done (code {payload})", tag)
                    self.active[tag] = False
                    if tag == "A":
                        self.run_a_btn.config(state="normal")
                    else:
                        self.run_b_btn.config(state="normal")
                    self.status_lbl.config(text="Idle")
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

if __name__ == "__main__":
    app = RunnerApp()
    app.mainloop()
