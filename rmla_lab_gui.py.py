import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
import sqlite3
import os
import time
import random

DB_FILE = "rmla_lab.db"

# -------------------------------------------
# Helper functions
# -------------------------------------------

def h(data: str) -> str:
    """SHA-256 hash"""
    return hashlib.sha256(data.encode()).hexdigest()

def random_hex(n: int) -> str:
    """Generate n-digit hex"""
    return ''.join(random.choices('abcdef0123456789', k=n))

def xor_hex(a: str, b: str) -> str:
    """Hex XOR"""
    return hex(int(a, 16) ^ int(b, 16))[2:]


# -------------------------------------------
# Initialize Database + RA + Fog initialization
# -------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Table for RA storing master key K
    c.execute("""
        CREATE TABLE IF NOT EXISTS ra (
            id INTEGER PRIMARY KEY,
            K TEXT
        )
    """)

    # Fog table
    c.execute("""
        CREATE TABLE IF NOT EXISTS fog (
            fog_id TEXT PRIMARY KEY,
            ID_f TEXT,
            TID_f TEXT,
            A_f TEXT,
            r1 TEXT
        )
    """)

    # IoT devices
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ID_d TEXT PRIMARY KEY,
            TID_d TEXT,
            A_d TEXT,
            B_k TEXT
        )
    """)

    conn.commit()

    # ---------------------------------------
    # Generate master key K (only if RA empty)
    # ---------------------------------------
    c.execute("SELECT K FROM ra WHERE id=1")
    row = c.fetchone()

    if not row:
        K = random_hex(32)
        c.execute("INSERT INTO ra (id, K) VALUES (1, ?)", (K,))
        conn.commit()

    # ---------------------------------------
    # Fog initialization (only once)
    # ---------------------------------------
    c.execute("SELECT * FROM fog WHERE fog_id='fog01'")
    fog = c.fetchone()

    if not fog:
        ID_f = "fog01"
        r1 = random_hex(16)
        A_f = h(ID_f + r1)
        TID_f = h(ID_f + str(time.time()))

        c.execute("""
            INSERT INTO fog (fog_id, ID_f, TID_f, A_f, r1)
            VALUES (?, ?, ?, ?, ?)
        """, ("fog01", ID_f, TID_f, A_f, r1))
        conn.commit()

    conn.close()
# ============================================
# PART 2 — Registration Phase + Authentication Phase
# ============================================

# -----------------------------------------------------
# Registration (IoT Device Initialization)
# -----------------------------------------------------
def register_device(ID_d: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Check if device already exists
    c.execute("SELECT ID_d FROM devices WHERE ID_d=?", (ID_d,))
    if c.fetchone():
        conn.close()
        return False, "Device already exists."

    # Get master key K from RA
    c.execute("SELECT K FROM ra WHERE id=1")
    K = c.fetchone()[0]

    # Device generates random r2 → A_d = h(ID_d ∥ r2)
    r2 = random_hex(16)
    A_d = h(ID_d + r2)

    # RA creates TID_d
    TID_d = h(ID_d + str(time.time()))

    # RA computes B_k = h(A_d ∥ K)
    B_k = h(A_d + K)

    # Store device
    c.execute("""
        INSERT INTO devices (ID_d, TID_d, A_d, B_k)
        VALUES (?, ?, ?, ?)
    """, (ID_d, TID_d, A_d, B_k))

    conn.commit()
    conn.close()

    return True, f"Device {ID_d} registered successfully."


# -----------------------------------------------------
# AUTHENTICATION — Full RMLA Protocol
# -----------------------------------------------------
def run_rmla_session(ID_d: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Load device parameters
    c.execute("SELECT TID_d, A_d, B_k FROM devices WHERE ID_d=?", (ID_d,))
    row = c.fetchone()

    if not row:
        conn.close()
        return False, "Device not found.", None

    TID_d, A_d, B_k = row

    # Load fog parameters
    c.execute("SELECT TID_f, A_f FROM fog WHERE fog_id='fog01'")
    fog = c.fetchone()
    conn.close()

    TID_f, A_f = fog

    # --------------------------------------------------
    # Step 1 — IoT Device Generates Authentication Request
    # --------------------------------------------------
    r_d = random_hex(16)
    T_d = str(time.time())

    C_d = h(T_d + r_d)
    E_d = xor_hex(r_d, h(B_k + A_f))      # r_d XOR h(B_k ∥ A_f)

    TID_d_new = h(TID_d + r_d)

    G_d = h(
        TID_d_new +
        B_k +
        r_d +
        T_d +
        C_d +
        E_d
    )

    # AuthReq = {TID_d, T_d, C_d, E_d, G_d}

    # --------------------------------------------------
    # Step 2 — Fog Node Verification and Response
    # --------------------------------------------------

    # Recover r_d*
    r_d_star = xor_hex(E_d, h(B_k + A_f))

    # Check C_d
    C_d_star = h(T_d + r_d_star)
    if C_d_star != C_d:
        return False, "C_d mismatch — message tampering detected.", None

    # Update TID_d
    TID_d_new_final = h(TID_d + r_d_star)

    # Generate fog-side values
    r_f = random_hex(16)
    T_f = str(time.time())
    T_s = str(time.time())

    C_f = h(T_f + r_f)
    E_f = xor_hex(r_f, h(TID_d_new_final + B_k))
    TID_f_new = h(TID_f + r_f)

    # Session Key
    SK = h(r_d_star + r_f + T_s + B_k)

    G_f = h(
        TID_f_new +
        B_k +
        r_f +
        SK +
        T_s +
        T_f +
        C_f +
        E_f
    )

    # AuthRep = {TID_f, T_f, T_s, C_f, E_f, G_f}

    # --------------------------------------------------
    # Step 3 — Device Verification
    # --------------------------------------------------

    # Recover r_f*
    r_f_star = xor_hex(E_f, h(TID_d_new + B_k))

    # Check C_f*
    C_f_star = h(T_f + r_f_star)
    if C_f_star != C_f:
        return False, "Fog authentication failed (C_f mismatch).", None

    # Device computes SK*
    SK_u = h(r_d + r_f_star + T_s + B_k)

    # --------------------------------------------------
    # Step 4 — Final Mutual Authentication (Ack)
    # --------------------------------------------------
    Ack = h(SK_u + "ACK")
    Ack_f = h(SK + "ACK")

    mutual = (Ack == Ack_f)

    # --------------------------------------------------
    # Update identities after successful authentication
    # --------------------------------------------------
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE devices SET TID_d=? WHERE ID_d=?", (TID_d_new, ID_d))
    c.execute("UPDATE fog SET TID_f=? WHERE fog_id='fog01'", (TID_f_new,))
    conn.commit()
    conn.close()

    logs = {
        "TID_d_old": TID_d,
        "TID_d_new": TID_d_new,
        "TID_f_old": TID_f,
        "TID_f_new": TID_f_new,
        "r_d": r_d,
        "C_d": C_d,
        "E_d": E_d,
        "G_d": G_d,
        "r_f": r_f,
        "C_f": C_f,
        "E_f": E_f,
        "G_f": G_f,
        "T_d": T_d,
        "T_f": T_f,
        "T_s": T_s,
        "SK_fog": SK,
        "SK_device": SK_u,
        "Ack": Ack,
        "Ack_f": Ack_f,
        "Mutual_Auth_Success": mutual
    }

    return mutual, "Authentication session completed.", logs
# ============================================
# PART 3 — FULL TKINTER GUI FOR RMLA LAB
# ============================================
# ============================================
# PART 3 — FULL TKINTER GUI FOR RMLA LAB (FINAL VERSION WITH SAVE LOG)
# ============================================

class RMLAGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RMLA Laboratory — Full Authentication Protocol Demo")

        frame = tk.Frame(root, padx=12, pady=12)
        frame.pack()

        # Device ID input
        tk.Label(frame, text="Device ID:", font=("Arial", 11)).grid(row=0, column=0)
        self.entry_id = tk.Entry(frame, width=22, font=("Arial", 11))
        self.entry_id.grid(row=0, column=1, padx=5, pady=3)

        # Buttons
        tk.Button(
            frame,
            text="Register Device",
            width=18,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.gui_register_device
        ).grid(row=1, column=0, pady=6)

        tk.Button(
            frame,
            text="Run Authentication",
            width=18,
            bg="#2196F3",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.gui_run_auth
        ).grid(row=1, column=1, pady=6)

        # NEW BUTTON: Save Log
        tk.Button(
            frame,
            text="Save Log",
            width=38,
            bg="#FF9800",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.save_log
        ).grid(row=2, column=0, columnspan=2, pady=5)

        # Log window
        self.log = scrolledtext.ScrolledText(frame, width=90, height=28, font=("Courier New", 10))
        self.log.grid(row=3, column=0, columnspan=2, pady=10)

        # Initialize DB & RA & Fog
        init_db()

    # -------------------------------------------------
    # GUI: Register Device
    # -------------------------------------------------
    def gui_register_device(self):
        ID_d = self.entry_id.get().strip()
        if ID_d == "":
            messagebox.showwarning("Error", "Enter a Device ID.")
            return

        ok, msg = register_device(ID_d)
        if ok:
            messagebox.showinfo("Success", msg)
            self.log.insert(tk.END, f"[REGISTER] {msg}\n\n")
        else:
            messagebox.showerror("Error", msg)

    # -------------------------------------------------
    # GUI: Run Full RMLA Authentication Session
    # -------------------------------------------------
    def gui_run_auth(self):
        ID_d = self.entry_id.get().strip()
        if ID_d == "":
            messagebox.showwarning("Error", "Enter Device ID first.")
            return

        ok, msg, logs = run_rmla_session(ID_d)

        # Clear log
        self.log.delete("1.0", tk.END)
        self.log.insert(tk.END, f"=== RMLA Authentication Session ===\n")
        self.log.insert(tk.END, f"{msg}\n\n")

        if not logs:
            self.log.insert(tk.END, "No logs available.\n")
            return

        # Pretty printing logs
        self.log.insert(tk.END, "--- Temporary Identity Update ---\n")
        self.log.insert(tk.END, f"TID_d_old : {logs['TID_d_old']}\n")
        self.log.insert(tk.END, f"TID_d_new : {logs['TID_d_new']}\n")
        self.log.insert(tk.END, f"TID_f_old : {logs['TID_f_old']}\n")
        self.log.insert(tk.END, f"TID_f_new : {logs['TID_f_new']}\n\n")

        self.log.insert(tk.END, "--- IoT Device Message Generation ---\n")
        self.log.insert(tk.END, f"r_d       : {logs['r_d']}\n")
        self.log.insert(tk.END, f"C_d       : {logs['C_d']}\n")
        self.log.insert(tk.END, f"E_d       : {logs['E_d']}\n")
        self.log.insert(tk.END, f"G_d       : {logs['G_d']}\n\n")

        self.log.insert(tk.END, "--- Fog Node Message Generation ---\n")
        self.log.insert(tk.END, f"r_f       : {logs['r_f']}\n")
        self.log.insert(tk.END, f"C_f       : {logs['C_f']}\n")
        self.log.insert(tk.END, f"E_f       : {logs['E_f']}\n")
        self.log.insert(tk.END, f"G_f       : {logs['G_f']}\n\n")

        self.log.insert(tk.END, "--- Session Parameters ---\n")
        self.log.insert(tk.END, f"T_d       : {logs['T_d']}\n")
        self.log.insert(tk.END, f"T_f       : {logs['T_f']}\n")
        self.log.insert(tk.END, f"T_s       : {logs['T_s']}\n\n")

        self.log.insert(tk.END, "--- Session Key Agreement ---\n")
        self.log.insert(tk.END, f"SK (Fog)   : {logs['SK_fog']}\n")
        self.log.insert(tk.END, f"SK (Device): {logs['SK_device']}\n\n")

        self.log.insert(tk.END, "--- Mutual Authentication ---\n")
        self.log.insert(tk.END, f"Ack    : {logs['Ack']}\n")
        self.log.insert(tk.END, f"Ack_f  : {logs['Ack_f']}\n")
        self.log.insert(tk.END, f"Success: {logs['Mutual_Auth_Success']}\n\n")

        self.log.insert(tk.END, "=== END OF SESSION ===\n\n")
        self.log.see(tk.END)

    # -------------------------------------------------
    # NEW FUNCTION: Save Log to File
    # -------------------------------------------------
    def save_log(self):
        content = self.log.get("1.0", tk.END)
        with open("rmla_output.txt", "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Saved", "Execution log saved as rmla_output.txt")


# ============================================
# MAIN EXECUTION
# ============================================

if __name__ == "__main__":
    root = tk.Tk()
    gui = RMLAGUI(root)
    root.mainloop()
