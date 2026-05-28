
import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
import sqlite3
import random
import time

DB_FILE = "rmla_lab.db"

# =========================================================
# HASH FUNCTION
# =========================================================

def h(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

# =========================================================
# 128-BIT RANDOM VALUES
# =========================================================

def random_hex_128():
    return ''.join(random.choices('0123456789abcdef', k=32))

# =========================================================
# ECC SIMULATION (320-BIT OUTPUT)
# =========================================================

def ecc_point(secret: str, P: str = "ECC_BASE_POINT"):

    x = h(secret + P)
    y = h(x)

    return (x + y)[:80]

# =========================================================
# XOR FUNCTION
# =========================================================

def xor_hex(a, b):

    max_len = max(len(a), len(b))

    a = a.zfill(max_len)
    b = b.zfill(max_len)

    return hex(int(a, 16) ^ int(b, 16))[2:].zfill(max_len)

# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    conn = sqlite3.connect(DB_FILE)

    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS ra(
            id INTEGER PRIMARY KEY,
            K TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS fog(
            fog_id TEXT PRIMARY KEY,
            ID_f TEXT,
            TID_f TEXT,
            A_f TEXT,
            r1 TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS devices(
            ID_d TEXT PRIMARY KEY,
            TID_d TEXT,
            A_d TEXT,
            B_k TEXT
        )
    """)

    conn.commit()

    # =====================================================
    # RA MASTER KEY
    # =====================================================

    c.execute("SELECT K FROM ra WHERE id=1")

    row = c.fetchone()

    if not row:

        K = random_hex_128()

        c.execute(
            "INSERT INTO ra(id,K) VALUES(1,?)",
            (K,)
        )

        conn.commit()

    # =====================================================
    # FOG INITIALIZATION
    # =====================================================

    c.execute("SELECT * FROM fog WHERE fog_id='fog01'")

    fog = c.fetchone()

    if not fog:

        ID_f = "fog01"

        r1 = random_hex_128()

        A_f = h(ID_f + r1)

        TID_f = h(ID_f + str(time.time()))

        c.execute("""
            INSERT INTO fog(
                fog_id,
                ID_f,
                TID_f,
                A_f,
                r1
            )
            VALUES(?,?,?,?,?)
        """,
        (
            "fog01",
            ID_f,
            TID_f,
            A_f,
            r1
        ))

        conn.commit()

    conn.close()

# =========================================================
# DEVICE REGISTRATION
# =========================================================

def register_device(ID_d):

    conn = sqlite3.connect(DB_FILE)

    c = conn.cursor()

    c.execute(
        "SELECT * FROM devices WHERE ID_d=?",
        (ID_d,)
    )

    if c.fetchone():

        conn.close()

        return False, "Device already registered."

    c.execute("SELECT K FROM ra WHERE id=1")

    K = c.fetchone()[0]

    c.execute("""
        SELECT A_f
        FROM fog
        WHERE fog_id='fog01'
    """)

    A_f = c.fetchone()[0]

    r2 = random_hex_128()

    A_d = h(ID_d + r2)

    TID_d = h(ID_d + str(time.time()))

    B_k = h(A_d + A_f + K)

    c.execute("""
        INSERT INTO devices(
            ID_d,
            TID_d,
            A_d,
            B_k
        )
        VALUES(?,?,?,?)
    """,
    (
        ID_d,
        TID_d,
        A_d,
        B_k
    ))

    conn.commit()

    conn.close()

    return True, f"{ID_d} registered successfully."

# =========================================================
# RMLA AUTHENTICATION
# =========================================================

def run_rmla_session(ID_d):

    conn = sqlite3.connect(DB_FILE)

    c = conn.cursor()

    # =====================================================
    # LOAD DEVICE
    # =====================================================

    c.execute("""
        SELECT
            TID_d,
            A_d,
            B_k
        FROM devices
        WHERE ID_d=?
    """,
    (ID_d,)
    )

    row = c.fetchone()

    if not row:

        conn.close()

        return False, "Device not found.", None

    TID_d, A_d, B_k = row

    # =====================================================
    # LOAD FOG
    # =====================================================

    c.execute("""
        SELECT
            TID_f,
            A_f
        FROM fog
        WHERE fog_id='fog01'
    """)

    row = c.fetchone()

    conn.close()

    TID_f, A_f = row

    # =====================================================
    # DEVICE SIDE
    # =====================================================

    rd = random_hex_128()
    re = random_hex_128()

    Td = str(time.time())

    I = ecc_point(re)

    Ed = xor_hex(
        rd,
        h(B_k + A_f + Td)
    )

    TID_d_new = h(
        xor_hex(TID_d, rd)
    )

    Gd = h(
        A_d +
        TID_d_new +
        B_k +
        Td +
        I
    )

    # =====================================================
    # FOG SIDE
    # =====================================================

    time.sleep(0.01)
    Tf = str(time.time())

    rd_star = xor_hex(
        Ed,
        h(B_k + A_f + Td)
    )

    rd_star = rd_star.zfill(64)
    rd = rd.zfill(64)

    TID_d_new_star = h(
        xor_hex(TID_d, rd_star)
    )

    Gd_star = h(
        A_d +
        TID_d_new_star +
        B_k +
        Td +
        I
    )

    if Gd != Gd_star:

        return False, "Device authentication failed.", None

    rf = random_hex_128()
    rg = random_hex_128()

    rf = rf.zfill(64)

    J = ecc_point(rg)

    Ef = xor_hex(
        rf,
        h(TID_d_new_star + B_k)
    )

    TID_f_new = h(
        xor_hex(TID_f, rf)
    )

    # =====================================================
    # SHARED SECRET
    # =====================================================

    shared_secret = h(I + J)

    # =====================================================
    # SESSION KEY (FOG)
    # =====================================================

    SK_fog = h(
        shared_secret +
        rd_star +
        rf +
        Tf +
        B_k
    )

    # =====================================================
    # FOG AUTHENTICATION TAG
    # =====================================================

    Gf = h(
        TID_f_new +
        B_k +
        rf +
        SK_fog +
        Tf +
        Ef
    )

    # =====================================================
    # DEVICE VERIFICATION
    # =====================================================

    rf_star = xor_hex(
        Ef,
        h(TID_d_new + B_k)
    )

    rf_star = rf_star.zfill(64)

    TID_f_new_star = h(
        xor_hex(TID_f, rf_star)
    )

    shared_secret_device = h(I + J)

    # =====================================================
    # SESSION KEY (DEVICE)
    # =====================================================

    SK_device = h(
        shared_secret_device +
        rd +
        rf_star +
        Tf +
        B_k
    )

    # =====================================================
    # VERIFY FOG
    # =====================================================

    Gf_star = h(
        TID_f_new_star +
        B_k +
        rf_star +
        SK_device +
        Tf +
        Ef
    )

    if Gf != Gf_star:

        return False, "Fog authentication failed.", None

    # =====================================================
    # ACKNOWLEDGMENT
    # =====================================================

    Ack = h(
        rf_star +
        B_k +
        SK_device
    )

    Ack_f = h(
        rf +
        B_k +
        SK_fog
    )

    mutual_auth = (Ack == Ack_f)

    # =====================================================
    # UPDATE DATABASE
    # =====================================================

    conn = sqlite3.connect(DB_FILE)

    c = conn.cursor()

    c.execute("""
        UPDATE devices
        SET TID_d=?
        WHERE ID_d=?
    """,
    (
        TID_d_new,
        ID_d
    ))

    c.execute("""
        UPDATE fog
        SET TID_f=?
        WHERE fog_id='fog01'
    """,
    (
        TID_f_new,
    ))

    conn.commit()

    conn.close()

    # =====================================================
    # LOGS
    # =====================================================

    logs = {

        "TID_d_old": TID_d,
        "TID_d_new": TID_d_new,

        "TID_f_old": TID_f,
        "TID_f_new": TID_f_new,

        "A_d": A_d,
        "A_f": A_f,
        "B_k": B_k,

        "rd": rd,
        "re": re,
        "rf": rf,
        "rg": rg,

        "Td": Td,
        "Tf": Tf,

        "I": I,
        "J": J,

        "Ed": Ed,
        "Ef": Ef,

        "Gd": Gd,
        "Gf": Gf,

        "SK_fog": SK_fog,
        "SK_device": SK_device,

        "Ack": Ack,
        "Ack_f": Ack_f,

        "Mutual": mutual_auth
    }

    return mutual_auth, "Authentication Successful.", logs

# =========================================================
# GUI
# =========================================================

class RMLAGUI:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "RMLA Laboratory — ECC-Based Authentication"
        )

        frame = tk.Frame(
            root,
            padx=10,
            pady=10
        )

        frame.pack()

        tk.Label(
            frame,
            text="Device ID:",
            font=("Arial", 12)
        ).grid(row=0, column=0)

        self.entry = tk.Entry(
            frame,
            width=25,
            font=("Arial", 12)
        )

        self.entry.grid(
            row=0,
            column=1,
            padx=10
        )

        tk.Button(
            frame,
            text="Register Device",
            width=20,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 11, "bold"),
            command=self.register_gui
        ).grid(
            row=1,
            column=0,
            pady=8
        )

        tk.Button(
            frame,
            text="Run Authentication",
            width=20,
            bg="#2196F3",
            fg="white",
            font=("Arial", 11, "bold"),
            command=self.run_gui
        ).grid(
            row=1,
            column=1,
            pady=8
        )

        tk.Button(
            frame,
            text="Save Log",
            width=45,
            bg="#FF9800",
            fg="white",
            font=("Arial", 11, "bold"),
            command=self.save_log
        ).grid(
            row=2,
            column=0,
            columnspan=2,
            pady=6
        )

        self.log = scrolledtext.ScrolledText(
            frame,
            width=120,
            height=40,
            font=("Courier New", 10)
        )

        self.log.grid(
            row=3,
            column=0,
            columnspan=2,
            pady=10
        )

        init_db()

    # =====================================================
    # REGISTER
    # =====================================================

    def register_gui(self):

        ID_d = self.entry.get().strip()

        if ID_d == "":

            messagebox.showwarning(
                "Error",
                "Enter Device ID."
            )

            return

        ok, msg = register_device(ID_d)

        if ok:

            messagebox.showinfo(
                "Success",
                msg
            )

            self.log.insert(
                tk.END,
                f"[REGISTER] {msg}\n\n"
            )

        else:

            messagebox.showerror(
                "Error",
                msg
            )

    # =====================================================
    # AUTHENTICATION
    # =====================================================

    def run_gui(self):

        ID_d = self.entry.get().strip()

        if ID_d == "":

            messagebox.showwarning(
                "Error",
                "Enter Device ID first."
            )

            return

        ok, msg, logs = run_rmla_session(ID_d)

        self.log.delete("1.0", tk.END)

        self.log.insert(
            tk.END,
            "================ RMLA SESSION ================\n\n"
        )

        self.log.insert(
            tk.END,
            f"{msg}\n\n"
        )

        if logs is None:

            self.log.insert(
                tk.END,
                "No logs available.\n"
            )

            return

        self.log.insert(
            tk.END,
            "---------------- TEMPORARY IDENTITY UPDATES ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"TID_d_old : {logs['TID_d_old']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"TID_d_new : {logs['TID_d_new']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"TID_f_old : {logs['TID_f_old']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"TID_f_new : {logs['TID_f_new']}\n\n"
        )

        self.log.insert(
            tk.END,
            "---------------- STORED PARAMETERS ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"A_d : {logs['A_d']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"A_f : {logs['A_f']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"B_k : {logs['B_k']}\n\n"
        )

        self.log.insert(
            tk.END,
            "---------------- NONCES (128-BIT) ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"rd : {logs['rd']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"re : {logs['re']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"rf : {logs['rf']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"rg : {logs['rg']}\n\n"
        )

        self.log.insert(
            tk.END,
            "---------------- ECC VALUES (320-BIT) ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"I : {logs['I']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"J : {logs['J']}\n\n"
        )

        self.log.insert(
            tk.END,
            "---------------- AUTHENTICATION PARAMETERS ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"Ed : {logs['Ed']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"Ef : {logs['Ef']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"Gd : {logs['Gd']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"Gf : {logs['Gf']}\n\n"
        )

        self.log.insert(
            tk.END,
            "---------------- TIMESTAMPS ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"Td : {logs['Td']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"Tf : {logs['Tf']}\n\n"
        )

        self.log.insert(
            tk.END,
            "---------------- SESSION KEY AGREEMENT ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"SK_fog : {logs['SK_fog']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"SK_device : {logs['SK_device']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"Verification : {logs['SK_fog'] == logs['SK_device']}\n\n"
        )

        self.log.insert(
            tk.END,
            "---------------- MUTUAL AUTHENTICATION ----------------\n"
        )

        self.log.insert(
            tk.END,
            f"Ack : {logs['Ack']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"Ack_f : {logs['Ack_f']}\n\n"
        )

        self.log.insert(
            tk.END,
            f"Success : {logs['Mutual']}\n\n"
        )

        self.log.insert(
            tk.END,
            "================ END SESSION ================\n"
        )

    # =====================================================
    # SAVE LOG
    # =====================================================

    def save_log(self):

        content = self.log.get(
            "1.0",
            tk.END
        )

        with open(
            "rmla_output.txt",
            "w",
            encoding="utf-8"
        ) as f:

            f.write(content)

        messagebox.showinfo(
            "Saved",
            "Execution log saved as rmla_output.txt"
        )

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    root = tk.Tk()

    gui = RMLAGUI(root)

    root.mainloop()

