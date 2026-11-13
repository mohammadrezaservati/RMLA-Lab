"""
RMLA Laboratory — revised implementation aligned with the supplied RMLA
message flow and key-evolution description.

Dependency:
    pip install cryptography

Notes:
- The ECC operations use real P-256 ECDH (SECP256R1), not a hash-based mock.
- Registration-channel confidentiality is represented by direct provisioning
  inside this laboratory application; no network transport is implemented.
- Device and Fog state are stored in separate SQLite tables to model their
  independent protocol state.
- The optional "Simulate lost Ack" control demonstrates pending-key recovery.
"""

import hashlib
import secrets
import sqlite3
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


DB_FILE = "rmla_lab_revised.sqlite"
FOG_ID = "fog01"
DELTA_T = 60.0
CURVE = ec.SECP256R1()

# Order of the NIST P-256 curve. Scalars are sampled uniformly from [1, n-1].
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    "BCE6FAADA7179E84F3B9CAC2FC632551", 16
)


# =========================================================
# BASIC CRYPTOGRAPHIC HELPERS
# =========================================================

def h(data: str) -> str:
    """SHA-256 over the exact concatenation used in the protocol formulas."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def random_hex_256() -> str:
    """Uniform 256-bit random value."""
    return secrets.token_hex(32)


def xor_hex(a: str, b: str) -> str:
    """XOR two equal-width hexadecimal strings."""
    if len(a) != len(b):
        raise ValueError("XOR operands must have equal hexadecimal width.")
    return format(int(a, 16) ^ int(b, 16), f"0{len(a)}x")


def new_ecc_keypair():
    """Generate a fresh P-256 private/public key pair."""
    scalar = secrets.randbelow(P256_ORDER - 1) + 1
    private_key = ec.derive_private_key(scalar, CURVE)
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return private_key, public_bytes.hex()


def decode_ecc_point(point_hex: str):
    """Decode an uncompressed P-256 point."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        CURVE, bytes.fromhex(point_hex)
    )


def ecdh_shared_secret(private_key, peer_point_hex: str) -> str:
    """
    Compute the P-256 ECDH shared secret.
    Both sides obtain the same ECDH output, corresponding to the shared
    elliptic-curve point represented in the protocol by r_g*I = r_e*J.
    """
    peer_public = decode_ecc_point(peer_point_hex)
    return private_key.exchange(ec.ECDH(), peer_public).hex()


def timestamp_now() -> str:
    # Fixed decimal representation makes the timestamp encoding unambiguous.
    return f"{time.time():.6f}"


def is_fresh(received_timestamp: str, now: float, delta: float = DELTA_T) -> bool:
    try:
        return abs(now - float(received_timestamp)) <= delta
    except (TypeError, ValueError):
        return False


# =========================================================
# DATABASE
# =========================================================

def db_connect():
    return sqlite3.connect(DB_FILE)


def init_db():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ra (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            master_key TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS fog (
            fog_id TEXT PRIMARY KEY,
            ID_f TEXT NOT NULL,
            TID_f TEXT NOT NULL,
            A_f TEXT NOT NULL,
            r1 TEXT NOT NULL
        )
    """)

    # RA repositories: the RA retains the registered pseudonymous records.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ra_fog (
            fog_id TEXT PRIMARY KEY,
            TID_f TEXT NOT NULL,
            A_f TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ra_devices (
            ID_d TEXT PRIMARY KEY,
            A_d TEXT NOT NULL,
            TID_d TEXT NOT NULL,
            B_k TEXT NOT NULL
        )
    """)

    # Device-side state. This table represents credentials stored by D_j.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ID_d TEXT PRIMARY KEY,
            TID_d TEXT NOT NULL,
            A_d TEXT NOT NULL,
            B_k TEXT NOT NULL,
            TID_f TEXT NOT NULL,
            A_f TEXT NOT NULL
        )
    """)

    # Fog-side state is stored separately from the Device-side state.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS fog_devices (
            ID_d TEXT PRIMARY KEY,
            TID_d TEXT NOT NULL,
            A_d TEXT NOT NULL,
            B_k TEXT NOT NULL,
            TID_f TEXT NOT NULL,
            A_f TEXT NOT NULL,
            old_B_k TEXT,
            pending_TID_d TEXT,
            pending_TID_f TEXT,
            pending_B_k TEXT
        )
    """)

    cur.execute("SELECT master_key FROM ra WHERE id=1")
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO ra(id, master_key) VALUES(1, ?)",
            (random_hex_256(),)
        )

    cur.execute("SELECT fog_id FROM fog WHERE fog_id=?", (FOG_ID,))
    if cur.fetchone() is None:
        ID_f = FOG_ID
        r1 = random_hex_256()
        A_f = h(ID_f + r1)
        TID_f = h(ID_f + timestamp_now() + random_hex_256())
        cur.execute(
            "INSERT INTO fog(fog_id, ID_f, TID_f, A_f, r1) "
            "VALUES(?,?,?,?,?)",
            (FOG_ID, ID_f, TID_f, A_f, r1)
        )
        cur.execute(
            "INSERT OR REPLACE INTO ra_fog(fog_id, TID_f, A_f) "
            "VALUES(?,?,?)",
            (FOG_ID, TID_f, A_f)
        )

    # Keep the RA repository synchronized if this is an existing database.
    cur.execute("SELECT TID_f, A_f FROM fog WHERE fog_id=?", (FOG_ID,))
    current_fog = cur.fetchone()
    if current_fog is not None:
        cur.execute(
            "INSERT OR REPLACE INTO ra_fog(fog_id, TID_f, A_f) VALUES(?,?,?)",
            (FOG_ID, current_fog[0], current_fog[1])
        )

    conn.commit()
    conn.close()


# =========================================================
# REGISTRATION — RA PROVISIONS DEVICE AND FOG
# =========================================================

def register_device(ID_d: str):
    ID_d = ID_d.strip()
    if not ID_d:
        return False, "Device ID cannot be empty."

    conn = db_connect()
    cur = conn.cursor()

    cur.execute("SELECT ID_d FROM devices WHERE ID_d=?", (ID_d,))
    if cur.fetchone():
        conn.close()
        return False, "Device already registered."

    cur.execute("SELECT master_key FROM ra WHERE id=1")
    ra_row = cur.fetchone()
    cur.execute(
        "SELECT ID_f, TID_f, A_f FROM fog WHERE fog_id=?",
        (FOG_ID,)
    )
    fog_row = cur.fetchone()

    if ra_row is None or fog_row is None:
        conn.close()
        return False, "RA or Fog initialization is missing."

    # K is retained by RA as a system master key. B_k is generated
    # independently and is NOT derived from K.
    ID_f, TID_f, A_f = fog_row

    r2 = random_hex_256()
    A_d = h(ID_d + r2)
    TID_d = h(ID_d + timestamp_now() + random_hex_256())
    B_k = random_hex_256()

    # RA stores (A_d, TID_d, B_k) in its repository.
    cur.execute("""
        INSERT INTO ra_devices(ID_d, A_d, TID_d, B_k)
        VALUES(?,?,?,?)
    """, (ID_d, A_d, TID_d, B_k))

    # RA provisions Device and Fog over the assumed secure registration link.
    cur.execute("""
        INSERT INTO devices(ID_d, TID_d, A_d, B_k, TID_f, A_f)
        VALUES(?,?,?,?,?,?)
    """, (ID_d, TID_d, A_d, B_k, TID_f, A_f))

    cur.execute("""
        INSERT INTO fog_devices(
            ID_d, TID_d, A_d, B_k, TID_f, A_f,
            old_B_k, pending_TID_d, pending_TID_f, pending_B_k
        ) VALUES(?,?,?,?,?,?,NULL,NULL,NULL,NULL)
    """, (ID_d, TID_d, A_d, B_k, TID_f, A_f))

    conn.commit()
    conn.close()
    return True, (
        f"{ID_d} registered successfully.\n"
        "RA provisioned the Device and Fog with the device-specific "
        "credential B_k."
    )


# =========================================================
# RMLA AUTHENTICATION AND KEY AGREEMENT
# =========================================================

def run_rmla_session(ID_d: str, simulate_lost_ack: bool = False):
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        SELECT TID_d, A_d, B_k, TID_f, A_f
        FROM devices WHERE ID_d=?
    """, (ID_d,))
    drow = cur.fetchone()

    cur.execute("""
        SELECT TID_d, A_d, B_k, TID_f, A_f,
               pending_TID_d, pending_TID_f, pending_B_k
        FROM fog_devices WHERE ID_d=?
    """, (ID_d,))
    frow = cur.fetchone()
    conn.close()

    if drow is None or frow is None:
        return False, "Device is not registered at both Device and Fog.", None

    (d_TID_d, d_A_d, d_B_k, d_TID_f, d_A_f) = drow
    (f_TID_d, f_A_d, f_B_k, f_TID_f, f_A_f,
     pending_TID_d, pending_TID_f, pending_B_k) = frow

    logs = {
        "Protocol": "RMLA — Initialization, Registration, Mutual Authentication",
        "Device": ID_d,
        "Fog": FOG_ID,
        "Delta_T_seconds": DELTA_T,
    }

    # -----------------------------------------------------
    # DEVICE: generate r_d, r_e, T_d and Auth_Req
    # -----------------------------------------------------
    rd = random_hex_256()
    re_private, I = new_ecc_keypair()
    Td = timestamp_now()

    Ed = xor_hex(rd, h(d_B_k + d_A_f + Td))
    TID_d_new = h(xor_hex(d_TID_d, rd))
    Gd = h(d_A_d + TID_d_new + d_B_k + Td + I)

    logs.update({
        "Device_r_d": rd,
        "Device_T_d": Td,
        "I = r_e.P (P-256 public point)": I,
        "E_d": Ed,
        "TID_d_new": TID_d_new,
        "G_d": Gd,
        "Auth_Req": "{TID_d, T_d, E_d, G_d, I}",
    })

    # -----------------------------------------------------
    # FOG: select active or pending state, then authenticate D_j
    # -----------------------------------------------------
    # If the previous Ack was lost, the Device has already advanced its
    # state. The next request will carry pending_TID_d and pending_B_k.
    recovering_pending = (
        pending_TID_d is not None
        and pending_B_k is not None
        and d_TID_d == pending_TID_d
        and d_B_k == pending_B_k
    )

    if recovering_pending:
        use_TID_d = pending_TID_d
        use_TID_f = pending_TID_f
        use_B_k = pending_B_k
        logs["Synchronization"] = (
            "Pending state detected. Fog will verify the request using "
            "the pending credentials and promote them after verification."
        )
    else:
        use_TID_d = f_TID_d
        use_TID_f = f_TID_f
        use_B_k = f_B_k
        logs["Synchronization"] = "No pending update detected."

    Tf = timestamp_now()
    if not is_fresh(Td, time.time(), DELTA_T):
        return False, "Fog rejected Auth_Req: device timestamp is stale.", logs

    if d_TID_d != use_TID_d or d_TID_f != use_TID_f or d_B_k != use_B_k:
        return False, (
            "Device/Fog state mismatch. The stored temporary identities "
            "or device-specific secret are not synchronized."
        ), logs

    rd_star = xor_hex(Ed, h(use_B_k + f_A_f + Td))
    TID_d_new_star = h(xor_hex(use_TID_d, rd_star))
    Gd_star = h(f_A_d + TID_d_new_star + use_B_k + Td + I)

    logs.update({
        "Fog_T_f": Tf,
        "Fog_r_d_star": rd_star,
        "Fog_TID_d_new_star": TID_d_new_star,
        "Fog_G_d_star": Gd_star,
        "Device_authentication": (Gd == Gd_star),
    })

    if Gd != Gd_star:
        return False, "Device authentication failed: G_d mismatch.", logs

    # If recovering a previous lost Ack, the valid request proves possession
    # of the pending B_k and new TID_d. Promote that pending state now.
    if recovering_pending:
        conn = db_connect()
        c = conn.cursor()
        c.execute("""
            UPDATE fog_devices
            SET TID_d=?, TID_f=?, B_k=?,
                old_B_k=?, pending_TID_d=NULL,
                pending_TID_f=NULL, pending_B_k=NULL
            WHERE ID_d=?
        """, (pending_TID_d, pending_TID_f, pending_B_k,
              f_B_k, ID_d))
        conn.commit()
        conn.close()
        use_TID_d, use_TID_f, use_B_k = (
            pending_TID_d, pending_TID_f, pending_B_k
        )
        logs["Synchronization"] += " Pending state promoted after G_d verification."

    # -----------------------------------------------------
    # FOG: generate r_f, r_g; compute E_f, J, TID_f_new, SK, G_f
    # -----------------------------------------------------
    rf = random_hex_256()
    rg_private, J = new_ecc_keypair()

    Ef = xor_hex(rf, h(TID_d_new_star + use_B_k))
    TID_f_new = h(xor_hex(use_TID_f, rf))

    shared_fog = ecdh_shared_secret(rg_private, I)
    SK_fog = h(shared_fog + rd_star + rf + Tf + use_B_k)

    Gf = h(TID_f_new + use_B_k + rf + SK_fog + Tf + Ef)

    # Candidate secret is computed by Fog before Auth_Rep is sent.
    B_k_cand = h(use_B_k + rd_star + rf + Tf)

    logs.update({
        "Fog_r_f": rf,
        "Fog_J = r_g.P (P-256 public point)": J,
        "E_f": Ef,
        "TID_f_new": TID_f_new,
        "Fog_ECDH_shared_secret": shared_fog,
        "SK_fog": SK_fog,
        "G_f": Gf,
        "B_k_candidate": B_k_cand,
        "Auth_Rep": "{TID_f, T_f, E_f, G_f, J}",
    })

    # Store candidate as pending at Fog; do not activate until Ack verifies.
    conn = db_connect()
    c = conn.cursor()
    c.execute("""
        UPDATE fog_devices
        SET pending_TID_d=?, pending_TID_f=?, pending_B_k=?
        WHERE ID_d=?
    """, (TID_d_new_star, TID_f_new, B_k_cand, ID_d))
    conn.commit()
    conn.close()

    # -----------------------------------------------------
    # DEVICE: verify freshness, recover r_f, compute SK and G_f*
    # -----------------------------------------------------
    if not is_fresh(Tf, time.time(), DELTA_T):
        return False, "Device rejected Auth_Rep: Fog timestamp is stale.", logs

    rf_star = xor_hex(Ef, h(TID_d_new + d_B_k))
    TID_f_new_star = h(xor_hex(d_TID_f, rf_star))

    shared_device = ecdh_shared_secret(re_private, J)
    SK_device = h(shared_device + rd + rf_star + Tf + d_B_k)

    Gf_star = h(
        TID_f_new_star + d_B_k + rf_star + SK_device + Tf + Ef
    )

    logs.update({
        "Device_r_f_star": rf_star,
        "Device_TID_f_new_star": TID_f_new_star,
        "Device_ECDH_shared_secret": shared_device,
        "SK_device": SK_device,
        "G_f_star": Gf_star,
        "Fog_authentication": (Gf == Gf_star),
        "Session_key_match": (SK_fog == SK_device),
    })

    if Gf != Gf_star:
        return False, "Fog authentication failed: G_f mismatch.", logs

    if SK_fog != SK_device:
        return False, "Session key agreement failed.", logs

    # -----------------------------------------------------
    # DEVICE: update TID_d, TID_f, B_k before sending Ack
    # -----------------------------------------------------
    B_k_new = h(d_B_k + rd + rf_star + Tf)

    # The two sides should derive identical candidate secrets.
    if B_k_new != B_k_cand:
        return False, "Key evolution mismatch: B_k values differ.", logs

    Ack = h(rf_star + d_B_k + SK_device)
    Ack_f = h(rf + use_B_k + SK_fog)

    logs.update({
        "B_k_new_device": B_k_new,
        "Ack_device": Ack,
        "Ack_fog_expected": Ack_f,
        "Ack_matches": (Ack == Ack_f),
        "Device_new_TID_d": TID_d_new,
        "Device_new_TID_f": TID_f_new_star,
    })

    if Ack != Ack_f:
        return False, "Acknowledgment verification failed.", logs

    # Device commits its new state before sending Ack, as in the supplied
    # protocol description.
    conn = db_connect()
    c = conn.cursor()
    c.execute("""
        UPDATE devices
        SET TID_d=?, TID_f=?, B_k=?
        WHERE ID_d=?
    """, (TID_d_new, TID_f_new_star, B_k_new, ID_d))
    conn.commit()
    conn.close()

    logs["Device_state"] = "Updated before Ack transmission."

    # Simulate an Ack lost in transit. Fog keeps old active state and pending
    # candidate; the next valid request can synchronize it.
    if simulate_lost_ack:
        logs["Ack_delivery"] = "Simulated lost Ack. Fog retains old and pending state."
        logs["Fog_state"] = "Pending; not promoted because Ack was not received."
        return True, (
            "Device authenticated Fog and updated its state. "
            "Ack was simulated as lost; Fog will recover on the next session."
        ), logs

    # -----------------------------------------------------
    # FOG: verify Ack and promote candidate to active state
    # -----------------------------------------------------
    if Ack_f != Ack:
        return False, "Fog rejected Ack.", logs

    conn = db_connect()
    c = conn.cursor()
    c.execute("""
        UPDATE fog_devices
        SET old_B_k=B_k,
            TID_d=pending_TID_d,
            TID_f=pending_TID_f,
            B_k=pending_B_k,
            pending_TID_d=NULL,
            pending_TID_f=NULL,
            pending_B_k=NULL
        WHERE ID_d=?
    """, (ID_d,))
    conn.commit()
    conn.close()

    logs["Ack_delivery"] = "Delivered and verified."
    logs["Fog_state"] = "Candidate B_k and new temporary identities promoted."
    logs["Key_evolution"] = "Successful: Device and Fog now store the same new B_k."
    return True, "Mutual authentication and key agreement successful.", logs


# =========================================================
# GUI — SAME TKINTER-BASED LABORATORY WORKFLOW
# =========================================================

class RMLAGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RMLA Laboratory — ECC-Based Authentication")
        self.root.geometry("1120x850")
        self.root.minsize(900, 650)

        frame = tk.Frame(root, padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            frame, text="Device ID:", font=("Arial", 12)
        ).grid(row=0, column=0, sticky="w")

        self.entry = tk.Entry(frame, width=28, font=("Arial", 12))
        self.entry.grid(row=0, column=1, padx=10, sticky="w")

        tk.Button(
            frame, text="Register Device", width=20,
            bg="#4CAF50", fg="white", font=("Arial", 10, "bold"),
            command=self.register_gui
        ).grid(row=1, column=0, pady=8, sticky="w")

        tk.Button(
            frame, text="Run Authentication", width=22,
            bg="#2196F3", fg="white", font=("Arial", 10, "bold"),
            command=self.run_gui
        ).grid(row=1, column=1, pady=8, sticky="w")

        self.lost_ack_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            frame,
            text="Simulate lost Ack (test synchronization recovery)",
            variable=self.lost_ack_var,
            font=("Arial", 10)
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=3)

        tk.Button(
            frame, text="Save Log", width=45,
            bg="#FF9800", fg="white", font=("Arial", 10, "bold"),
            command=self.save_log
        ).grid(row=3, column=0, columnspan=2, pady=6, sticky="w")

        self.log = scrolledtext.ScrolledText(
            frame, width=135, height=42, font=("Courier New", 9),
            wrap=tk.WORD
        )
        self.log.grid(row=4, column=0, columnspan=2, pady=10, sticky="nsew")

        frame.grid_rowconfigure(4, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        init_db()
        self.log.insert(
            tk.END,
            "RMLA Laboratory initialized.\n"
            "Curve: NIST P-256 / SECP256R1\n"
            "Hash: SHA-256\n"
            f"Freshness threshold: {DELTA_T} seconds\n"
            "Device and Fog protocol states are stored separately.\n\n"
        )

    def register_gui(self):
        ID_d = self.entry.get().strip()
        if not ID_d:
            messagebox.showwarning("Error", "Enter Device ID.")
            return

        ok, msg = register_device(ID_d)
        if ok:
            messagebox.showinfo("Registration", msg)
            self.log.insert(tk.END, f"[REGISTRATION]\n{msg}\n\n")
        else:
            messagebox.showerror("Registration", msg)

    def run_gui(self):
        ID_d = self.entry.get().strip()
        if not ID_d:
            messagebox.showwarning("Error", "Enter Device ID first.")
            return

        ok, msg, logs = run_rmla_session(
            ID_d, simulate_lost_ack=self.lost_ack_var.get()
        )

        self.log.delete("1.0", tk.END)
        self.log.insert(tk.END, "================ RMLA SESSION ================\n\n")
        self.log.insert(tk.END, f"Result: {msg}\n")
        self.log.insert(tk.END, f"Overall status: {'SUCCESS' if ok else 'FAILED'}\n\n")

        if logs is None:
            self.log.insert(tk.END, "No logs available.\n")
            return

        sections = [
            ("PROTOCOL AND CONFIGURATION", [
                "Protocol", "Device", "Fog", "Delta_T_seconds"
            ]),
            ("SYNCHRONIZATION", ["Synchronization"]),
            ("DEVICE AUTHENTICATION REQUEST", [
                "Device_r_d", "Device_T_d", "I = r_e.P (P-256 public point)",
                "E_d", "TID_d_new", "G_d", "Auth_Req"
            ]),
            ("FOG DEVICE VERIFICATION", [
                "Fog_T_f", "Fog_r_d_star", "Fog_TID_d_new_star",
                "Fog_G_d_star", "Device_authentication"
            ]),
            ("FOG AUTHENTICATION RESPONSE AND KEY", [
                "Fog_r_f", "Fog_J = r_g.P (P-256 public point)",
                "E_f", "TID_f_new", "Fog_ECDH_shared_secret",
                "SK_fog", "G_f", "B_k_candidate", "Auth_Rep"
            ]),
            ("DEVICE VERIFICATION", [
                "Device_r_f_star", "Device_TID_f_new_star",
                "Device_ECDH_shared_secret", "SK_device",
                "G_f_star", "Fog_authentication", "Session_key_match"
            ]),
            ("KEY EVOLUTION AND ACKNOWLEDGMENT", [
                "B_k_new_device", "Ack_device", "Ack_fog_expected",
                "Ack_matches", "Device_new_TID_d", "Device_new_TID_f",
                "Device_state", "Ack_delivery", "Fog_state", "Key_evolution"
            ]),
        ]

        for title, keys in sections:
            present = [(k, logs[k]) for k in keys if k in logs]
            if not present:
                continue
            self.log.insert(tk.END, f"\n---------------- {title} ----------------\n")
            for key, value in present:
                self.log.insert(tk.END, f"{key}:\n{value}\n\n")

        self.log.insert(tk.END, "\n================ END SESSION ================\n")

    def save_log(self):
        content = self.log.get("1.0", tk.END)
        with open("rmla_output.txt", "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Saved", "Execution log saved as rmla_output.txt")


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = RMLAGUI(root)
    root.mainloop()
