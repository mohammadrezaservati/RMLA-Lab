
import hashlib
import secrets
import sqlite3
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

DB = "rmla_lab.sqlite"
FOG_ID = "fog01"
DELTA_T = 60

CURVE = ec.SECP256R1()

ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    "BCE6FAADA7179E84F3B9CAC2FC632551", 16
)


# =====================================================
# CRYPTOGRAPHIC FUNCTIONS
# =====================================================

def H(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def random_value():
    return secrets.token_hex(32)


def xor_hex(a, b):
    if len(a) != len(b):
        raise ValueError("Invalid XOR operands")
    return format(int(a, 16) ^ int(b, 16), f"0{len(a)}x")


def timestamp():
    return f"{time.time():.6f}"


def fresh(T):
    try:
        return abs(time.time() - float(T)) <= DELTA_T
    except ValueError:
        return False


def ecc_keypair():
    scalar = secrets.randbelow(ORDER - 1) + 1
    private = ec.derive_private_key(scalar, CURVE)

    public = private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    return private, public.hex()


def ecdh(private, public_hex):
    public = ec.EllipticCurvePublicKey.from_encoded_point(
        CURVE, bytes.fromhex(public_hex)
    )
    return private.exchange(ec.ECDH(), public).hex()


# =====================================================
# DATABASE
# =====================================================

def connect():
    return sqlite3.connect(DB)


def init_db():
    with connect() as db:

        db.execute("""
        CREATE TABLE IF NOT EXISTS fog(
            ID_f TEXT,
            TID_f TEXT,
            A_f TEXT
        )
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS devices(
            ID_d TEXT PRIMARY KEY,
            TID_d TEXT,
            A_d TEXT,
            B_k TEXT,
            TID_f TEXT,
            A_f TEXT
        )
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS fog_devices(
            ID_d TEXT PRIMARY KEY,
            TID_d TEXT,
            A_d TEXT,
            B_k TEXT,
            TID_f TEXT,
            A_f TEXT,
            pending_TID_d TEXT,
            pending_TID_f TEXT,
            pending_B_k TEXT
        )
        """)

        row = db.execute(
            "SELECT ID_f FROM fog"
        ).fetchone()

        if row is None:
            ID_f = FOG_ID
            r1 = random_value()
            A_f = H(ID_f + r1)
            TID_f = H(ID_f + random_value())

            db.execute(
                "INSERT INTO fog VALUES(?,?,?)",
                (ID_f, TID_f, A_f)
            )


# =====================================================
# REGISTRATION PHASE
# =====================================================

def register_device(ID_d):

    ID_d = ID_d.strip()

    if not ID_d:
        return False, "Enter Device ID."

    with connect() as db:

        if db.execute(
            "SELECT 1 FROM devices WHERE ID_d=?",
            (ID_d,)
        ).fetchone():
            return False, "Device already registered."

        ID_f, TID_f, A_f = db.execute(
            "SELECT ID_f,TID_f,A_f FROM fog"
        ).fetchone()

        r2 = random_value()
        A_d = H(ID_d + r2)
        TID_d = H(ID_d + timestamp() + random_value())

        # Independent random secret
        B_k = random_value()

        db.execute("""
        INSERT INTO devices
        VALUES(?,?,?,?,?,?)
        """, (ID_d, TID_d, A_d, B_k, TID_f, A_f))

        db.execute("""
        INSERT INTO fog_devices
        VALUES(?,?,?,?,?,?,?,?,?)
        """, (
            ID_d, TID_d, A_d, B_k, TID_f, A_f,
            None, None, None
        ))

    return True, "Registration successful."


# =====================================================
# RMLA AUTHENTICATION PHASE
# =====================================================

def run_rmla(ID_d, lose_ack=False):

    with connect() as db:

        d = db.execute("""
        SELECT TID_d,A_d,B_k,TID_f,A_f
        FROM devices WHERE ID_d=?
        """, (ID_d,)).fetchone()

        f = db.execute("""
        SELECT TID_d,A_d,B_k,TID_f,A_f,
               pending_TID_d,pending_TID_f,pending_B_k
        FROM fog_devices WHERE ID_d=?
        """, (ID_d,)).fetchone()

    if d is None or f is None:
        return False, "Device not registered.", {}

    d_tid, d_ad, d_bk, d_tf, d_af = d

    f_tid, f_ad, f_bk, f_tf, f_af, p_tid, p_tf, p_bk = f

    log = {}

    # -------------------------------------------------
    # 1. DEVICE AUTHENTICATION REQUEST
    # -------------------------------------------------

    rd = random_value()
    re_private, I = ecc_keypair()
    Td = timestamp()

    Ed = xor_hex(
        rd,
        H(d_bk + d_af + Td)
    )

    TID_d_new = H(
        xor_hex(d_tid, rd)
    )

    Gd = H(
        d_ad + TID_d_new + d_bk + Td + I
    )

    Auth_req = (d_tid, Td, Ed, Gd, I)

    log["Auth_req"] = Auth_req
    log["E_d"] = Ed
    log["I"] = I
    log["TID_d_new"] = TID_d_new
    log["G_d"] = Gd

    # -------------------------------------------------
    # 2. FOG VERIFICATION
    # -------------------------------------------------

    if p_tid is not None and d_tid == p_tid:

        recovering = True
        use_tid = p_tid
        use_tf = p_tf
        use_bk = p_bk

    elif d_tid == f_tid:

        recovering = False
        use_tid = f_tid
        use_tf = f_tf
        use_bk = f_bk

    else:
        return False, "Unknown TID_d.", log

    Tf_now = timestamp()
    log["Fog_local_time"] = Tf_now

    if not fresh(Td):
        return False, "Device timestamp rejected.", log

    rd_star = xor_hex(
        Ed,
        H(use_bk + f_af + Td)
    )

    TID_d_new_star = H(
        xor_hex(use_tid, rd_star)
    )

    Gd_star = H(
        f_ad + TID_d_new_star + use_bk + Td + I
    )

    log["r_d_star"] = rd_star
    log["G_d_star"] = Gd_star

    if Gd != Gd_star:
        return False, "Device authentication failed.", log

    log["Device_authenticated"] = True

    # -------------------------------------------------
    # RECOVERY
    # -------------------------------------------------

    if recovering:

        with connect() as db:
            db.execute("""
            UPDATE fog_devices
            SET TID_d=?,TID_f=?,B_k=?,
                pending_TID_d=NULL,
                pending_TID_f=NULL,
                pending_B_k=NULL
            WHERE ID_d=?
            """, (p_tid, p_tf, p_bk, ID_d))

        use_tid = p_tid
        use_tf = p_tf
        use_bk = p_bk

        log["Recovery"] = "Pending credentials recovered."

    # -------------------------------------------------
    # 3. FOG RESPONSE
    # -------------------------------------------------

    Tf = timestamp()
    rf = random_value()

    rg_private, J = ecc_keypair()

    Ef = xor_hex(
        rf,
        H(TID_d_new_star + use_bk)
    )

    TID_f_new = H(
        xor_hex(use_tf, rf)
    )

    Z_f = ecdh(rg_private, I)

    SK = H(
        Z_f + rd_star + rf + Tf + use_bk
    )

    Gf = H(
        TID_f_new + use_bk + rf + SK + Tf + Ef
    )

    B_k_cand = H(
        use_bk + rd_star + rf + Tf
    )

    Auth_rep = (use_tf, Tf, Ef, Gf, J)

    log["Auth_rep"] = Auth_rep
    log["E_f"] = Ef
    log["J"] = J
    log["TID_f_new"] = TID_f_new
    log["SK_fog"] = SK
    log["G_f"] = Gf
    log["B_k_cand"] = B_k_cand

    with connect() as db:
        db.execute("""
        UPDATE fog_devices
        SET pending_TID_d=?,
            pending_TID_f=?,
            pending_B_k=?
        WHERE ID_d=?
        """, (
            TID_d_new_star,
            TID_f_new,
            B_k_cand,
            ID_d
        ))

    # -------------------------------------------------
    # 4. DEVICE VERIFICATION
    # -------------------------------------------------

    if not fresh(Tf):
        return False, "Fog timestamp rejected.", log

    rf_star = xor_hex(
        Ef,
        H(TID_d_new + d_bk)
    )

    TID_f_new_star = H(
        xor_hex(d_tf, rf_star)
    )

    Z_d = ecdh(re_private, J)

    SK_star = H(
        Z_d + rd + rf_star + Tf + d_bk
    )

    Gf_star = H(
        TID_f_new_star + d_bk +
        rf_star + SK_star + Tf + Ef
    )

    log["r_f_star"] = rf_star
    log["SK_device"] = SK_star
    log["G_f_star"] = Gf_star

    if Gf != Gf_star:
        return False, "Fog authentication failed.", log

    if SK != SK_star:
        return False, "Session key mismatch.", log

    log["Fog_authenticated"] = True
    log["Session_key_match"] = True

    # -------------------------------------------------
    # 5. KEY EVOLUTION
    # -------------------------------------------------

    B_k_new = H(
        d_bk + rd + rf_star + Tf
    )

    if B_k_new != B_k_cand:
        return False, "Key evolution mismatch.", log

    TID_d_old = d_tid
    TID_f_old = d_tf

    with connect() as db:
        db.execute("""
        UPDATE devices
        SET TID_d=?,TID_f=?,B_k=?
        WHERE ID_d=?
        """, (
            TID_d_new,
            TID_f_new_star,
            B_k_new,
            ID_d
        ))

    log["B_k_new"] = B_k_new
    log["TID_d_old"] = TID_d_old
    log["TID_f_old"] = TID_f_old

    # -------------------------------------------------
    # 6. ACKNOWLEDGMENT
    # -------------------------------------------------

    Ack = H(
        rf_star + B_k_new + SK_star
    )

    Ack_f = H(
        rf + B_k_cand + SK
    )

    log["Ack"] = Ack
    log["Ack_f"] = Ack_f

    if lose_ack:

        log["Ack_delivery"] = "LOST"
        return True, "ACK lost. Recovery is pending.", log

    if Ack != Ack_f:
        return False, "ACK verification failed.", log

    with connect() as db:
        db.execute("""
        UPDATE fog_devices
        SET TID_d=pending_TID_d,
            TID_f=pending_TID_f,
            B_k=pending_B_k,
            pending_TID_d=NULL,
            pending_TID_f=NULL,
            pending_B_k=NULL
        WHERE ID_d=?
        """, (ID_d,))

    log["Ack_verified"] = True
    log["Synchronization"] = True

    return True, "RMLA authentication successful.", log


# =====================================================
# AUTOMATED TESTS
# =====================================================

def run_tests():

    print("\nRMLA AUTOMATED TESTS\n")

    ID_d = "TEST_DEVICE_" + secrets.token_hex(4)

    ok, msg = register_device(ID_d)
    assert ok, msg

    ok, msg, log = run_rmla(ID_d)
    assert ok, msg
    assert log["Session_key_match"]
    assert log["Ack_verified"]

    print("[PASS] Normal authentication")
    print("[PASS] ECDH key agreement")
    print("[PASS] Mutual authentication")
    print("[PASS] ACK verification")

    ok, msg, log = run_rmla(ID_d, lose_ack=True)
    assert ok, msg

    print("[PASS] Lost ACK simulation")

    ok, msg, log = run_rmla(ID_d)
    assert ok, msg
    assert log["Synchronization"]

    print("[PASS] Synchronization recovery")

    print("\nALL TESTS COMPLETED.\n")


# =====================================================
# TKINTER GUI
# =====================================================

class RMLAGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("RMLA Authentication Laboratory")
        self.root.geometry("1100x780")

        frame = tk.Frame(root, padx=15, pady=15)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame,
            text="IoT Device ID:",
            font=("Arial", 12)
        ).pack(anchor="w")

        self.device = tk.Entry(frame, width=35)
        self.device.pack(anchor="w", pady=5)

        tk.Button(
            frame,
            text="Register Device",
            command=self.register
        ).pack(anchor="w", pady=5)

        tk.Button(
            frame,
            text="Run RMLA Authentication",
            command=self.run
        ).pack(anchor="w", pady=5)

        self.lost = tk.BooleanVar()

        tk.Checkbutton(
            frame,
            text="Simulate Lost ACK",
            variable=self.lost
        ).pack(anchor="w")

        self.output = scrolledtext.ScrolledText(
            frame,
            font=("Consolas", 10),
            wrap=tk.WORD
        )

        self.output.pack(
            fill="both",
            expand=True,
            pady=10
        )

    def register(self):

        ID_d = self.device.get().strip()

        ok, msg = register_device(ID_d)

        if ok:
            messagebox.showinfo("Registration", msg)
        else:
            messagebox.showerror("Error", msg)

    def run(self):

        ID_d = self.device.get().strip()

        ok, msg, logs = run_rmla(
            ID_d,
            self.lost.get()
        )

        self.output.delete("1.0", tk.END)

        self.output.insert(
            tk.END,
            f"RESULT: {msg}\n"
            f"STATUS: {'SUCCESS' if ok else 'FAILED'}\n\n"
        )

        for key, value in logs.items():

            self.output.insert(
                tk.END,
                f"{key}:\n{value}\n\n"
            )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    init_db()

    import sys

    if "--test" in sys.argv:
        run_tests()
    else:
        root = tk.Tk()
        app = RMLAGUI(root)
        root.mainloop()
