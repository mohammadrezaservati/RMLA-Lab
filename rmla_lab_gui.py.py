#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMLA Laboratory Prototype (v3 - 32-bit timestamps)
==============================

Functional prototype of the RMLA mutual-authentication / key-agreement
protocol (IoT device <-> fog node, with a trusted RA).

What is different from v1
-------------------------
* RA, Fog and Device are separate classes. Each one touches only its own
  tables and only sees the *messages* it receives (no shared local variables).
* Messages are serialised to bytes ("wire") and parsed again, so an entity can
  never read the other side's memory.
* The fog finds the device record from the TID_d carried in Auth_Req.
* Many fog nodes / many devices are supported.
* Desynchronisation recovery is really implemented:
    - fog keeps (current, candidate) state per device,
    - candidate is activated only after a valid ACK, or when the next
      Auth_Req is authenticated with the candidate identity (ACK was lost),
    - device commits only after G_f is verified and keeps the previous state.
* Fog has a replay cache (a replayed Auth_Req could otherwise overwrite a
  pending candidate and cause a permanent desync).
* Failure simulation: lose Auth_Rep, lose ACK, stale timestamp, tampered
  Auth_Req, replayed Auth_Req.
* Automated self-test suite (also: `python rmla_lab.py --selftest`).
* Hash inputs are length-prefixed (unambiguous concatenation).

Requirements: Python standard library only (tkinter ships with Python)
"""

import csv
import hashlib
import hmac
import json
import secrets
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path


try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:          # headless use (self-tests only)
    tk = None


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "RMLA_Laboratory_v3_32bit_timestamp.db"
SCHEMA_VERSION = 4  # new database/schema profile for 32-bit-second timestamps

# Experimental profile matching the paper's nominal output sizes.
HASH_OUTPUT_BYTES = 20       # 160-bit hash output
NONCE_BYTES = 16              # 128-bit protocol nonces
MASK_BYTES = 16               # 128-bit XOR mask
DELTA_T_S = 60                # allowed timestamp skew: 60 seconds

# SEC 2 secp160r1 domain parameters. This is an experimental, legacy-size
# curve and MUST NOT be used for production security.
ECC_P = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", 16)
ECC_A = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", 16)
ECC_B = int("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", 16)
ECC_GX = int("4A96B5688EF573284664698968C38BB913CBFC82", 16)
ECC_GY = int("23A628553168947D59DCC912042351377AC5FB32", 16)
ECC_N = int("0100000000000000000001F4C8F927AED3CA752257", 16)
ECC_G = (ECC_GX, ECC_GY)
ECC_COORD_BYTES = 20
ECC_POINT_BYTES = 2 * ECC_COORD_BYTES  # x || y = 320 bits, no SEC1 prefix


class ProtocolError(Exception):
    """A protocol message was rejected."""


class LabError(Exception):
    """Misuse of the laboratory (not initialised, duplicate ID, ...)."""


# ============================================================
# CRYPTOGRAPHIC UTILITIES
# ============================================================

def _enc(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("hash inputs must be bytes or str")


def H(*values):
    """SHA-256 with a 160-bit truncated digest and length-prefixed inputs."""
    h = hashlib.sha256()
    for value in values:
        b = _enc(value)
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return h.digest()[:HASH_OUTPUT_BYTES]


def H_mask(*values):
    """Return a 128-bit mask for XOR with 128-bit protocol nonces."""
    return H(*values)[:MASK_BYTES]


def random_nonce():
    """Generate a cryptographically secure 128-bit protocol nonce."""
    return secrets.token_bytes(NONCE_BYTES)


def xor_bytes(a, b):
    if len(a) != len(b):
        raise ProtocolError("malformed message: XOR length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_tid_nonce(tid, nonce):
    """XOR a 128-bit nonce with a 160-bit TID using zero-extension.

    The same fixed-width encoding is used by Device and Fog.
    """
    if len(nonce) != NONCE_BYTES or len(tid) != HASH_OUTPUT_BYTES:
        raise ProtocolError("invalid TID/nonce length")
    return xor_bytes(tid, nonce + b"\x00" * (HASH_OUTPUT_BYTES - NONCE_BYTES))


def now_s():
    """Current Unix timestamp in whole seconds (32-bit wire representation)."""
    return int(time.time())


def ts_bytes(timestamp_s):
    """Encode a Unix timestamp as an unsigned 32-bit integer (4 bytes)."""
    value = int(timestamp_s)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError("timestamp is outside the unsigned 32-bit range")
    return value.to_bytes(4, "big", signed=False)


def _point_add(p1, p2):
    """Affine point addition on secp160r1; None represents point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % ECC_P == 0:
        return None
    if p1 == p2:
        if y1 % ECC_P == 0:
            return None
        slope = ((3 * x1 * x1 + ECC_A) * pow(2 * y1, -1, ECC_P)) % ECC_P
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % ECC_P, -1, ECC_P)) % ECC_P
    x3 = (slope * slope - x1 - x2) % ECC_P
    y3 = (slope * (x1 - x3) - y1) % ECC_P
    return x3, y3


def _scalar_mult(k, point=ECC_G):
    if not isinstance(k, int) or k < 0:
        raise ValueError("ECC scalar must be a non-negative integer")
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


# Validate the secp160r1 base point and subgroup order at module load.
assert _scalar_mult(ECC_N, ECC_G) is None and \
       (ECC_GY**2 - (ECC_GX**3 + ECC_A*ECC_GX + ECC_B)) % ECC_P == 0


def generate_ecc_private_key():
    """Uniform private scalar in [1, n-1] for the experimental curve."""
    return secrets.randbelow(ECC_N - 1) + 1


def encode_point(point):
    """Encode a secp160r1 point as x||y (40 bytes = 320 bits)."""
    if point is None:
        raise ProtocolError("cannot encode point at infinity")
    x, y = point
    return x.to_bytes(ECC_COORD_BYTES, "big") + y.to_bytes(ECC_COORD_BYTES, "big")


def decode_point(data):
    """Decode and validate the laboratory's 40-byte x||y point encoding."""
    if not isinstance(data, bytes) or len(data) != ECC_POINT_BYTES:
        raise ProtocolError("invalid elliptic-curve point length")
    x = int.from_bytes(data[:ECC_COORD_BYTES], "big")
    y = int.from_bytes(data[ECC_COORD_BYTES:], "big")
    if x >= ECC_P or y >= ECC_P:
        raise ProtocolError("invalid elliptic-curve point coordinates")
    if (y * y - (x * x * x + ECC_A * x + ECC_B)) % ECC_P != 0:
        raise ProtocolError("point is not on secp160r1")
    # secp160r1 has cofactor 1; on-curve validation is sufficient.
    return (x, y)


def ecdh(private_key, public_key):
    """Return the 160-bit x-coordinate of the ECDH shared point."""
    shared = _scalar_mult(private_key, public_key)
    if shared is None:
        raise ProtocolError("invalid ECDH shared point")
    return shared[0].to_bytes(ECC_COORD_BYTES, "big")

def hx(value, n=12):
    return value.hex()[:n] + "..."


def fingerprint(key):
    """Short fingerprint so that keys can be compared without printing them."""
    return hashlib.sha256(b"fp" + key).hexdigest()[:16]


# ---------------- wire format ----------------

def to_wire(msg):
    return json.dumps(
        {k: (v.hex() if isinstance(v, bytes) else v) for k, v in msg.items()},
        sort_keys=True,
    ).encode()


def from_wire(data):
    raw = json.loads(data.decode())
    return {k: (bytes.fromhex(v) if isinstance(v, str) else v)
            for k, v in raw.items()}


def fmt_msg(msg):
    return ", ".join(
        f"{k}={hx(v, 10) if isinstance(v, bytes) else v}"
        for k, v in msg.items()
    )


def require(msg, spec):
    """spec: {field: byte-length or None (=integer)}"""
    for field, size in spec.items():
        if field not in msg:
            raise ProtocolError(f"malformed message: missing {field}")
        v = msg[field]
        if size is None:
            if not isinstance(v, int) or isinstance(v, bool):
                raise ProtocolError(f"malformed message: {field} type")
        elif not isinstance(v, bytes) or len(v) != size:
            raise ProtocolError(f"malformed message: {field} size")


REQ_SPEC = {"TID_d": 20, "T_d": None, "E_d": 16, "G_d": 20, "I": 40}
REP_SPEC = {"TID_f": 20, "T_f": None, "E_f": 16, "G_f": 20, "J": 40}
ACK_SPEC = {"TID_d": 20, "Ack": 20}


# ============================================================
# DATABASE
# ============================================================

class RMLADatabase:
    """
    Ownership of tables (each class only uses its own):
      RA     : system_config, ra_fog, ra_device
      Fog    : fog_node, fog_devices
      Device : device_node
    """

    TABLES = {
        "system_config": """CREATE TABLE system_config (
            id INTEGER PRIMARY KEY, curve TEXT, hash TEXT,
            master_secret BLOB)""",
        "ra_fog": """CREATE TABLE ra_fog (
            fog_id TEXT PRIMARY KEY, tid_f BLOB, a_f BLOB)""",
        "ra_device": """CREATE TABLE ra_device (
            device_id TEXT PRIMARY KEY, fog_id TEXT,
            tid_d BLOB, a_d BLOB, b_k BLOB)""",
        "fog_node": """CREATE TABLE fog_node (
            fog_id TEXT PRIMARY KEY, tid_f BLOB, a_f BLOB)""",
        "fog_devices": """CREATE TABLE fog_devices (
            fog_id TEXT, a_d BLOB,
            tid_d BLOB, tid_f BLOB, b_k BLOB,
            pending INTEGER DEFAULT 0,
            tid_d_c BLOB, tid_f_c BLOB, b_k_c BLOB,
            PRIMARY KEY (fog_id, a_d))""",
        "device_node": """CREATE TABLE device_node (
            device_id TEXT PRIMARY KEY, fog_id TEXT,
            a_d BLOB, a_f BLOB,
            tid_d BLOB, tid_f BLOB, b_k BLOB,
            tid_d_old BLOB, tid_f_old BLOB, b_k_old BLOB,
            sessions INTEGER DEFAULT 0)""",
    }

    def __init__(self, path=None):
        self.conn = sqlite3.connect(str(path) if path else ":memory:")
        self.conn.row_factory = sqlite3.Row
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            self._drop_all()
            self._create()
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.conn.commit()

    def _drop_all(self):
        names = [r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'")]
        for n in names:
            self.conn.execute(f'DROP TABLE IF EXISTS "{n}"')
        self.conn.commit()

    def _create(self):
        for sql in self.TABLES.values():
            self.conn.execute(sql)
        self.conn.commit()

    def reset(self):
        self._drop_all()
        self._create()

    def close(self):
        self.conn.close()


# ============================================================
# ENTITY: REGISTRATION AUTHORITY
# ============================================================

class RA:
    def __init__(self, db, log):
        self.db, self.log = db, log

    def initialize(self):
        self.db.reset()
        K = secrets.token_bytes(HASH_OUTPUT_BYTES)
        self.db.conn.execute(
            "INSERT INTO system_config VALUES (1, ?, ?, ?)",
            ("secp160r1 (experimental)", "SHA-256/160-bit-truncated", K))
        self.db.conn.commit()
        self.log("[RA] Curve selected: secp160r1 (experimental; x||y = 320 bits).")
        self.log("[RA] Hash function: SHA-256 truncated to 160 bits.")
        self.log("[RA] Protocol nonces: 128 bits.")
        self.log("[RA] Master secret K generated and kept only by the RA.")
        self.log("[RA] B_k is generated independently of K (not derived).")

    def initialized(self):
        return self.db.conn.execute(
            "SELECT 1 FROM system_config WHERE id=1").fetchone() is not None

    def register_fog(self, fog_id, a_f):
        if self.db.conn.execute(
                "SELECT 1 FROM ra_fog WHERE fog_id=?", (fog_id,)).fetchone():
            raise LabError(f"Fog node '{fog_id}' is already registered.")
        tid_f = secrets.token_bytes(HASH_OUTPUT_BYTES)
        self.db.conn.execute(
            "INSERT INTO ra_fog VALUES (?, ?, ?)", (fog_id, tid_f, a_f))
        self.db.conn.commit()
        self.log("[RA] TID_f assigned; (TID_f, A_f) stored.")
        return tid_f

    def register_device(self, device_id, fog_id, a_d):
        if self.db.conn.execute(
                "SELECT 1 FROM ra_device WHERE device_id=?",
                (device_id,)).fetchone():
            raise LabError(f"Device '{device_id}' is already registered.")
        fog = self.db.conn.execute(
            "SELECT * FROM ra_fog WHERE fog_id=?", (fog_id,)).fetchone()
        if fog is None:
            raise LabError(f"Fog node '{fog_id}' is not registered.")
        tid_d = secrets.token_bytes(HASH_OUTPUT_BYTES)
        b_k = secrets.token_bytes(HASH_OUTPUT_BYTES)  # independent 160-bit B_k (protocol credential)
        self.db.conn.execute(
            "INSERT INTO ra_device VALUES (?, ?, ?, ?, ?)",
            (device_id, fog_id, tid_d, a_d, b_k))
        self.db.conn.commit()
        self.log("[RA] TID_d assigned; independent random 160-bit B_k generated.")
        self.log("[RA] (A_d, TID_d, B_k) stored.")
        return {"TID_d": tid_d, "B_k": b_k,
                "TID_f": fog["tid_f"], "A_f": fog["a_f"]}


# ============================================================
# ENTITY: FOG NODE
# ============================================================

class Fog:
    def __init__(self, db, fog_id, log):
        self.db, self.fog_id, self.log = db, fog_id, log
        self.sessions = {}      # in-memory session contexts (waiting for ACK)
        self.replay = {}        # replay cache: (TID_d, T_d, G_d) -> T_d
        self.last_sk = None     # laboratory observation only

    # ---------------- registration ----------------
    @classmethod
    def register(cls, db, ra, fog_id, log):
        r1 = random_nonce()
        a_f = H(fog_id, r1)
        log("[Fog] r1 generated; A_f = h(ID_f || r1) computed.")
        log("[Fog -> RA] A_f sent over the secure channel.")
        tid_f = ra.register_fog(fog_id, a_f)
        db.conn.execute("INSERT INTO fog_node VALUES (?, ?, ?)",
                        (fog_id, tid_f, a_f))
        db.conn.commit()
        log("[RA -> Fog] TID_f received and stored.")
        return cls(db, fog_id, log)

    def accept_provision(self, a_d, tid_d, b_k):
        node = self._node()
        self.db.conn.execute(
            "INSERT INTO fog_devices (fog_id, a_d, tid_d, tid_f, b_k, pending)"
            " VALUES (?, ?, ?, ?, ?, 0)",
            (self.fog_id, a_d, tid_d, node["tid_f"], b_k))
        self.db.conn.commit()
        self.log("[RA -> Fog] (TID_d, A_d, B_k) received and stored.")

    # ---------------- helpers ----------------
    def _node(self):
        return self.db.conn.execute(
            "SELECT * FROM fog_node WHERE fog_id=?", (self.fog_id,)).fetchone()

    def _lookup(self, tid_d):
        c = self.db.conn
        row = c.execute(
            "SELECT * FROM fog_devices WHERE fog_id=? AND tid_d=?",
            (self.fog_id, tid_d)).fetchone()
        if row:
            return row, "current"
        row = c.execute(
            "SELECT * FROM fog_devices WHERE fog_id=? AND pending=1 "
            "AND tid_d_c=?", (self.fog_id, tid_d)).fetchone()
        if row:
            return row, "candidate"
        return None

    def _purge(self, now):
        limit = 2 * DELTA_T_S
        self.replay = {k: t for k, t in self.replay.items()
                       if now - t <= limit}

    # ---------------- step 2 + 3 ----------------
    def handle_request(self, req):
        log = self.log
        require(req, REQ_SPEC)
        node = self._node()
        now, td = now_s(), req["T_d"]

        if abs(now - td) > DELTA_T_S:
            raise ProtocolError(
                "Auth_Req rejected: timestamp not fresh (|T_f - T_d| > dT)")
        log("[Fog] Timestamp freshness verified.")

        self._purge(now)
        rid = (req["TID_d"], td, req["G_d"])
        if rid in self.replay:
            raise ProtocolError("Auth_Req rejected: replay detected")

        found = self._lookup(req["TID_d"])
        if found is None:
            raise ProtocolError("Auth_Req rejected: unknown TID_d")
        row, which = found
        log(f"[Fog] Device record found from TID_d ({which} state).")

        if which == "current":
            tid_d, tid_f, b_k = row["tid_d"], row["tid_f"], row["b_k"]
        else:
            tid_d, tid_f, b_k = row["tid_d_c"], row["tid_f_c"], row["b_k_c"]
        a_d, a_f = row["a_d"], node["a_f"]
        td_b = ts_bytes(td)

        rd = xor_bytes(req["E_d"], H_mask(b_k, a_f, td_b))
        tid_d_new = H(xor_tid_nonce(tid_d, rd))
        gd_star = H(a_d, tid_d_new, b_k, td_b, req["I"])
        if not hmac.compare_digest(gd_star, req["G_d"]):
            raise ProtocolError("Auth_Req rejected: G_d verification failed")
        device_pub = decode_point(req["I"])
        self.replay[rid] = td
        log("[Fog] r_d* recovered, G_d* == G_d  ->  device authenticated.",
            "ok")

        if which == "candidate":
            log("[Fog] ACK of the previous session was lost: the device "
                "already uses the candidate state -> candidate promoted "
                "(synchronisation recovered).", "warn")

        tf = now_s()
        tf_b = ts_bytes(tf)
        rf = random_nonce()
        rg = generate_ecc_private_key()              # r_g in Z_n^*
        J = encode_point(_scalar_mult(rg))          # J = r_g . P
        ef = xor_bytes(rf, H_mask(tid_d_new, b_k))
        tid_f_new = H(xor_tid_nonce(tid_f, rf))
        shared = ecdh(rg, device_pub)              # r_g . I
        sk = H(shared, rd, rf, tf_b, b_k)
        gf = H(tid_f_new, b_k, rf, sk, tf_b, ef)
        bk_cand = H(b_k, rd, rf, tf_b)
        log("[Fog] J, E_f, TID_f_new, ECDH point, SK, G_f, B_k_cand computed.")

        # current := state that authenticated this request (promotes the
        # candidate if needed); candidate := new state, pending ACK.
        self.db.conn.execute(
            "UPDATE fog_devices SET tid_d=?, tid_f=?, b_k=?, pending=1, "
            "tid_d_c=?, tid_f_c=?, b_k_c=? WHERE fog_id=? AND a_d=?",
            (tid_d, tid_f, b_k, tid_d_new, tid_f_new, bk_cand,
             self.fog_id, a_d))
        self.db.conn.commit()
        log("[Fog] Current + candidate credentials stored (pending ACK).")

        self.sessions = {k: v for k, v in self.sessions.items()
                         if v["a_d"] != a_d}
        self.sessions[req["TID_d"]] = {
            "a_d": a_d, "rf": rf, "sk": sk,
            "tid_d_new": tid_d_new, "bk_cand": bk_cand}
        self.last_sk = sk

        return {"TID_f": tid_f, "T_f": tf, "E_f": ef, "G_f": gf, "J": J}

    # ---------------- step 4 ----------------
    def handle_ack(self, msg):
        require(msg, ACK_SPEC)
        ctx = self.sessions.get(msg["TID_d"])
        if ctx is None:
            raise ProtocolError("ACK rejected: no pending session")
        ack_f = H(ctx["rf"], ctx["bk_cand"], ctx["sk"])
        if not hmac.compare_digest(ack_f, msg["Ack"]):
            raise ProtocolError("ACK rejected: verification failed")
        cur = self.db.conn.execute(
            "UPDATE fog_devices SET tid_d=tid_d_c, tid_f=tid_f_c, "
            "b_k=b_k_c, pending=0, tid_d_c=NULL, tid_f_c=NULL, b_k_c=NULL "
            "WHERE fog_id=? AND a_d=? AND pending=1 AND tid_d_c=?",
            (self.fog_id, ctx["a_d"], ctx["tid_d_new"]))
        self.db.conn.commit()
        if cur.rowcount != 1:
            raise ProtocolError("ACK rejected: candidate no longer pending")
        del self.sessions[msg["TID_d"]]
        self.log("[Fog] Ack_f == Ack  ->  candidate activated; previous "
                 "credentials erased.", "ok")


# ============================================================
# ENTITY: IoT DEVICE
# ============================================================

class Device:
    def __init__(self, db, device_id, log):
        self.db, self.device_id, self.log = db, device_id, log
        self.ctx = None
        self.last_sk = None     # laboratory observation only

    @property
    def fog_id(self):
        return self._row()["fog_id"]

    @classmethod
    def register(cls, db, ra, fog, device_id, log):
        r2 = random_nonce()
        a_d = H(device_id, r2)
        log("[Device] r2 generated; A_d = h(ID_d || r2) computed.")
        log("[Device -> RA] A_d sent over the secure channel.")
        pkg = ra.register_device(device_id, fog.fog_id, a_d)
        fog.accept_provision(a_d, pkg["TID_d"], pkg["B_k"])
        db.conn.execute(
            "INSERT INTO device_node (device_id, fog_id, a_d, a_f, tid_d, "
            "tid_f, b_k) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (device_id, fog.fog_id, a_d, pkg["A_f"],
             pkg["TID_d"], pkg["TID_f"], pkg["B_k"]))
        db.conn.commit()
        log("[RA -> Device] (TID_d, TID_f, A_f, B_k) received and stored.")
        return cls(db, device_id, log)

    def _row(self):
        return self.db.conn.execute(
            "SELECT * FROM device_node WHERE device_id=?",
            (self.device_id,)).fetchone()

    # ---------------- step 1 ----------------
    def make_request(self, ts_offset_s=0):
        row = self._row()
        a_d, a_f = row["a_d"], row["a_f"]
        tid_d, b_k = row["tid_d"], row["b_k"]

        td = now_s() + int(ts_offset_s)
        td_b = ts_bytes(td)
        rd = random_nonce()
        re = generate_ecc_private_key()                 # r_e in Z_n^*
        I = encode_point(_scalar_mult(re))             # I = r_e . P
        ed = xor_bytes(rd, H_mask(b_k, a_f, td_b))
        tid_d_new = H(xor_tid_nonce(tid_d, rd))
        gd = H(a_d, tid_d_new, b_k, td_b, I)

        self.ctx = {"tid_d": tid_d, "rd": rd, "re": re,
                    "tid_d_new": tid_d_new}
        self.log("[Device] T_d, r_d, r_e generated; I, E_d, TID_d_new, G_d "
                 "computed.")
        return {"TID_d": tid_d, "T_d": td, "E_d": ed, "G_d": gd, "I": I}

    def abort(self):
        self.ctx = None

    # ---------------- step 3 ----------------
    def handle_response(self, rep):
        require(rep, REP_SPEC)
        if self.ctx is None:
            raise ProtocolError("Auth_Rep rejected: no pending request")
        ctx, row = self.ctx, self._row()
        if ctx["tid_d"] != row["tid_d"]:
            raise ProtocolError("Auth_Rep rejected: stale request context")
        if abs(now_s() - rep["T_f"]) > DELTA_T_S:
            raise ProtocolError("Auth_Rep rejected: timestamp not fresh")
        if rep["TID_f"] != row["tid_f"]:
            raise ProtocolError("Auth_Rep rejected: unexpected TID_f")
        self.log("[Device] Timestamp freshness verified.")

        b_k, tid_f = row["b_k"], row["tid_f"]
        tf_b = ts_bytes(rep["T_f"])
        rf = xor_bytes(rep["E_f"], H_mask(ctx["tid_d_new"], b_k))
        fog_pub = decode_point(rep["J"])
        shared = ecdh(ctx["re"], fog_pub)             # r_e . J
        sk = H(shared, ctx["rd"], rf, tf_b, b_k)
        tid_f_new = H(xor_tid_nonce(tid_f, rf))
        gf_star = H(tid_f_new, b_k, rf, sk, tf_b, rep["E_f"])
        if not hmac.compare_digest(gf_star, rep["G_f"]):
            raise ProtocolError("Auth_Rep rejected: G_f verification failed")
        self.log("[Device] r_f* recovered, SK* derived, G_f* == G_f  ->  "
                 "fog node authenticated.", "ok")

        bk_new = H(b_k, ctx["rd"], rf, tf_b)
        ack = H(rf, bk_new, sk)

        # commit new state, keep the previous one for recovery
        self.db.conn.execute(
            "UPDATE device_node SET tid_d_old=tid_d, tid_f_old=tid_f, "
            "b_k_old=b_k, tid_d=?, tid_f=?, b_k=?, sessions=sessions+1 "
            "WHERE device_id=?",
            (ctx["tid_d_new"], tid_f_new, bk_new, self.device_id))
        self.db.conn.commit()
        self.log("[Device] B_k_new, TID_d, TID_f committed; previous state "
                 "retained for recovery.")

        self.last_sk = sk
        self.ctx = None
        return {"TID_d": ctx["tid_d"], "Ack": ack}


# ============================================================
# LABORATORY (environment + insecure channel)
# ============================================================

class Lab:
    def __init__(self, db, log):
        self.db, self.log = db, log
        self.ra = RA(db, log)
        self.fogs, self.devices, self.captured = {}, {}, {}
        self.counter = 0

    def section(self, title):
        self.log("")
        self.log("=" * 72, "sec")
        self.log(title, "sec")
        self.log("=" * 72, "sec")

    # ---------------- phases ----------------
    def initialize(self):
        self.fogs.clear(); self.devices.clear(); self.captured.clear()
        self.counter = 0
        self.section("PHASE 1: SYSTEM INITIALIZATION")
        self.ra.initialize()

    def _require_init(self):
        if not self.ra.initialized():
            raise LabError("Initialize the system first.")

    def add_fog(self, fog_id):
        self._require_init()
        if not fog_id:
            raise LabError("Enter a Fog Node ID.")
        self.section(f"PHASE 2: FOG NODE REGISTRATION ({fog_id})")
        self.fogs[fog_id] = Fog.register(self.db, self.ra, fog_id, self.log)
        self.log("[Fog] Registration successful.", "ok")

    def add_device(self, device_id, fog_id):
        self._require_init()
        if not device_id:
            raise LabError("Enter an IoT Device ID.")
        if not fog_id:
            raise LabError("Select a registered Fog Node.")
        fog = self.fog(fog_id)
        self.section(f"PHASE 3: IOT DEVICE REGISTRATION ({device_id})")
        self.devices[device_id] = Device.register(
            self.db, self.ra, fog, device_id, self.log)
        self.log("[Device] Registration successful.", "ok")

    def fog(self, fog_id):
        if fog_id not in self.fogs:
            if self.db.conn.execute("SELECT 1 FROM fog_node WHERE fog_id=?",
                                    (fog_id,)).fetchone() is None:
                raise LabError(f"Unknown fog node '{fog_id}'.")
            self.fogs[fog_id] = Fog(self.db, fog_id, self.log)
        return self.fogs[fog_id]

    def device(self, device_id):
        if device_id not in self.devices:
            if self.db.conn.execute(
                    "SELECT 1 FROM device_node WHERE device_id=?",
                    (device_id,)).fetchone() is None:
                raise LabError(f"Unknown device '{device_id}'.")
            self.devices[device_id] = Device(self.db, device_id, self.log)
        return self.devices[device_id]

    def fog_ids(self):
        return [r[0] for r in self.db.conn.execute(
            "SELECT fog_id FROM fog_node ORDER BY rowid")]

    def device_ids(self):
        return [r[0] for r in self.db.conn.execute(
            "SELECT device_id FROM device_node ORDER BY rowid")]

    # ---------------- channel helpers ----------------
    def _wire(self, direction, name, msg, wire):
        self.log(f"[Channel] {direction}: {name} ({len(wire)} bytes)", "wire")
        self.log(f"          {fmt_msg(msg)}", "wire")

    # ---------------- phase 4 ----------------
    def session(self, device_id, drop_rep=False, drop_ack=False,
                stale=False, tamper=False, verbose=True):
        self._require_init()
        dev = self.device(device_id)
        fog = self.fog(dev.fog_id)
        self.counter += 1
        res = {"device_authenticated": False, "fog_authenticated": False,
               "acked": False, "error": None, "stage": "auth_req",
               "device_sk": None, "fog_sk": None}
        if verbose:
            self.section(f"PHASE 4: AUTHENTICATION SESSION #{self.counter} "
                         f"({device_id} <-> {dev.fog_id})")

        # 1. device -> fog : Auth_Req
        req = dev.make_request(-120 if stale else 0)
        self.captured[device_id] = to_wire(req)          # eavesdropper copy
        if tamper:
            req = dict(req)
            req["E_d"] = bytes([req["E_d"][0] ^ 0x01]) + req["E_d"][1:]
            self.log("[Attacker] Auth_Req modified in transit (E_d bit flip).",
                     "warn")
        if stale:
            self.log("[Attacker/Network] Auth_Req delayed: stale timestamp.",
                     "warn")
        wire = to_wire(req)
        if verbose:
            self._wire("Device -> Fog", "Auth_Req", req, wire)

        # 2. fog verifies, answers
        try:
            rep = fog.handle_request(from_wire(wire))
        except ProtocolError as e:
            res["error"], res["stage"] = str(e), "fog_rejected"
            dev.abort()
            self.log(f"[Fog] {e}", "err")
            return res
        res["fog_authenticated"] = True
        res["fog_sk"] = fog.last_sk
        rep_wire = to_wire(rep)

        if drop_rep:
            res["stage"] = "auth_rep_lost"
            dev.abort()
            self.log("[Channel] Auth_Rep LOST. Fog holds a pending candidate; "
                     "device state is unchanged.", "warn")
            return res
        if verbose:
            self._wire("Fog -> Device", "Auth_Rep", rep, rep_wire)

        # 3. device verifies, commits, sends ACK
        try:
            ack = dev.handle_response(from_wire(rep_wire))
        except ProtocolError as e:
            res["error"], res["stage"] = str(e), "device_rejected"
            self.log(f"[Device] {e}", "err")
            return res
        res["device_authenticated"] = True
        res["device_sk"] = dev.last_sk
        ack_wire = to_wire(ack)

        if drop_ack:
            res["stage"] = "ack_lost"
            self.log("[Channel] ACK LOST. Device already uses the new state; "
                     "fog keeps the candidate until the next session.", "warn")
            return res
        if verbose:
            self._wire("Device -> Fog", "ACK", ack, ack_wire)

        # 4. fog verifies ACK, activates candidate
        try:
            fog.handle_ack(from_wire(ack_wire))
        except ProtocolError as e:
            res["error"], res["stage"] = str(e), "ack_rejected"
            self.log(f"[Fog] {e}", "err")
            return res
        res["acked"], res["stage"] = True, "complete"

        if verbose:
            same = res["device_sk"] == res["fog_sk"]
            self.log("")
            self.log("[RESULT] Device authentication : SUCCESS", "ok")
            self.log("[RESULT] Fog authentication    : SUCCESS", "ok")
            self.log("[RESULT] ACK / synchronisation : SUCCESS", "ok")
            self.log(f"[RESULT] SK fingerprint (device) : "
                     f"{fingerprint(res['device_sk'])}")
            self.log(f"[RESULT] SK fingerprint (fog)    : "
                     f"{fingerprint(res['fog_sk'])}")
            self.log(f"[RESULT] Session keys identical  : {same}",
                     "ok" if same else "err")
            self.log(f"[RESULT] Sync status             : "
                     f"{self.sync_status(device_id)}")
        return res

    def replay_last_request(self, device_id):
        self._require_init()
        dev = self.device(device_id)
        fog = self.fog(dev.fog_id)
        wire = self.captured.get(device_id)
        if wire is None:
            raise LabError("No captured Auth_Req for this device yet. "
                           "Run a session first.")
        self.section(f"ATTACK: REPLAY OF CAPTURED Auth_Req ({device_id})")
        self.log("[Attacker] Re-sending a previously captured Auth_Req.",
                 "warn")
        try:
            fog.handle_request(from_wire(wire))
        except ProtocolError as e:
            self.log(f"[Fog] {e}", "err")
            self.log("[RESULT] Replay attack was REJECTED.", "ok")
            return str(e)
        self.log("[RESULT] Replay attack was ACCEPTED (unexpected!).", "err")
        return None

    # ---------------- state inspection ----------------
    def sync_status(self, device_id):
        d = self.db.conn.execute(
            "SELECT * FROM device_node WHERE device_id=?",
            (device_id,)).fetchone()
        f = self.db.conn.execute(
            "SELECT * FROM fog_devices WHERE fog_id=? AND a_d=?",
            (d["fog_id"], d["a_d"])).fetchone()
        dev = (d["tid_d"], d["tid_f"], d["b_k"])
        cur = (f["tid_d"], f["tid_f"], f["b_k"])
        if not f["pending"]:
            return "SYNC" if dev == cur else "DESYNC"
        cand = (f["tid_d_c"], f["tid_f_c"], f["b_k_c"])
        if dev == cand:
            return "DEVICE_AHEAD"      # ACK lost, recoverable
        if dev == cur:
            return "FOG_PENDING"       # Auth_Rep lost / ACK in flight
        return "DESYNC"

    def state_report(self):
        c = self.db.conn
        lines = []

        def dump(title, table, hide=()):
            lines.append(f"--- {title}  [{table}] ---")
            cur = c.execute(f"SELECT * FROM {table}")
            cols = [x[0] for x in cur.description]
            rows = cur.fetchall()
            if not rows:
                lines.append("   (empty)")
            for r in rows:
                parts = []
                for col in cols:
                    v = r[col]
                    if col in hide:
                        v = "(hidden)"
                    elif isinstance(v, bytes):
                        v = hx(v, 10)
                    parts.append(f"{col}={v}")
                lines.append("   " + " | ".join(parts))
            lines.append("")

        dump("RA: system configuration", "system_config", hide=("master_secret",))
        dump("RA: fog repository", "ra_fog")
        dump("RA: device repository", "ra_device")
        dump("Fog: own credentials", "fog_node")
        dump("Fog: per-device state (current + candidate)", "fog_devices")
        dump("Device: own state (current + previous)", "device_node")
        lines.append("--- Synchronisation status ---")
        for d in self.device_ids():
            lines.append(f"   {d}: {self.sync_status(d)}")
        return "\n".join(lines)


# ============================================================
# AUTOMATED SELF-TESTS
# ============================================================

def run_self_tests(log):
    quiet = lambda msg="", tag=None: None
    lab = Lab(RMLADatabase(None), quiet)
    lab.initialize()
    lab.add_fog("FOG-A")
    lab.add_device("DEV-1", "FOG-A")
    lab.add_device("DEV-2", "FOG-A")

    results = []

    def check(name, cond):
        results.append((name, bool(cond)))
        log(f"   [{'PASS' if cond else 'FAIL'}] {name}",
            "ok" if cond else "err")

    def expect_error(fn):
        try:
            fn()
        except ProtocolError:
            return True
        return False

    log("")
    log("=" * 72, "sec")
    log("AUTOMATED SELF-TESTS (isolated in-memory database)", "sec")
    log("=" * 72, "sec")

    # T0: verify the concrete field sizes claimed by the paper's table.
    field_device = lab.device("DEV-1")
    field_req = field_device.make_request()
    field_sizes_ok = (
        len(field_req["G_d"]) * 8 == 160
        and len(field_req["I"]) * 8 == 320
        and len(field_req["E_d"]) * 8 == 128
        and len(ts_bytes(field_req["T_d"])) * 8 == 32
    )
    check("T0  request field sizes match the paper's parameter table",
          field_sizes_ok)
    field_device.abort()

    # T1 -------------------------------------------------------
    r = lab.session("DEV-1", verbose=False)
    check("T1  normal session: both parties authenticated, ACK accepted",
          r["acked"] and r["device_authenticated"] and r["fog_authenticated"])
    check("T1b session keys identical on both sides",
          r["device_sk"] == r["fog_sk"] and r["device_sk"] is not None)
    check("T1c credentials synchronised", lab.sync_status("DEV-1") == "SYNC")

    # T2 -------------------------------------------------------
    keys, ok = set(), True
    for _ in range(5):
        r = lab.session("DEV-1", verbose=False)
        ok &= r["acked"] and r["device_sk"] == r["fog_sk"]
        keys.add(r["device_sk"])
    check("T2  5 consecutive sessions succeed with 5 distinct keys",
          ok and len(keys) == 5 and lab.sync_status("DEV-1") == "SYNC")

    # T3 -------------------------------------------------------
    r = lab.session("DEV-1", drop_ack=True, verbose=False)
    check("T3  ACK loss: device ahead of fog (recoverable)",
          r["device_authenticated"] and not r["acked"]
          and lab.sync_status("DEV-1") == "DEVICE_AHEAD")
    r = lab.session("DEV-1", verbose=False)
    check("T3b next session recovers and re-synchronises",
          r["acked"] and lab.sync_status("DEV-1") == "SYNC")

    # T4 -------------------------------------------------------
    r = lab.session("DEV-1", drop_rep=True, verbose=False)
    check("T4  Auth_Rep loss: fog pending, device unchanged",
          r["fog_authenticated"] and not r["device_authenticated"]
          and lab.sync_status("DEV-1") == "FOG_PENDING")
    r = lab.session("DEV-1", verbose=False)
    check("T4b next session succeeds and re-synchronises",
          r["acked"] and lab.sync_status("DEV-1") == "SYNC")

    # T5 -------------------------------------------------------
    lab.session("DEV-1", drop_ack=True, verbose=False)
    lab.session("DEV-1", drop_ack=True, verbose=False)
    lab.session("DEV-1", drop_rep=True, verbose=False)
    r = lab.session("DEV-1", verbose=False)
    check("T5  repeated ACK/Auth_Rep losses never cause permanent desync",
          r["acked"] and lab.sync_status("DEV-1") == "SYNC")

    # T6 -------------------------------------------------------
    lab.session("DEV-1", drop_ack=True, verbose=False)
    check("T6  replayed Auth_Req is rejected (cache)",
          expect_error(lambda: lab.fog("FOG-A").handle_request(
              from_wire(lab.captured["DEV-1"]))))
    r = lab.session("DEV-1", verbose=False)
    check("T6b replay did not destroy the pending candidate (still recovers)",
          r["acked"] and lab.sync_status("DEV-1") == "SYNC")

    # T7 -------------------------------------------------------
    r = lab.session("DEV-1", tamper=True, verbose=False)
    check("T7  tampered Auth_Req rejected by fog",
          not r["fog_authenticated"] and r["stage"] == "fog_rejected")
    r = lab.session("DEV-1", verbose=False)
    check("T7b state unaffected by the failed attack",
          r["acked"] and lab.sync_status("DEV-1") == "SYNC")

    # T8 -------------------------------------------------------
    r = lab.session("DEV-1", stale=True, verbose=False)
    check("T8  stale timestamp rejected",
          not r["fog_authenticated"] and "fresh" in (r["error"] or ""))
    r = lab.session("DEV-1", verbose=False)
    check("T8b protocol continues normally afterwards", r["acked"])

    # T9 -------------------------------------------------------
    lab.session("DEV-1", drop_ack=True, verbose=False)
    r2 = lab.session("DEV-2", verbose=False)
    r1 = lab.session("DEV-1", verbose=False)
    check("T9  two devices on one fog node stay independent",
          r1["acked"] and r2["acked"]
          and lab.sync_status("DEV-1") == "SYNC"
          and lab.sync_status("DEV-2") == "SYNC")

    # T10 ------------------------------------------------------
    lab.session("DEV-2", verbose=False)
    old_req = lab.captured["DEV-2"]
    lab.session("DEV-2", verbose=False)
    lab.fog("FOG-A").replay.clear()
    check("T10 retired TID_d no longer accepted (old state erased)",
          expect_error(lambda: lab.fog("FOG-A").handle_request(
              from_wire(old_req))))

    # T11 ------------------------------------------------------
    dev, fog = lab.device("DEV-1"), lab.fog("FOG-A")
    rep1 = fog.handle_request(dev.make_request())
    fog.handle_ack(dev.handle_response(rep1))
    dev.make_request()
    check("T11 replayed old Auth_Rep rejected by device",
          expect_error(lambda: dev.handle_response(rep1)))
    dev.abort()
    check("T11b device state unchanged by rejected Auth_Rep",
          lab.sync_status("DEV-1") == "SYNC")

    # T12 ------------------------------------------------------
    bad = dict(lab.device("DEV-1").make_request())
    bad["G_d"] = bad["G_d"][:-1]
    check("T12 malformed message (wrong length) rejected",
          expect_error(lambda: lab.fog("FOG-A").handle_request(bad)))
    lab.device("DEV-1").abort()

    passed = sum(1 for _, ok in results if ok)
    log("")
    log(f"SELF-TEST SUMMARY: {passed}/{len(results)} passed",
        "ok" if passed == len(results) else "err")
    return passed == len(results)


# ============================================================
# GRAPHICAL USER INTERFACE (simple: Registration + Authentication)
# ============================================================

class RMLAApp:

    def __init__(self, root):
        self.root = root
        root.title("RMLA Authentication Protocol - Laboratory Prototype")
        root.geometry("1000x720")
        root.minsize(800, 560)

        self.db = RMLADatabase(DB_PATH)
        self.records = []
        self.lab = Lab(self.db, self.log)
        self.status = tk.StringVar(value="Ready. Press Registration first.")

        self.build_ui()

        self.log("RMLA Laboratory Prototype started.", "sec")
        self.log("Curve: secp160r1 (320-bit x||y) | Hash: SHA-256/160 | Nonces: 128-bit")
        self.log("1) Press 'Registration'   2) Press 'Authentication'")

    # ---------------------------------------------------- layout
    def build_ui(self):
        ttk.Label(self.root, text="RMLA Authentication Protocol",
                  font=("Arial", 19, "bold")).pack(pady=(12, 0))
        ttk.Label(self.root, text="Laboratory-scale functional prototype",
                  font=("Arial", 10)).pack(pady=(0, 8))

        top = ttk.LabelFrame(self.root, text="Entities", padding=10)
        top.pack(fill=tk.X, padx=12, pady=4)
        ttk.Label(top, text="Fog Node ID:").grid(row=0, column=0, sticky="w",
                                                 padx=4, pady=3)
        self.fog_entry = ttk.Entry(top, width=28)
        self.fog_entry.grid(row=0, column=1, padx=4, pady=3)
        self.fog_entry.insert(0, "FOG-001")
        ttk.Label(top, text="IoT Device ID:").grid(row=0, column=2,
                                                   sticky="w", padx=(20, 4))
        self.dev_entry = ttk.Entry(top, width=28)
        self.dev_entry.grid(row=0, column=3, padx=4, pady=3)
        self.dev_entry.insert(0, "DEVICE-001")

        btns = ttk.Frame(self.root)
        btns.pack(fill=tk.X, padx=12, pady=6)
        ttk.Button(btns, text="Registration",
                   command=self.on_register).pack(
            side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 6), ipady=8)
        ttk.Button(btns, text="Authentication",
                   command=self.on_authenticate).pack(
            side=tk.LEFT, expand=True, fill=tk.X, padx=(6, 0), ipady=8)

        out = ttk.LabelFrame(self.root, text="Protocol Execution Log",
                             padding=6)
        out.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)
        self.output = tk.Text(out, wrap=tk.WORD, font=("Consolas", 10),
                              undo=False)
        sb = ttk.Scrollbar(out, orient=tk.VERTICAL,
                           command=self.output.yview)
        self.output.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.output.tag_configure("sec", foreground="#1a4fa0",
                                  font=("Consolas", 10, "bold"))
        self.output.tag_configure("ok", foreground="#0a7a2f")
        self.output.tag_configure("err", foreground="#b00020")
        self.output.tag_configure("warn", foreground="#b36b00")
        self.output.tag_configure("wire", foreground="#666666")

        self.output.bind("<Key>", self._block_key)
        self.output.bind("<Control-a>", self._select_all_event)
        self.output.bind("<Control-A>", self._select_all_event)

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Select All", command=self.select_all)
        menu.add_command(label="Copy Selected", command=self.copy_selection)
        menu.add_command(label="Copy All", command=self.copy_all)
        self.output.bind("<Button-3>", lambda e: self._popup(menu, e))
        self.output.bind("<Button-2>", lambda e: self._popup(menu, e))

        bar = ttk.Frame(self.root)
        bar.pack(fill=tk.X, padx=12, pady=(2, 6))
        for text, cmd in (("Copy All", self.copy_all),
                          ("Copy Selected", self.copy_selection),
                          ("Export TXT", self.export_txt),
                          ("Export CSV", self.export_csv),
                          ("Clear Log", self.clear_log)):
            ttk.Button(bar, text=text, command=cmd).pack(side=tk.LEFT, padx=3)

        ttk.Label(self.root, textvariable=self.status, relief=tk.SUNKEN,
                  anchor="w").pack(fill=tk.X, side=tk.BOTTOM)

    # ---------------------------------------------------- log helpers
    def log(self, message="", tag=None):
        ts = datetime.now().strftime("%H:%M:%S")
        self.records.append({"timestamp": ts, "message": str(message)})
        self.output.insert(tk.END, f"[{ts}] {message}\n", tag or ())
        self.output.see(tk.END)
        self.root.update_idletasks()

    def _block_key(self, e):
        if (e.state & 0x4) and e.keysym.lower() in ("c", "a"):
            return None
        if e.keysym in ("Left", "Right", "Up", "Down", "Prior", "Next",
                        "Home", "End"):
            return None
        return "break"

    def _popup(self, menu, e):
        try:
            menu.tk_popup(e.x_root, e.y_root)
        finally:
            menu.grab_release()

    def select_all(self):
        self.output.focus_set()
        self.output.tag_add("sel", "1.0", "end-1c")

    def _select_all_event(self, e=None):
        self.select_all()
        return "break"

    def _clip(self, text):
        if not text.strip():
            self.status.set("Nothing to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        self.status.set("Copied to clipboard.")

    def copy_all(self):
        self._clip(self.output.get("1.0", "end-1c"))

    def copy_selection(self):
        try:
            self._clip(self.output.get("sel.first", "sel.last"))
        except tk.TclError:
            self.status.set("Select some text first.")

    def clear_log(self):
        if messagebox.askyesno("Clear Log", "Clear the displayed log?"):
            self.output.delete("1.0", tk.END)
            self.records.clear()

    def export_txt(self):
        content = self.output.get("1.0", "end-1c")
        if not content.strip():
            return messagebox.showwarning("Empty", "Nothing to export.")
        fn = filedialog.asksaveasfilename(
            defaultextension=".txt", initialfile="RMLA_Execution_Log.txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if fn:
            try:
                Path(fn).write_text(content, encoding="utf-8")
                self.status.set(f"Saved {fn}")
            except OSError as e:
                messagebox.showerror("Export error", str(e))

    def export_csv(self):
        if not self.records:
            return messagebox.showwarning("Empty", "Nothing to export.")
        fn = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile="RMLA_Execution_Log.csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if fn:
            try:
                with open(fn, "w", newline="", encoding="utf-8-sig") as f:
                    w = csv.DictWriter(f, fieldnames=["timestamp", "message"])
                    w.writeheader()
                    w.writerows(self.records)
                self.status.set(f"Saved {fn}")
            except OSError as e:
                messagebox.showerror("Export error", str(e))

    # ---------------------------------------------------- actions
    def on_register(self):
        fog_id = self.fog_entry.get().strip()
        dev_id = self.dev_entry.get().strip()
        if not fog_id or not dev_id:
            return messagebox.showwarning(
                "Input", "Enter both a Fog Node ID and an IoT Device ID.")
        if self.lab.device_ids() and not messagebox.askyesno(
                "Registration",
                "Existing registration data will be replaced. Continue?"):
            return
        try:
            self.lab.initialize()                 # initialization phase
            self.lab.add_fog(fog_id)              # fog registration
            self.lab.add_device(dev_id, fog_id)   # device registration
            self.log("")
            self.log("[RESULT] Registration completed successfully.", "ok")
            self.status.set("Registration done. Press Authentication.")
        except (LabError, ProtocolError) as e:
            self.log(f"[ERROR] {e}", "err")
            messagebox.showwarning("Registration", str(e))
        except Exception as e:                                # noqa
            self.log(f"[ERROR] {type(e).__name__}: {e}", "err")
            messagebox.showerror("Unexpected error", str(e))

    def on_authenticate(self):
        devices = self.lab.device_ids()
        if not devices:
            return messagebox.showwarning(
                "Authentication", "Press Registration first.")
        try:
            res = self.lab.session(devices[-1])
            if res["acked"]:
                self.status.set("Authentication successful.")
            else:
                self.status.set("Authentication failed.")
        except (LabError, ProtocolError) as e:
            self.log(f"[ERROR] {e}", "err")
            messagebox.showwarning("Authentication", str(e))
        except Exception as e:                                # noqa
            self.log(f"[ERROR] {type(e).__name__}: {e}", "err")
            messagebox.showerror("Unexpected error", str(e))


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    if "--selftest" in sys.argv:
        ok = run_self_tests(lambda m="", t=None: print(m))
        sys.exit(0 if ok else 1)

    if tk is None:
        print("tkinter is not available; use --selftest for headless mode.")
        sys.exit(1)

    root = tk.Tk()
    app = RMLAApp(root)

    def on_close():
        app.db.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
