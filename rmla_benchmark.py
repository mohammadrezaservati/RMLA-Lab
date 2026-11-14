#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Benchmark the exact current RMLA Laboratory v4 implementation.

Keep this file beside RMLA_Laboratory_v4_paper_aligned.py.
Run:
    python RMLA_Benchmark_v4_paper_aligned.py
    python RMLA_Benchmark_v4_paper_aligned.py --warmup 20 --sessions 1000
    python RMLA_Benchmark_v4_paper_aligned.py --sessions 1000 --csv rmla_v4_results.csv

The prototype is imported directly; protocol equations/steps are not reimplemented.
Overall session timings are collected without instrumentation. A separate
profile run counts actual H(), _scalar_mult(), and xor_bytes() calls; its
instrumentation overhead is excluded from the reported timing statistics.
"""

import argparse
import csv
import importlib.util
import statistics
import sys
import time
from pathlib import Path

DEFAULT_PROTOTYPE = "RMLA_Laboratory_v4_paper_aligned.py"
DEFAULT_WARMUP = 20
DEFAULT_SESSIONS = 1000
DEFAULT_FOG_ID = "FOG-001"
DEFAULT_DEVICE_ID = "DEVICE-001"


def load_prototype(path):
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Prototype file not found: {path}")
    spec = importlib.util.spec_from_file_location("rmla_v4_prototype", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load prototype module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, path


def ns_to_ms(value):
    return value / 1_000_000.0


def summarize(samples):
    return {
        "mean": statistics.mean(samples),
        "std": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }


def assert_success(result, lab, device_id, label):
    required = (
        result.get("acked")
        and result.get("device_authenticated")
        and result.get("fog_authenticated")
        and result.get("device_sk") is not None
        and result.get("device_sk") == result.get("fog_sk")
        and lab.sync_status(device_id) == "SYNC"
    )
    if not required:
        raise RuntimeError(
            f"{label} did not complete correctly: result={result}; "
            f"sync={lab.sync_status(device_id)}"
        )


def make_lab(m):
    db = m.RMLADatabase(None)  # Same in-memory SQLite backend as the prototype.
    lab = m.Lab(db, lambda *_args, **_kwargs: None)
    return db, lab


def inspect_registered_sizes(m, lab, fog_id, device_id):
    db = lab.db
    d = db.conn.execute(
        "SELECT * FROM device_node WHERE device_id=?", (device_id,)
    ).fetchone()
    f = db.conn.execute(
        "SELECT * FROM fog_devices WHERE fog_id=? AND a_d=?",
        (fog_id, d["a_d"]),
    ).fetchone()
    if d is None or f is None:
        raise RuntimeError("Could not inspect registered device/fog records.")

    sizes = {
        "A_d": len(d["a_d"]),
        "A_f": len(d["a_f"]),
        "TID_d": len(d["tid_d"]),
        "TID_f": len(d["tid_f"]),
        "B_k_device": len(d["b_k"]),
        "B_k_fog": len(f["b_k"]),
    }
    expected = {
        "A_d": m.HASH_OUTPUT_BYTES,
        "A_f": m.HASH_OUTPUT_BYTES,
        "TID_d": m.HASH_OUTPUT_BYTES,
        "TID_f": m.HASH_OUTPUT_BYTES,
        "B_k_device": m.HASH_OUTPUT_BYTES,
        "B_k_fog": m.HASH_OUTPUT_BYTES,
    }
    for name, expected_len in expected.items():
        if sizes[name] != expected_len:
            raise RuntimeError(
                f"Parameter-size mismatch: {name} is {sizes[name]} bytes; "
                f"expected {expected_len} bytes from the prototype constants."
            )
    return sizes


def count_one_session_operations(m, fog_id, device_id):
    """Count calls in a separate session; does not affect timing samples."""
    db, lab = make_lab(m)
    counts = {"hash_calls": 0, "scalar_mult_calls": 0, "xor_calls": 0}
    original_h = m.H
    original_scalar_mult = m._scalar_mult
    original_xor = m.xor_bytes

    def counted_h(*args):
        counts["hash_calls"] += 1
        return original_h(*args)

    def counted_scalar_mult(*args, **kwargs):
        counts["scalar_mult_calls"] += 1
        return original_scalar_mult(*args, **kwargs)

    def counted_xor(*args, **kwargs):
        counts["xor_calls"] += 1
        return original_xor(*args, **kwargs)

    try:
        lab.initialize()
        lab.add_fog(fog_id)
        lab.add_device(device_id, fog_id)
        m.H = counted_h
        m._scalar_mult = counted_scalar_mult
        m.xor_bytes = counted_xor
        result = lab.session(device_id, verbose=False)
        assert_success(result, lab, device_id, "Instrumented profile session")
    finally:
        m.H = original_h
        m._scalar_mult = original_scalar_mult
        m.xor_bytes = original_xor
        db.close()
    return counts


def write_csv(path, metadata, stats, samples, counts):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["section", "metric", "value", "unit"])
        for key, value in metadata.items():
            w.writerow(["configuration", key, value, ""])
        for key, value in stats.items():
            w.writerow(["authentication_timing", key, value, "ms"])
        for key, value in counts.items():
            w.writerow(["one_session_operation_count", key, value, "calls/session"])
        w.writerow(["authentication_timing", "session_index", "time_ms", ""])
        for i, sample in enumerate(samples, 1):
            w.writerow(["authentication_timing", i, sample, "ms"])


def run(args):
    if args.warmup < 0:
        raise ValueError("--warmup must be zero or greater.")
    if args.sessions < 1:
        raise ValueError("--sessions must be at least 1.")

    m, prototype_path = load_prototype(args.prototype)
    db, lab = make_lab(m)
    try:
        # Initialize and register using the actual v4 classes.
        t0 = time.perf_counter_ns()
        lab.initialize()
        initialization_ms = ns_to_ms(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        lab.add_fog(args.fog)
        fog_registration_ms = ns_to_ms(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        lab.add_device(args.device, args.fog)
        device_registration_ms = ns_to_ms(time.perf_counter_ns() - t0)

        registered_sizes = inspect_registered_sizes(m, lab, args.fog, args.device)

        # Warm-up sessions are real protocol sessions but are not timed.
        for i in range(args.warmup):
            result = lab.session(args.device, verbose=False)
            assert_success(result, lab, args.device, f"Warm-up session {i + 1}")

        # Measure complete protocol sessions with no profiling wrappers.
        samples = []
        for i in range(args.sessions):
            start = time.perf_counter_ns()
            result = lab.session(args.device, verbose=False)
            elapsed = time.perf_counter_ns() - start
            assert_success(result, lab, args.device, f"Measured session {i + 1}")
            samples.append(ns_to_ms(elapsed))

        stats = summarize(samples)
        final_sync = lab.sync_status(args.device)
    finally:
        db.close()

    # One separate instrumented session counts actual primitive invocations.
    operation_counts = count_one_session_operations(m, args.fog, args.device)

    hash_bits = m.HASH_OUTPUT_BYTES * 8
    nonce_bits = m.NONCE_BYTES * 8
    mask_bits = m.MASK_BYTES * 8
    point_bits = m.ECC_POINT_BYTES * 8
    coord_bits = m.ECC_COORD_BYTES * 8
    timestamp_bits = 32  # ts_bytes() in this prototype serializes uint32 seconds.

    # Registration + one mean authentication session; initialization is shown
    # separately and included only in the explicitly named full-startup metric.
    registration_ms = fog_registration_ms + device_registration_ms
    end_to_end_one_session_ms = initialization_ms + registration_ms + stats["mean"]

    metadata = {
        "prototype_file": str(prototype_path),
        "curve": "secp160r1 (experimental)",
        "hash": f"SHA-256 truncated to {hash_bits} bits",
        "hash_output_bits": hash_bits,
        "ecc_point_encoding": f"x||y = {point_bits} bits ({m.ECC_POINT_BYTES} bytes)",
        "ecc_coordinate_bits": coord_bits,
        "nonce_bits": nonce_bits,
        "xor_mask_bits": mask_bits,
        "timestamp": f"unsigned {timestamp_bits}-bit Unix seconds",
        "timestamp_tolerance_seconds": m.DELTA_T_S,
        "B_k_bits": registered_sizes["B_k_device"] * 8,
        "database": "in-memory SQLite",
        "measurement_scope": "complete local Lab.session() including ACK and synchronization",
        "network_latency": "not measured",
        "symmetric_encryption_decryption": "not implemented; prototype uses XOR masking",
    }

    print("=" * 78)
    print("RMLA v4 — IMPLEMENTATION-ALIGNED EXECUTION-TIME BENCHMARK")
    print("=" * 78)
    print(f"Prototype file                 : {prototype_path.name}")
    print(f"Curve                           : secp160r1 (experimental)")
    print(f"Hash                            : SHA-256 / {hash_bits}-bit truncated output")
    print(f"ECC point encoding              : x||y / {point_bits} bits")
    print(f"ECC coordinate                  : {coord_bits} bits each")
    print(f"Protocol nonce                  : {nonce_bits} bits")
    print(f"XOR mask                        : {mask_bits} bits")
    print(f"B_k                             : {metadata['B_k_bits']} bits (runtime DB check)")
    print(f"Timestamp                       : uint{timestamp_bits} Unix seconds")
    print(f"Timestamp tolerance             : {m.DELTA_T_S} seconds")
    print("Symmetric SE/SD                 : NOT IMPLEMENTED (XOR masking is used)")
    print(f"Warm-up sessions                : {args.warmup}")
    print(f"Measured sessions               : {args.sessions}")
    print("Database                        : In-memory SQLite")
    print("GUI/log rendering               : excluded")
    print("Network latency                 : not measured")
    print("-" * 78)
    print("REGISTERED DATABASE FIELD SIZES")
    for key, value in registered_sizes.items():
        print(f"{key:<32}: {value * 8:>4} bits ({value} bytes)")
    print("-" * 78)
    print("TIMING RESULTS")
    print(f"System initialization           : {initialization_ms:.6f} ms")
    print(f"Fog registration                : {fog_registration_ms:.6f} ms")
    print(f"Device registration             : {device_registration_ms:.6f} ms")
    print(f"Total registration              : {registration_ms:.6f} ms")
    print(f"Authentication mean             : {stats['mean']:.6f} ms")
    print(f"Authentication median           : {stats['median']:.6f} ms")
    print(f"Authentication standard dev.    : {stats['std']:.6f} ms")
    print(f"Authentication minimum          : {stats['min']:.6f} ms")
    print(f"Authentication maximum          : {stats['max']:.6f} ms")
    print(f"Initialization + registration + one mean session: {end_to_end_one_session_ms:.6f} ms")
    print("-" * 78)
    print("ACTUAL PRIMITIVE CALL COUNTS IN ONE AUTHENTICATION SESSION")
    print(f"H() calls                        : {operation_counts['hash_calls']}")
    print(f"_scalar_mult() calls              : {operation_counts['scalar_mult_calls']}")
    print(f"xor_bytes() calls                 : {operation_counts['xor_calls']}")
    print("Note: profiling counts come from a separate instrumented session;")
    print("      profiling overhead is not included in timing statistics.")
    print("-" * 78)
    print(f"Successful sessions              : {len(samples)} / {args.sessions}")
    print(f"Mutual authentication             : VERIFIED")
    print(f"Session-key agreement             : VERIFIED")
    print(f"ACK + credential synchronization  : {final_sync}")
    print("=" * 78)
    print("Interpretation:")
    print("* Authentication time is the full local Lab.session() path:")
    print("  Auth_Req, Fog verification/response, Device verification, ACK,")
    print("  and the prototype's credential-state update.")
    print("* The prototype does not implement a symmetric SE/SD primitive;")
    print("  XOR masking must not be reported as AES or symmetric encryption.")
    print("* The reported timings are implementation execution times, not")
    print("  network latency and not the paper's assumed per-primitive constants.")

    if args.csv:
        write_csv(args.csv, metadata, stats, samples, operation_counts)
        print(f"CSV saved                         : {args.csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark the exact current RMLA Laboratory v4 implementation."
    )
    parser.add_argument("--prototype", default=DEFAULT_PROTOTYPE,
                        help=f"prototype Python file (default: {DEFAULT_PROTOTYPE})")
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument("--sessions", type=int, default=DEFAULT_SESSIONS)
    parser.add_argument("--fog", default=DEFAULT_FOG_ID)
    parser.add_argument("--device", default=DEFAULT_DEVICE_ID)
    parser.add_argument("--csv", default=None, help="optional CSV output path")
    args = parser.parse_args()
    try:
        run(args)
    except (ValueError, RuntimeError, ImportError, FileNotFoundError) as exc:
        print(f"BENCHMARK ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
