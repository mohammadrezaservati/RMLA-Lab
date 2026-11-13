
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RMLA EXECUTION-TIME BENCHMARK

Files:
    rmla_benchmark.py
    rmla_lab.py

Run:
    python rmla_benchmark.py

Optional:
    python rmla_benchmark.py --warmup 20 --sessions 1000

CSV:
    python rmla_benchmark.py --warmup 20 --sessions 1000 --csv rmla_results.csv
"""

import argparse
import csv
import statistics
import sys
import time

try:
    from rmla_lab import RMLADatabase, Lab
except ImportError as exc:
    raise SystemExit(
        "\nERROR: Cannot import the RMLA prototype.\n"
        "Make sure rmla_lab.py is in the same directory as this file.\n"
    ) from exc


# ================================================================
# CONFIGURATION
# ================================================================

DEFAULT_WARMUP = 20
DEFAULT_SESSIONS = 1000

DEFAULT_FOG_ID = "FOG-001"
DEFAULT_DEVICE_ID = "DEVICE-001"


# ================================================================
# HELPER FUNCTIONS
# ================================================================

def quiet_log(*args, **kwargs):
    """
    Suppress prototype logs during benchmark execution.
    GUI output is not included in measurements.
    """
    pass


def nanoseconds_to_ms(value):
    """Convert nanoseconds to milliseconds."""
    return value / 1_000_000.0


def calculate_statistics(samples):

    return {
        "mean": statistics.mean(samples),
        "std": (
            statistics.stdev(samples)
            if len(samples) > 1
            else 0.0
        ),
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }


def verify_session(result, session_number):

    if not isinstance(result, dict):
        raise RuntimeError(
            f"Session {session_number}: unexpected result format."
        )

    if not result.get("acked"):
        raise RuntimeError(
            f"Session {session_number}: protocol session failed. "
            f"Details: {result}"
        )

    device_sk = result.get("device_sk")
    fog_sk = result.get("fog_sk")

    if device_sk is None or fog_sk is None:
        raise RuntimeError(
            f"Session {session_number}: session key is missing."
        )

    if device_sk != fog_sk:
        raise RuntimeError(
            f"Session {session_number}: session keys do not match."
        )

    return True


# ================================================================
# CSV EXPORT
# ================================================================

def export_csv(
    csv_path,
    initialization_ms,
    fog_registration_ms,
    device_registration_ms,
    total_registration_ms,
    stats,
    complete_workflow_ms,
    successful_sessions,
    key_agreement_count,
    synchronization_count,
    samples
):

    with open(
        csv_path,
        mode="w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(["Metric", "Value", "Unit"])

        writer.writerow([
            "System Initialization",
            initialization_ms,
            "ms"
        ])

        writer.writerow([
            "Fog Registration",
            fog_registration_ms,
            "ms"
        ])

        writer.writerow([
            "Device Registration",
            device_registration_ms,
            "ms"
        ])

        writer.writerow([
            "Total Registration",
            total_registration_ms,
            "ms"
        ])

        writer.writerow([
            "Authentication Mean",
            stats["mean"],
            "ms"
        ])

        writer.writerow([
            "Authentication Standard Deviation",
            stats["std"],
            "ms"
        ])

        writer.writerow([
            "Authentication Median",
            stats["median"],
            "ms"
        ])

        writer.writerow([
            "Authentication Minimum",
            stats["min"],
            "ms"
        ])

        writer.writerow([
            "Authentication Maximum",
            stats["max"],
            "ms"
        ])

        writer.writerow([
            "Complete Workflow",
            complete_workflow_ms,
            "ms"
        ])

        writer.writerow([
            "Successful Sessions",
            successful_sessions,
            "sessions"
        ])

        writer.writerow([
            "Session Key Agreements",
            key_agreement_count,
            "sessions"
        ])

        writer.writerow([
            "Credential Synchronizations",
            synchronization_count,
            "sessions"
        ])

        writer.writerow([])

        writer.writerow([
            "Session Index",
            "Authentication Time (ms)"
        ])

        for index, sample in enumerate(samples, start=1):

            writer.writerow([
                index,
                sample
            ])


# ================================================================
# MAIN BENCHMARK
# ================================================================

def run_benchmark(
    warmup=DEFAULT_WARMUP,
    sessions=DEFAULT_SESSIONS,
    fog_id=DEFAULT_FOG_ID,
    device_id=DEFAULT_DEVICE_ID,
    csv_path=None
):

    if warmup < 0:
        raise ValueError(
            "Warm-up sessions cannot be negative."
        )

    if sessions < 1:
        raise ValueError(
            "Benchmark sessions must be at least 1."
        )

    # ------------------------------------------------------------
    # DATABASE AND PROTOCOL INITIALIZATION
    # ------------------------------------------------------------

    db = RMLADatabase(None)
    lab = Lab(db, quiet_log)

    try:

        # --------------------------------------------------------
        # 1. SYSTEM INITIALIZATION
        # --------------------------------------------------------

        start = time.perf_counter_ns()

        lab.initialize()

        initialization_ms = nanoseconds_to_ms(
            time.perf_counter_ns() - start
        )

        # --------------------------------------------------------
        # 2. FOG REGISTRATION
        # --------------------------------------------------------

        start = time.perf_counter_ns()

        lab.add_fog(fog_id)

        fog_registration_ms = nanoseconds_to_ms(
            time.perf_counter_ns() - start
        )

        # --------------------------------------------------------
        # 3. DEVICE REGISTRATION
        # --------------------------------------------------------

        start = time.perf_counter_ns()

        lab.add_device(device_id, fog_id)

        device_registration_ms = nanoseconds_to_ms(
            time.perf_counter_ns() - start
        )

        total_registration_ms = (
            fog_registration_ms
            + device_registration_ms
        )

        # --------------------------------------------------------
        # 4. WARM-UP
        # --------------------------------------------------------

        for i in range(warmup):

            result = lab.session(
                device_id,
                verbose=False
            )

            verify_session(
                result,
                f"Warm-up {i + 1}"
            )

            if lab.sync_status(device_id) != "SYNC":

                raise RuntimeError(
                    f"Warm-up session {i + 1}: "
                    "credential synchronization failed."
                )

        # --------------------------------------------------------
        # 5. MEASURED SESSIONS
        # --------------------------------------------------------

        authentication_times = []

        key_agreement_count = 0
        synchronization_count = 0

        for i in range(sessions):

            start = time.perf_counter_ns()

            result = lab.session(
                device_id,
                verbose=False
            )

            elapsed = time.perf_counter_ns() - start

            # Validate the completed protocol execution.
            verify_session(
                result,
                i + 1
            )

            authentication_times.append(
                nanoseconds_to_ms(elapsed)
            )

            # Session-key agreement.
            device_sk = result.get("device_sk")
            fog_sk = result.get("fog_sk")

            if (
                device_sk is not None
                and fog_sk is not None
                and device_sk == fog_sk
            ):

                key_agreement_count += 1

            # Credential synchronization.
            if lab.sync_status(device_id) == "SYNC":

                synchronization_count += 1

        # --------------------------------------------------------
        # 6. CALCULATE RESULTS
        # --------------------------------------------------------

        stats = calculate_statistics(
            authentication_times
        )

        complete_workflow_ms = (
            total_registration_ms
            + stats["mean"]
        )

        final_sync = lab.sync_status(device_id)

        successful_sessions = len(
            authentication_times
        )

        # In this implementation, a completed ACKed session,
        # matching session keys and successful synchronization
        # are used together as the mutual-authentication check.
        mutual_authentication_verified = (
            successful_sessions == sessions
            and key_agreement_count == sessions
            and synchronization_count == sessions
            and final_sync == "SYNC"
        )

        # --------------------------------------------------------
        # 7. PRINT TERMINAL REPORT
        # --------------------------------------------------------

        print()

        print("=" * 76)
        print("RMLA EXECUTION-TIME BENCHMARK")
        print("=" * 76)

        print(
            f"{'Cryptographic Suite':<34}: "
            "NIST P-256 / SHA-256"
        )

        print(
            f"{'Fog Node ID':<34}: {fog_id}"
        )

        print(
            f"{'IoT Device ID':<34}: {device_id}"
        )

        print(
            f"{'Warm-up Sessions':<34}: {warmup}"
        )

        print(
            f"{'Benchmark Sessions':<34}: {sessions}"
        )

        print(
            f"{'Database':<34}: In-Memory SQLite"
        )

        print(
            f"{'GUI Overhead':<34}: Excluded"
        )

        print("=" * 76)

        print()
        print("=" * 76)
        print("BENCHMARK RESULTS")
        print("=" * 76)

        print(
            f"{'System Initialization':<34}: "
            f"{initialization_ms:.6f} ms"
        )

        print(
            f"{'Fog Registration':<34}: "
            f"{fog_registration_ms:.6f} ms"
        )

        print(
            f"{'Device Registration':<34}: "
            f"{device_registration_ms:.6f} ms"
        )

        print(
            f"{'Total Registration':<34}: "
            f"{total_registration_ms:.6f} ms"
        )

        print()

        print(
            f"{'Authentication (Mean)':<34}: "
            f"{stats['mean']:.6f} ms"
        )

        print(
            f"{'Authentication (Min)':<34}: "
            f"{stats['min']:.6f} ms"
        )

        print(
            f"{'Authentication (Max)':<34}: "
            f"{stats['max']:.6f} ms"
        )

        print(
            f"{'Authentication (Median)':<34}: "
            f"{stats['median']:.6f} ms"
        )

        print(
            f"{'Standard Deviation':<34}: "
            f"{stats['std']:.6f} ms"
        )

        print()

        print(
            f"{'Complete Workflow':<34}: "
            f"{complete_workflow_ms:.6f} ms"
        )

        print()

        print(
            f"{'Authentication Result':<34}: "
            f"{'SUCCESS' if successful_sessions == sessions else 'FAILED'}"
        )

        print(
            f"{'Session Key Agreement':<34}: "
            f"{'VERIFIED' if key_agreement_count == sessions else 'FAILED'}"
        )

        print(
            f"{'Mutual Authentication':<34}: "
            f"{'VERIFIED' if mutual_authentication_verified else 'FAILED'}"
        )

        print(
            f"{'Credential Synchronization':<34}: "
            f"{'VERIFIED' if synchronization_count == sessions else 'FAILED'}"
        )

        print(
            f"{'Successful Sessions':<34}: "
            f"{successful_sessions} / {sessions}"
        )

        print(
            f"{'Final Synchronization State':<34}: "
            f"{final_sync}"
        )

        print("=" * 76)

        # --------------------------------------------------------
        # 8. MEASUREMENT NOTES
        # --------------------------------------------------------

        print()
        print("Measurement Notes:")

        print(
            "- Authentication measures the complete Lab.session execution."
        )

        print(
            "- It includes Auth_Req, Fog processing, Auth_Rep,"
        )

        print(
            "  Device verification, ACK processing, and state synchronization."
        )

        print(
            "- Session-key agreement is verified by comparing both keys."
        )

        print(
            "- Mutual authentication status is based on successful"
        )

        print(
            "  ACK completion, key agreement, and synchronization checks."
        )

        print(
            "- GUI rendering and visible log output are excluded."
        )

        print(
            "- Warm-up sessions are excluded from timing statistics."
        )

        print(
            "- Complete Workflow = Fog registration + Device registration"
        )

        print(
            "  + mean authentication time."
        )

        print(
            "- These are local implementation execution times,"
        )

        print(
            "  not real-network latency measurements."
        )

        # --------------------------------------------------------
        # 9. OPTIONAL CSV EXPORT
        # --------------------------------------------------------

        if csv_path:

            export_csv(
                csv_path=csv_path,
                initialization_ms=initialization_ms,
                fog_registration_ms=fog_registration_ms,
                device_registration_ms=device_registration_ms,
                total_registration_ms=total_registration_ms,
                stats=stats,
                complete_workflow_ms=complete_workflow_ms,
                successful_sessions=successful_sessions,
                key_agreement_count=key_agreement_count,
                synchronization_count=synchronization_count,
                samples=authentication_times
            )

            print()
            print(
                f"CSV report saved: {csv_path}"
            )

    finally:

        # Always close the database, including when a session fails.
        db.close()


# ================================================================
# COMMAND-LINE INTERFACE
# ================================================================

def main():

    parser = argparse.ArgumentParser(
        description="RMLA Execution-Time Benchmark"
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP
    )

    parser.add_argument(
        "--sessions",
        type=int,
        default=DEFAULT_SESSIONS
    )

    parser.add_argument(
        "--fog",
        type=str,
        default=DEFAULT_FOG_ID
    )

    parser.add_argument(
        "--device",
        type=str,
        default=DEFAULT_DEVICE_ID
    )

    parser.add_argument(
        "--csv",
        type=str,
        default=None,
        help="Optional CSV output file."
    )

    args = parser.parse_args()

    try:

        run_benchmark(
            warmup=args.warmup,
            sessions=args.sessions,
            fog_id=args.fog,
            device_id=args.device,
            csv_path=args.csv
        )

    except (ValueError, RuntimeError) as exc:

        print(
            f"\nBENCHMARK ERROR: {exc}",
            file=sys.stderr
        )

        raise SystemExit(1)


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    main()
