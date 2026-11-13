# RMLA-Lab: A Lightweight Mutual Authentication Protocol for WBANs

## Authors

Masoumeh Safkhani, Mohammad Reza Servati, Hadis Shahbazi

---

## Overview

**RMLA-Lab** is an executable laboratory implementation of the **RMLA lightweight registration and mutual authentication protocol**, designed for **Wireless Body Area Networks (WBANs)** operating in a WBAN–Fog–Registration Authority (RA) architecture.

The laboratory demonstrates the complete protocol workflow, including system initialization, secure device and fog-node registration, mutual authentication, session key establishment, temporary identity updates, and synchronization recovery.

The implementation is developed in Python and provides a graphical interface for observing protocol operations and testing authentication scenarios. Its modular architecture separates the Registration Authority (RA), Fog Nodes, and WBAN Devices, with protocol messages serialized and parsed between entities to simulate message exchange.

---

## Abstract

Wireless Body Area Networks (WBANs) play a critical role in continuous health monitoring and therefore require authentication mechanisms that are both lightweight and secure. However, the constrained computational and energy resources of WBAN devices make it challenging to achieve strong security without introducing excessive overhead.

In this work, we conduct a detailed cryptanalysis of a lightweight authentication scheme proposed by Ali et al. and demonstrate that it suffers from two critical vulnerabilities: **traceability** and **session key disclosure**, both exploitable through passive eavesdropping on only two consecutive authentication sessions.

To address these weaknesses, we introduce **RMLA**, a strengthened lightweight mutual authentication protocol that employs non-invertible temporary identity updates, enhanced randomness protection, and a resilient session key derivation mechanism. The proposed protocol is designed to resist impersonation, replay, desynchronization, and session key disclosure attacks.

To evaluate its practical feasibility, we developed **RMLA-Lab**, an executable Python-based implementation that demonstrates the complete registration and authentication workflow. The implementation includes separate RA, Fog, and Device components, SQLite-backed storage, ECC-based key agreement using NIST P-256, SHA-256 hashing, and a graphical interface for protocol visualization and testing.

An execution-time benchmark was conducted using 1,000 authentication sessions following 20 warm-up sessions. The implementation achieved an average authentication execution time of **0.350377 ms**, with a standard deviation of **0.040881 ms**. All 1,000 measured sessions completed successfully, including session key agreement and credential synchronization. These results demonstrate the low local execution overhead of the prototype, although they do not represent real-world network latency or deployment-level performance.

At the protocol-analysis level, RMLA requires **20 hash computations** and **1,536 transmitted bits**, according to the stated protocol cost analysis.

---

## Key Features

- Lightweight mutual authentication for WBAN environments.
- ECC-based ephemeral key agreement using NIST P-256.
- SHA-256-based authentication and credential update operations.
- Secure registration of Fog Nodes and WBAN Devices.
- Temporary identity and credential evolution.
- Session key establishment using ephemeral ECDH.
- Replay protection and timestamp validation.
- Resilient credential synchronization and recovery mechanisms.
- Support for multiple Fog Nodes and multiple WBAN Devices.
- Serialized protocol messages between separate entities.
- SQLite-backed storage.
- Tkinter-based graphical user interface.
- Authentication failure and message-loss simulation.
- Automated protocol self-tests.
- Execution-time benchmarking.

---

## Laboratory Architecture

The laboratory consists of three main protocol entities:

### 1. Registration Authority (RA)

The RA is responsible for:

- System initialization and public parameter configuration.
- Generation and secure management of the master secret.
- Registration of Fog Nodes and WBAN Devices.
- Assignment of temporary identities.
- Generation and provisioning of device-specific credentials.
- Maintaining registration information in the database.

### 2. Fog Node

The Fog Node acts as an intermediary between WBAN Devices and the RA infrastructure. Its responsibilities include:

- Receiving authentication requests from devices.
- Validating device credentials and timestamps.
- Generating authentication responses.
- Performing session key derivation.
- Maintaining current and candidate credential states.
- Verifying acknowledgments and completing credential synchronization.
- Supporting recovery when authentication messages or acknowledgments are lost.

### 3. WBAN Device

The WBAN Device represents a resource-constrained medical monitoring device. Its responsibilities include:

- Generating authentication requests.
- Maintaining temporary identity and credential information.
- Performing ephemeral ECC key agreement.
- Verifying Fog Node authentication responses.
- Establishing the shared session key.
- Updating temporary identities and credentials.
- Sending acknowledgments to complete synchronization.

---

## Cryptographic Backend

The implementation uses the following cryptographic components:

| Component | Implementation |
|---|---|
| Hash function | SHA-256 |
| ECC curve | NIST P-256 (SECP256R1) |
| Key agreement | Elliptic Curve Diffie–Hellman (ECDH) |
| Random number generation | Python `secrets` module |
| Credential masking | XOR-based operations |
| Message encoding | Length-prefixed hash input encoding |
| Message serialization | JSON-based serialization |

The implementation uses length-prefixed encoding for hash inputs to avoid ambiguity when combining multiple input values.

---

## Storage Layer

RMLA-Lab uses SQLite for persistent storage of protocol information, including:

- RA system configuration and master secret.
- Registered Fog Node information.
- Registered WBAN Device information.
- Temporary identities and device credentials.
- Current and candidate synchronization states.
- Protocol-related configuration parameters.

The laboratory uses separate database tables and entity-specific classes to maintain separation between the RA, Fog, and Device components.

---

## Graphical User Interface

The Tkinter-based GUI provides an interactive environment for demonstrating the protocol.

The interface supports:

- System initialization.
- Fog Node and Device registration.
- Authentication session execution.
- Step-by-step protocol message visualization.
- Observation of exchanged authentication messages.
- Session key agreement verification.
- Temporary identity and credential updates.
- Authentication failure and synchronization scenarios.
- Exporting laboratory logs.

The GUI is intended for educational, experimental, and research purposes.

---

## Security and Recovery Testing

The laboratory supports testing of several protocol scenarios, including:

- Normal authentication and successful key agreement.
- Replayed authentication requests.
- Tampered authentication messages.
- Stale timestamp rejection.
- Lost authentication responses.
- Lost acknowledgment messages.
- Credential synchronization recovery.
- Multiple devices connected to a Fog Node.
- Rejection of retired temporary identities.

An automated self-test suite is also provided to validate important protocol execution paths.

---

## Performance Evaluation

### Execution-Time Benchmark

The execution-time benchmark was performed using:

- 20 warm-up authentication sessions.
- 1,000 measured authentication sessions.
- NIST P-256 and SHA-256.
- In-memory SQLite database.
- GUI and logging overhead excluded.

| Metric | Result |
|---|---:|
| System initialization | 0.308000 ms |
| Fog registration | 0.062900 ms |
| Device registration | 0.069600 ms |
| Total registration | 0.132500 ms |
| Mean authentication time | **0.350377 ms** |
| Median authentication time | 0.348700 ms |
| Minimum authentication time | 0.294600 ms |
| Maximum authentication time | 1.107800 ms |
| Standard deviation | 0.040881 ms |
| Complete workflow | **0.482877 ms** |
| Successful authentication sessions | 1,000 / 1,000 |

All 1,000 measured sessions completed successfully. The returned results confirmed successful device and Fog authentication, matching session keys, acknowledgment processing, and credential synchronization.

**Measurement scope:** Authentication execution time represents local prototype execution, including protocol processing and simulated message serialization/parsing. It excludes actual network transmission delays, wireless communication overhead, and deployment-specific hardware effects. Therefore, these results should not be interpreted as end-to-end WBAN communication latency.

### Protocol-Level Cost

According to the protocol cost analysis:

- Hash computations: 20
- Communication overhead: 1,536 bits

These are protocol-level cost figures and are distinct from the execution-time measurements reported above.

---

## Requirements

- Python 3.8 or later
- `cryptography`
- Tkinter (usually included with standard Python installations)
- SQLite (included with Python)

Install the required external dependency:

```bash
pip install cryptography
```

---

## Running the Laboratory

Navigate to the implementation directory:

```bash
cd implementation
```

Run the graphical laboratory:

```bash
python rmla_lab.py
```

Run the automated self-test suite:

```bash
python rmla_lab.py --selftest
```

---

## Project Structure

A typical project layout is:

```text
RMLA-Lab/
│
├── implementation/
│   ├── rmla_lab.py
│   ├── rmla_benchmark.py
│   └── RMLA_Laboratory_v2.db
│
└── README.md
```

The SQLite database is created and managed by the laboratory implementation. The benchmark script is used to measure local registration and authentication execution times.

---

## Scope and Limitations

RMLA-Lab is a research and experimental prototype intended to demonstrate the proposed protocol and evaluate its local implementation performance.

The laboratory simulates message exchange through serialization and parsing; it does not establish actual wireless or network connections between physically separate devices. Similarly, secure provisioning and communication channels are represented within the local prototype rather than implemented as a complete deployed infrastructure.

Consequently, the reported execution-time results should be interpreted as implementation-level measurements, not as a complete evaluation of real-world WBAN performance.

The prototype is not intended to be deployed directly in clinical or production environments without additional implementation, security, and hardware-level evaluation.

---

## License and Citation

If you use RMLA-Lab in academic research, please cite the associated RMLA protocol publication.

**Project:** RMLA-Lab  
**Protocol:** RMLA – Lightweight Mutual Authentication Protocol for WBANs  
**Authors:** Masoumeh Safkhani, Mohammad Reza Servati, Hadis Shahbazi
