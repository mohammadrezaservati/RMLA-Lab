# RMLA-Lab: A Lightweight Mutual Authentication Protocol for WBANs

## Authors
Masoumeh Safkhani, Mohammad Reza Servati, Hadis Shahbazi

---

## Overview
**RMLA-Lab** is an interactive laboratory implementation of the **RMLA lightweight registration and mutual authentication protocol**, designed for **Wireless Body Area Networks (WBANs)** operating in **WBAN–Fog–Registration Authority (RA)** environments.

This project provides a complete, end-to-end demonstration of how secure device registration, temporary identity updating, mutual authentication, and session key establishment can be achieved in resource-constrained medical and cyber-physical systems.

---

## Abstract
Wireless Body Area Networks (WBANs) play a critical role in continuous health monitoring and therefore require authentication mechanisms that are both lightweight and highly secure. However, the constrained computational and energy resources of WBAN devices often lead to protocol designs that unintentionally leak sensitive information.

In this work, we conduct a detailed cryptanalysis of a lightweight authentication scheme proposed by Ali et al. and demonstrate that it suffers from two critical vulnerabilities: **traceability** and **session key disclosure**, both exploitable through passive eavesdropping on only two consecutive authentication sessions.

To address these weaknesses, we introduce **RMLA**, a strengthened lightweight mutual authentication protocol that employs non-invertible temporary identity updates, enhanced randomness protection, and a resilient session key derivation mechanism. The proposed protocol resists impersonation, replay, desynchronization, and key disclosure attacks.

To demonstrate practical feasibility, an executable implementation of RMLA is developed using a Python-based graphical environment, enabling end-to-end testing of registration, authentication, key agreement, and identity update procedures under realistic WBAN–fog interaction settings. Performance evaluation shows that RMLA maintains low computational and communication overhead, requiring only **20 hash computations** and **1536 transmitted bits**, making it suitable for next-generation WBAN deployments.

---

## Key Features
- Lightweight mutual authentication for WBAN environments
- Secure registration and temporary identity update mechanisms
- Robust session key establishment resistant to passive attacks
- Python-based executable implementation
- Graphical user interface for step-by-step protocol visualization
- SQLite-backed storage for identities, keys, and protocol parameters

---

## Laboratory Components
- **Cryptographic Backend**  
  Implements registration, identity updating, authentication, and session key derivation using SHA-256 hashing, random nonce generation, XOR masking, and secure key derivation.

- **Storage Layer**  
  SQLite-based database for managing RA master keys, fog node identities, and WBAN device parameters.

- **Graphical User Interface**  
  A Tkinter-based GUI allowing users to observe protocol phases, intermediate computations, exchanged messages, and the final session key.

---

## Requirements
- Python 3.8 or later
- Standard Python libraries: `hashlib`, `secrets`, `sqlite3`, `tkinter`

---

## Running the Laboratory
To execute the RMLA laboratory environment:

```bash
cd implementation
python rmla_gui.py
