RMLA-Lab is an interactive laboratory implementation of a lightweight
Registration and Mutual Authentication (RMLA) protocol designed for
IoT–Fog–RA environments. This project provides a complete, end-to-end
demonstration of how secure device initialization, identity updating,
session key establishment, and mutual authentication are performed in a
lightweight cyber-physical system.

The laboratory includes:

- A cryptographic backend implementing registration, identity management,
  and mutual authentication steps.
- A SQLite-based storage layer for maintaining RA master keys, fog node
  identities, and device parameters.
- A detailed implementation of protocol primitives such as SHA-256 hashing,
  random nonce generation, XOR masking, and session key derivation.
- A Tkinter-based graphical interface that allows users to visually observe
  each phase of the protocol, step-by-step logs, and the resulting session key.

This project is intended for researchers, students, and practitioners in
security protocol design who want to study and analyze lightweight
authentication in practice. It can also be used as an educational tool in
security courses, IoT laboratories, and academic demonstrations involving
identity-based authentication, fog-assisted security, and secure key
agreement mechanisms.
