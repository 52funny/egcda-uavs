# An Efficient Group Communication Scheme with Delegated Authentication for UAV Swarms

## Overview
This repository contains the implementation of the work, a secure and efficient group communication framework designed for **UAV swarms**.
The framework is implemented in Rust to leverage the language’s **memory safety**, **high performance**, and **concurrency** advantages. It provides a distributed architecture integrating: **Ground Station**, **UAV Nodes**, and **Trust Authority**, with shared libraries `rpc` and `utils` for communication and utility functions.


## System Architecture
The project is organized as a **Rust Workspace** comprising the following core modules:

| Module  | Description                                                                                                          |
| ------- | -------------------------------------------------------------------------------------------------------------------- |
| `gs`    | **Ground Station** – Authenticates UAVs, conducts group key agreement                                                |
| `uav`   | **UAV Node** – Executes assigned missions,  and participates in secure group communication                           |
| `ta`    | **Trust Authority** – Registers all system entities, authenticates the Ground Station                                |
| `bm`    | **Benchmark Module** – Measures system performance and evaluates algorithm efficiency                                |
| `rpc`   | **Remote Procedure Call Layer** – Handles structured inter-module communication                                      |
| `utils` | **Utility Library** – Provides cryptographic primitives, random number generation, and parallel processing utilities |



## Build & Run
1. Install the Rust toolchain (recommended via `rustup`):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Clone the repository and navigate to the project root:
    ```bash
    git clone https://github.com/52funny/egcda-uavs.git
    cd egcda-uavs
    ```
3. Build the project:
   ```bash
   cargo build --release
   make cp
   ``` 
4. Run a specific module (e.g., trust authority):
   ```bash
   cd bin
   ./ta
   ```



## Contribution Guidelines

We welcome contributions from the community! Please follow the steps below:

1. Fork the repository to your personal account.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
    ```
3. Commit your code and create a Pull Request.


## Acknowledgements

This project builds upon the efforts of the open-source community. We gratefully acknowledge the use of the following libraries and tools:

* [Tokio](https://github.com/tokio-rs/tokio): Asynchronous runtime for building reliable and concurrent network applications.
* [Serde](https://github.com/serde-rs/serde): Framework for efficient serialization and deserialization of Rust data structures.
* [Rug](https://github.com/mirkosertic/rug): Multiple-precision arithmetic and number theory library with Rust bindings.
* [BLAKE2](https://github.com/RustCrypto/hashes): Cryptographic hash function implementation.
* [AES-GCM](https://github.com/RustCrypto/AEADs): Authenticated encryption with associated data (AEAD) using AES-GCM.
* [TarPC](https://github.com/google/tarpc): RPC framework for Rust.
* [Blstrs Plus](https://github.com/filecoin-project/blstrs): BLS12-381 pairing-friendly elliptic curve library with serialization support.
* [Rayon](https://github.com/rayon-rs/rayon): Data parallelism library for Rust.

---

## Contact Us

If you have any questions, suggestions, or encounter issues, please reach out through:

* **Project Issue Page**: [GitHub Repo Issues](https://github.com/52funny/egcda-uavs/issues)