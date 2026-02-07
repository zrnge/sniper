# SNIPER

**Simple Network Input Payload ExploRer**

Owner: https://github.com/zrnge  
Status: Production-ready  
Use case: Authorized HTTP parameter fuzzing and anomaly detection

---

## Overview

**SNIPER** is a lightweight, deterministic HTTP fuzzing tool designed for
**security testing**, **QA**, and **automation pipelines**.

It supports:

- Multi-parameter fuzzing (e.g. `username` + `password`)
- Intruder-style attack modes (Pitchfork / Cluster Bomb)
- Grep-style response filtering (status code, response length)
- CI/CD-friendly output
- Safe throttling and timeout controls

SNIPER focuses on **signal over noise** and is built to scale cleanly in
production environments.

---

## Features

- Multi-parameter fuzzing (any number of parameters)
- Payload iteration modes:
  - **Pitchfork** (parallel iteration)
  - **Cluster Bomb** (Cartesian product)
- Response filtering:
  - HTTP status code matching
  - Response length matching
  - Inverted matching (anomaly detection)
- GET and POST support
- Custom headers (auth tokens, cookies, etc.)
- Deterministic, scriptable output
- No external dependencies beyond `requests`

---

## Installation

### Requirements

- Python 3.8+
- `requests` library

```bash
pip install requests
