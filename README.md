# 🛡️ Zero Trust Endpoint Platform

A **Zero Trust security prototype** that enforces application allowlisting, detects suspicious process behavior, identifies **Living-off-the-Land (LoLBin) attacks**, calculates **risk scores**, maps detections to the **MITRE ATT&CK framework**, and provides actionable security insights.

---

# 📖 Project Overview

**TrustME** is a prototype **Endpoint Detection Platform** designed to demonstrate how modern **Endpoint Detection and Response (EDR)** systems operate.

The system collects telemetry from endpoints, analyzes behavioral patterns using **Sigma detection rules**, and generates alerts when suspicious activity is detected.

The project focuses on **behavior-based detection techniques** inspired by modern security products.

---

# ⚙️ Core Components

### 🖥️ Endpoint Telemetry Agent

A lightweight Python agent collects process execution data using **psutil**.

Captured telemetry includes:

- Process name
- Parent process
- Command line arguments
- Process hash (SHA256)
- Execution path classification
- Username
- Living-off-the-Land binary (LoLBin) identification
- Timestamp

---

### 🌐 Centralized Telemetry Server

A **FastAPI-based ingestion server** receives telemetry from endpoint agents and stores it in **PostgreSQL**.

The backend exposes APIs for:

- Telemetry ingestion
- Event storage
- Alert generation
- Alert retrieval

---

### 🔎 Sigma-Based Detection Engine

The detection engine evaluates incoming telemetry against **Sigma rules** written in YAML format.

Sigma enables **portable detection logic** across different security platforms.

Current detections include:

- 📄 Office spawning PowerShell
- 🧬 Encoded PowerShell execution
- 🌐 Browser spawning shell interpreters
- 📂 Execution from temporary directories
- ⚔️ Living-off-the-Land binary (LoLBin) execution

---

# 🧱 Architecture

Endpoint Agent
->
Telemetry Collection
->
FastAPI Ingestion Server
->
PostgreSQL Event Storage
->
Sigma Detection Engine
->
Alert Generation


# ⚡Configuration

1. Start PostgreSQL and create the database:

2. Run the FastAPI server:
uvicorn server:app --host 0.0.0.0 --port PORT --reload

3. Run the Endpoint Agent
python monitor.py

 4.Test with custom payloads

5.Check for Alerts
curl http[:]//localhost[:]PORT/alerts


