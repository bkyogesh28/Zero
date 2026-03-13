# zero-trust-endpoint-platform
A Zero-trust model application that enforces application allowlisting, alerts about suspicious parent-child process, finding LoLBin attacks, calculates risk score, map to MITRE ATT&CK framework and give insightfull data in the dashboard


Project Description

Zero is a prototype endpoint security platform designed to demonstrate how modern endpoint detection and response (EDR) systems collect telemetry, analyze behavior, and generate security alerts.

The platform consists of a lightweight endpoint agent, a centralized telemetry server, a Sigma-based detection engine, and a PostgreSQL event store. The system collects process execution metadata from endpoints, streams telemetry to a backend API, evaluates events against behavioral detection rules, and produces alerts for suspicious activity.

The project focuses on behavior-based detection techniques inspired by real-world endpoint security solutions.

Key Features
Endpoint Telemetry Agent

A lightweight Python agent collects process execution data from endpoints using psutil.

Captured telemetry includes:
Process name
Parent process
Command line arguments
Process hash (SHA256)
Execution path classification
Username
LOLBin identification
Timestamp

Centralized Telemetry Server

A FastAPI-based ingestion server receives telemetry from agents and stores events in PostgreSQL.

The backend provides APIs for:
Telemetry ingestion
Event storage
Alert generation
Alert retrieval


Sigma-Based Detection Engine

The platform uses Sigma rules to detect suspicious behavior patterns.

Sigma rules allow detections to be expressed in a standardized YAML format, making the detection engine modular and extensible.

Current detections include:
Office spawning PowerShell
Encoded PowerShell execution
Browser spawning shell interpreters
Execution from temporary directories
Living-Off-The-Land binary (LOLBin) execution


Architecture

Endpoint Agent
     ↓
Telemetry Collection
     ↓
FastAPI Ingestion Server
     ↓
PostgreSQL Event Storage
     ↓
Sigma Detection Engine
     ↓
Alert Generation
