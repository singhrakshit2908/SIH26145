# 🛡️ SIH26145 — AI-Based Cyber Threat Detection

> **AI-powered passive threat detection for unidirectional IP traffic in critical infrastructure networks.**


## 📌 Overview

Critical infrastructure such as **power grids, transportation systems, telecommunications, and defence networks** requires extremely strict network isolation.

Our solution is designed for environments where network traffic is copied through a **unidirectional monitoring path** into a separate security environment.

The monitoring system can **observe and analyse traffic**, but it cannot send packets, establish connections, or take action against the production network.

The prototype uses **AI/ML-based traffic analysis** to identify suspicious behaviour and generate security alerts with supporting evidence.

### Core Principle

```text
┌──────────────────────────┐
│   Production Network     │
│                          │
│  Critical Infrastructure │
└────────────┬─────────────┘
             │
             │ One-Way Traffic Copy
             ▼
┌──────────────────────────┐
│   Passive Ingestion      │
│  PCAP / Flow Data / Logs │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│    Feature Extraction    │
│ Flow • DNS • TLS • Stats │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│       AI / ML Engine     │
│ Classification + Anomaly │
│ Detection                │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│    Threat Correlation    │
│ Alerts + Evidence        │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Security Dashboard     │
│ Threats • Alerts • Stats │
└──────────────────────────┘
