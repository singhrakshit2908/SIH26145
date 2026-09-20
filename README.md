# 🛡️ SIH26145 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic

<p align="center">

### AI-Powered Passive Network Threat Detection for Critical Infrastructure

</p>

---

## 📌 Overview

**SIH26145** is an AI/ML-based cybersecurity solution designed to detect and analyse cyber threats in **unidirectional IP traffic environments**.

Critical infrastructure such as:

- ⚡ Power grids
- 🚆 Transportation systems
- 📡 Telecommunications
- 🛡️ Defence infrastructure
- 🏭 Industrial and OT environments

often require strict network isolation.

In a unidirectional architecture, traffic from a production environment can be copied into a separate monitoring environment for security analysis, while the monitoring environment cannot send traffic back into the production network.

This creates an important security constraint:

> **The monitoring system must detect threats using only passively collected network information.**

The proposed system addresses this challenge by combining **network traffic analysis, feature engineering, machine learning, anomaly detection, rule-based detection, and threat correlation** to identify suspicious activity and present the results through a visualisation dashboard.

---

# 🎯 Problem Statement

### AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Traditional security monitoring systems may rely on active communication with monitored devices.

However, in critical infrastructure environments, active interaction can be undesirable or prohibited because the monitoring system must not:

- Establish connections with production devices.
- Send packets back into the production network.
- Perform active network scans.
- Inject test traffic.
- Modify production traffic.
- Automatically execute defensive actions inside the protected network.

The monitoring system therefore needs to operate using **passively collected network information**.

The objective of this project is to build an AI/ML pipeline capable of:

1. Ingesting one-way IP traffic or previously captured network data.
2. Extracting meaningful network features.
3. Detecting abnormal network behaviour.
4. Classifying known cyber threats.
5. Identifying previously unseen anomalies.
6. Correlating multiple security indicators.
7. Generating labelled security alerts.
8. Providing confidence and supporting evidence.
9. Visualising the results through a security dashboard.

---

# 💡 Solution

The system follows a **passive detection architecture**.

The network traffic is copied from the production environment into a dedicated monitoring environment.

The monitoring pipeline then performs:

```text
Network Traffic
      │
      ▼
┌─────────────────────┐
│ Passive Ingestion   │
│                     │
│ PCAP / Flow / Logs  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Feature Engineering │
│                     │
│ Flow Statistics     │
│ DNS                 │
│ TLS / QUIC          │
│ Timing              │
│ Entropy             │
│ Packet Statistics   │
└──────────┬──────────┘
           │
           ▼
┌──────────────────────────┐
│ Detection Layer          │
│                          │
│ Rule-Based Detection     │
│ ML Classification        │
│ Anomaly Detection        │
└──────────┬───────────────┘
           │
           ▼
┌─────────────────────┐
│ Threat Correlation  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Security Dashboard  │
│                     │
│ Alerts              │
│ Threats             │
│ Statistics          │
│ Evidence            │
└─────────────────────┘
