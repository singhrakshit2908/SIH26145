# SIH26145

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**
Critical-infrastructure networks, such as power, transport, telecom, and defence systems, are monitored using a one-way connection. A copy of network traffic is sent into a separate, secure monitoring area, but nothing can be sent back to the main production network. This keeps the core network safe: even if the monitoring system is compromised, it cannot be used to attack internal systems. The monitoring area can only observe data such as packet captures, flow records, and traffic details. It cannot scan devices, send test packets, complete connections, or automatically block an attack. Its job is to detect suspicious activity, classify threats, and alert the security team for action.

The objective is to design and build an AI/ML pipeline that ingests a one-directional stream of IP traffic from simulated IP data and detects, classifies, and scores cyber-security threats in near real time, using only passively collected data. The pipeline must assume it can never re-contact the traffic's source or destination, cannot rely on completing any handshake itself, and cannot issue any action back across the ingest path. Its output is intelligence as labelled alerts, confidence scores, and supporting evidence displayed on a visualisation dashboard. The system is designed to detect the following types of threats:
		a) Volumetric / protocol DDoS.
		b) Botnet C2 beaconing.
		c) DGA domains and DNS tunnelling.
		d) Malware inside encrypted sessions.
		e) Reconnaissance and port scanning.
		f) Data exfiltration.
