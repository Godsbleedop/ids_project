# Intelligent Intrusion Detection System (IDS) - Project Explanation

## 1. System Overview
This project is a **Distributed, Hybrid Intrusion Detection System**.
- **Distributed**: It can monitor remote machines using a lightweight agent (`remote_agent.py`) that sends traffic data to a central server (`app.py`).
- **Hybrid**: It combines **Rule-Based Detection** (for known, specific signatures) with **Machine Learning** (for detecting complex or evolving attack patterns).

## 2. The Dataset (How it learns)
**Does it use a dataset? YES.**

Instead of using outdated public datasets (like KDD99 which is from 1999), this system uses a **Custom Synthetic Modern Dataset**.

### How the Dataset is Created (`generate_dataset.py`)
We wrote a script that acts as a "Network Simulator". It generates thousands of network packets to create a training file (`data/modern_dataset.csv`).
1.  **Normal Traffic Generation**: The script simulates normal user behavior, such as browsing the web (HTTP GET requests), logging in validly, and requesting images.
2.  **Attack Traffic Generation**: The script simulates modern attacks using real attack payloads:
    -   **SQL Injection**: Injecting malicious SQL commands (e.g., `' OR '1'='1`).
    -   **XSS (Cross-Site Scripting)**: Injecting malicious JavaScript (e.g., `<script>alert(1)</script>`).
    -   **Command Injection**: Trying to execute shell commands (e.g., `; cat /etc/passwd`).

### Why this is better
Standard datasets often lack the specific *payload* content (the actual text inside the packet) that reveals modern web attacks. By generating our own data, we ensure the model learns to recognize these specific malicious text patterns.

## 3. How Detection Works (The Pipeline)

### Step 1: Packet Capture & Feature Extraction
When a packet arrives (either live or from the remote agent), the system analyzes it using `packet_capture.py`. It converts the raw binary packet into a set of **Numerical Features**:
-   **Traffic Features**: How many packets in the last 2 seconds? (Detects Floods/DoS)
-   **Error Rates**: How many connections failed? (Detects Scanning)
-   **Payload Features (NEW)**:
    -   `payload_len`: How big is the data?
    -   `has_sql_keywords`: Does it contain words like "UNION SELECT"? (1 for yes, 0 for no)
    -   `has_xss_keywords`: Does it contain "<script>"?

### Step 2: The Hybrid Detection Engine (`ids_detector.py`)
The system passes these features through two layers of checks:

1.  **Layer 1: Rule-Based (The "Speed Filter")**
    -   Checks for obvious signs like "Too many connections from one IP" (DoS) or "Scanning too many ports".
    -   If a rule is triggered, it alerts immediately. This is fast and explains *why* it's an attack.

2.  **Layer 2: Machine Learning (The "Smart Filter")**
    -   If the rules are unsure, the **Random Forest Model** analyzes the features.
    -   It compares the current packet's features against the patterns it learned from the **Synthetic Dataset**.
    -   If the model predicts "Attack" with high confidence, it raises an alert.

## 4. Summary for Lecturer
> "This system is a modern IDS that uses a **distributed agent architecture** to monitor network traffic. Unlike traditional systems that rely solely on old datasets, we implemented a **synthetic data generator** to train our Machine Learning model on **modern web attack patterns** like SQL Injection and XSS. The system extracts features from live packets—including deep payload analysis—and uses a **Random Forest classifier** to distinguish between normal user traffic and malicious attacks in real-time."
