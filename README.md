
# Cybersecurity Internship Projects

## Overview

This repository contains cybersecurity projects completed as part of the **CodeAlpha Cybersecurity Internship Program**. The projects focus on network monitoring, vulnerability assessment, secure coding practices, and intrusion detection.

The objective of these projects is to develop practical cybersecurity skills through real-world security scenarios and hands-on implementation.

---

#  Project Structure

text
├── task1_network_sniffer.py
├── task3_vulnerable_app.py
├── task4_nids.py
|──README.md

--

# 🛡️ Task 1: Basic Network Sniffer

## Objective

Develop a network packet sniffer capable of capturing and analyzing network traffic in real time.

## Description

This tool captures packets from a selected network interface and displays detailed information including:

- Source IP Address
- Destination IP Address
- Source and Destination Ports
- MAC Addresses
- Protocol Information
- DNS Queries and Responses
- HTTP Requests and Responses
- Packet Payload Data
- Packet Size

## Features

- Real-time packet capture
- Protocol detection (TCP, UDP, ICMP, ARP, DNS, HTTP)
- Packet payload analysis
- Network traffic statistics
- Interface selection support
- Packet filtering support
- Colorized terminal output

## Technologies Used

- Python
- Scapy

## Learning Outcomes

- Network packet analysis
- Protocol inspection
- Traffic monitoring
- Network troubleshooting

---

# 🔍 Task 3: Secure Coding Review

## Objective

Perform a security review of a vulnerable web application and identify common security flaws.

## Description

A Flask-based web application was intentionally designed with multiple security vulnerabilities to demonstrate common web security risks and secure coding practices.

## Vulnerabilities Identified

| ID | Vulnerability |
|----|--------------|
| V-01 | SQL Injection |
| V-02 | Stored Cross-Site Scripting (XSS) |
| V-03 | Hardcoded Credentials |
| V-04 | Weak Password Storage (MD5) |
| V-05 | Path Traversal |
| V-06 | Broken Access Control |
| V-07 | Insecure Direct Object Reference (IDOR) |
| V-08 | Sensitive Information Disclosure |
| V-09 | Missing CSRF Protection |
| V-10 | Insecure Session Cookies |

## Technologies Used

- Python
- Flask
- SQLite

## Learning Outcomes

- Vulnerability Assessment
- Secure Coding Practices
- Risk Analysis
- Web Application Security

---

# 🚨 Task 4: Network Intrusion Detection System (NIDS)

## Objective

Design and implement a Network Intrusion Detection System to detect suspicious network activities.

## Description

The NIDS continuously monitors network traffic, analyzes packets against predefined detection rules, generates alerts, and displays them through a real-time dashboard.

## Detection Rules

| Rule ID | Detection |
|----------|------------|
| RULE-01 | Port Scan Detection |
| RULE-02 | SYN Flood Detection |
| RULE-03 | ICMP Sweep Detection |
| RULE-04 | DNS Tunneling Detection |
| RULE-05 | SSH Brute Force Detection |
| RULE-06 | HTTP Brute Force Detection |
| RULE-07 | UDP Flood Detection |
| RULE-08 | Path Traversal Detection |
| RULE-09 | NULL Scan Detection |
| RULE-10 | XMAS Scan Detection |

## Features

- Real-time traffic monitoring
- Threat detection engine
- Alert management system
- JSON alert logging
- Web-based dashboard
- Severity classification
- Automated response actions
- IP blocking support

## Technologies Used

- Python
- Scapy
- Flask
- JSON
- Multithreading

## Learning Outcomes

- Intrusion Detection Techniques
- Security Monitoring
- Threat Analysis
- Incident Response

---

# ⚙️ Installation

## Clone Repository

bash
git clone https://github.com/yourusername/codealpha-cybersecurity.git
cd codealpha-cybersecurity


## Install Dependencies

bash
pip install scapy flask

---

# ▶️ Usage

## Task 1 - Network Sniffer

bash
sudo python3 task1_network_sniffer.py

Example:

bash
sudo python3 task1_network_sniffer.py -i wlan0


---

## Task 3 - Vulnerable Application

bash
python3 task3_vulnerable_app.py


Open:

text
http://localhost:5000


---

## Task 4 - Network Intrusion Detection System

bash
sudo python3 task4_nids.py


Dashboard:

text
http://localhost:8080


---

# 🛠 Skills Demonstrated

- Network Security
- Packet Analysis
- Secure Coding
- Vulnerability Assessment
- Threat Detection
- Incident Response
- Python Programming
- Flask Development

---

# 🎯 Internship Outcome

Through these projects, practical experience was gained in:

- Capturing and analyzing network traffic
- Identifying web application vulnerabilities
- Detecting malicious network activities
- Monitoring security events in real time
- Applying cybersecurity best practices

These projects demonstrate foundational cybersecurity skills relevant to Security Analyst, SOC Analyst, Penetration Tester, and Network Security roles.

---

# 👨‍💻 Author

**Mohamed Unaiz A**

**Role:** CodeAlpha Cybersecurity Intern

**Domain:** Cybersecurity

