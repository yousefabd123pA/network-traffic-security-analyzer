# Network Security Analyzer

A Python-based network security analysis tool designed to analyze PCAP traffic, detect suspicious network activities, and generate SOC-style security reports.

## Overview

Network Security Analyzer processes captured network traffic through a modular security analysis pipeline:

**Parser → Tracker → Detection Rules → Detection Engine → Evidence → Alert → Report**

The project combines packet analysis, behavioral tracking, rule-based detection, evidence evaluation, alert management, and security reporting in a single application.

## Features

* PCAP file analysis
* Packet parsing using Scapy
* Network traffic tracking
* Time-window based analysis
* Rule-based detection
* Detection Engine for correlating detection results
* Evidence collection and evaluation
* Alert management
* Security logging
* SOC-style report generation
* Web-based GUI
* Simulation Mode for testing detection logic

## Attack Detection

### HTTP Flood

Analyzes HTTP request behavior using:

* Request count
* Request rate
* Average inter-arrival time
* Sustained activity duration
* Detection windows

The detection engine correlates multiple suspicious windows and assigns different severity levels based on the observed activity.

### Port Scan

Detects suspicious TCP scanning behavior based on packet patterns and connection attempts.

Supported scan types:

* SYN Scan
* Connect Scan
* ACK Scan

The analyzer examines TCP flags, destination ports, connection behavior, and scanning patterns to classify the activity.

### ICMP Flood

Analyzes ICMP traffic to identify abnormal packet rates and sustained ICMP activity.

## Detection Pipeline

PCAP File
    │
    ▼
  Parser
    │
    ▼
  Tracker
    │
    ▼
Detection Rules
    │
    ▼
Detection Engine
    │
    ▼
Evidence Collector
    │
    ▼
Alert Manager
    │
    ▼
Report Generator


## Core Components

| Component          | Purpose                                              |
| ------------------ | ---------------------------------------------------- |
| Parser             | Extracts and identifies network packets              |
| Tracker            | Groups and tracks traffic behavior over time         |
| Detection Rules    | Defines conditions for suspicious activities         |
| Detection Engine   | Correlates detection results and determines severity |
| Evidence Collector | Evaluates supporting traffic evidence                |
| Alert Manager      | Handles generated security alerts                    |
| Log Manager        | Records analysis and detection events                |
| Report Generator   | Produces SOC-style security reports                  |
| GUI                | Provides the interface for analysis and results      |

## Analysis Modes

### PCAP Analysis

Analyze previously captured network traffic and detect suspicious activities.

### Simulation Mode

Used to test the detection pipeline with controlled scenarios:

* Normal Traffic
* HTTP Flood
* Port Scan
* ICMP Flood

## Severity & Evidence

Detected activities are evaluated using:

* Detection windows
* Attack duration
* Traffic behavior
* Packet characteristics
* Detection consistency

Alerts can be classified with different severity levels such as:

**Medium → High → Critical**

Evidence is also categorized according to its strength.

## SOC Reporting

Generated reports include information such as:

* Source IP
* Destination IP
* Attack type
* Detection type
* Detection window
* Severity
* Evidence
* Observed traffic behavior
* SOC analysis
* Security assessment

## Technologies

* **Python**
* **Scapy**
* **Flask**
* **HTML**
* **CSS**
* **JavaScript**
* **TCP/IP**
* **PCAP**
* **Wireshark**

## Project Structure

Network Security Analyzer/
│
├── parser.py
├── tracker.py
├── engine.py
├── alert_manager.py
├── log_manager.py
├── report_generator.py
│
├── http_flood.py
├── port_scan.py
├── icmp_flood.py
│
├── GUI.html
├── requirements.txt
└── README.md

## Installation

git clone https://github.com/yousef-abdelkader/Network-Security-Analyzer.git
cd Network-Security-Analyzer
pip install -r requirements.txt

## Usage

python appi.py

Upload a PCAP file through the application or use Simulation Mode to test the detection modules.

## Project Goal

The project demonstrates practical cybersecurity concepts including:

* Network Traffic Analysis
* Packet Inspection
* TCP Flag Analysis
* Behavioral Tracking
* Rule-Based Detection
* Attack Detection
* Evidence Analysis
* Alert Management
* SOC-Style Incident Reporting

## Author

**Yousef Abdelkader Kamel**

Cybersecurity & Network Security Student
