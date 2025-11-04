# 🛡️ Cybersecurity Portfolio — Oladotun

Welcome to my cybersecurity portfolio!  
This repository documents my **hands-on SOC lab projects**, **SIEM configurations**, and **security monitoring experiments** using open-source tools like **Wazuh**, **Suricata**, and **Kali Linux**.  
It serves as a collection of my practical learning journey toward mastering **threat detection, log analysis, and incident response**.


---

## 👨‍💻 About Me
I’m a cybersecurity enthusiast passionate about **defensive security**, **SIEM engineering**, and **blue team operations**.  
I build and manage **virtual SOC environments** that simulate real-world monitoring using **Wazuh, Suricata, and Windows agents**.

**Current Focus:**  
`SOC Lab Setup | Wazuh | Suricata | Log Analysis | Active Directory Security`

**Goal:**  
To become proficient in **SOC analysis, incident response, and security automation** using open-source tools.

---

## 🧰 Skills / Tools & Associated project

| **skill**                        | Tools                                                         | Associated project
|----------------------------------|---------------------------------------------------------------|----------------------------------|
| **SIEM implementation and log Analysis**            | Wazuh (Manager & Agent), Elasticsearch, Kibana |              |
| **Network Security**             | Suricata, Zeek (learning), Wireshark, TCPdump |               |
| **Operating Systems**            | Kali Linux, Ubuntu Server, Windows 10/11 |                    |
| **Incident Response**            | Sysmon, OSINT, YARA, Sigma Rules |                            |
| **Automation & Scripting**       | Bash, Python, PowerShell |                                    |
| **Threat Intelligence**          | VirusTotal API, AbuseIPDB, MISP (learning)                    |

---

## 🧩 Featured Projects

### 🔹 [Wazuh + Suricata Integration Lab](https://github.com/yourusername/wazuh-suricata-lab)
**Goal:** Combine Wazuh and Suricata to detect and visualize network threats.  
**Setup Includes:**
- Wazuh Manager 4.13 (OVA Appliance)
- Suricata on Kali Linux (EVE JSON enabled)
- Custom Wazuh decoders and rules for Suricata alerts
- GeoIP and AbuseIPDB threat enrichment in Kibana

**Skills Demonstrated:**  
SIEM configuration, log ingestion, rule tuning, network defense.

---

### 🔹 [Windows Endpoint Monitoring with Wazuh Agent](https://github.com/yourusername/wazuh-windows-agent)
**Goal:** Monitor Windows system events for suspicious activity.  
**Setup Includes:**
- Wazuh agent installed on Windows 10/11
- Sysmon integration for detailed event capture
- Custom Wazuh rules to detect PowerShell abuse and privilege escalation
- Event correlation in Wazuh Dashboard

**Skills Demonstrated:**  
Windows event analysis, Sysmon configuration, rule customization.

---

### 🔹 [Kali Linux Threat Simulation Lab](https://github.com/yourusername/kali-threat-lab)
**Goal:** Generate test attacks to validate Wazuh + Suricata detection accuracy.  
**Tools Used:** Metasploit, Nmap, Hydra, Nikto, and custom Bash scripts.  
**Outcome:** 
Validated alert generation for port scans, brute-force, and web exploitation attempts.

**Skills Demonstrated:**  
Adversary emulation, SOC alert testing, and detection engineering.

---

## Certifications & Training


- **TryHackMe: SOC Level 1** *(in progress)*  
- **Google Cybersecurity Professional Certificate** *(ongoing)*  
- **CompTIA Security+ (planned)**  
- **Wazuh Advanced Rule Customization Lab** *(self-paced)*  

---

## Future Projects
- Active Directory domain controller integration with Wazuh  
- Automating alert triage with Python scripts  
- Creating MITRE ATT&CK–aligned dashboards  
- Implementing honeypot logs into Wazuh for threat hunting  
