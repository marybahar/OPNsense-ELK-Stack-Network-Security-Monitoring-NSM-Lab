OPNsense + ELK Stack: Network Security Monitoring (NSM) Lab
📌 Project Overview
This project demonstrates the deployment and configuration of a full-stack SIEM (Security Information and Event Management) pipeline. Using OPNsense as the core firewall and the Elastic Stack (ELK) for centralized logging, I built a system capable of detecting and visualizing real-time network threats.

The lab focuses on Log Ingestion, Data Normalization, and Threat Visualization by simulating reconnaissance attacks from a Kali Linux machine.

🏗️ Architecture & Topology
Firewall: OPNsense v25.7 (Dual-homed: WAN/LAN)

SIEM Ingestion: Logstash (UDP Port 5514)

Search Engine: Elasticsearch

Visualization: Kibana

Attack Node: Kali Linux (Nmap, Netcat)

🛠️ Configuration: The Logstash Pipeline
To ensure high-quality data for analysis, I developed a custom Logstash Dissect Filter. This filter successfully handles OPNsense CSV-style syslog headers and maps them to ECS (Elastic Common Schema) compatible fields.

opnsense.conf Snippet
Ruby
filter {
  if [type] == "syslog" {
    dissect {
      mapping => {
        "message" => "%{?f1},%{?f2},%{?f3},%{?f4},%{interface},%{reason},%{action},%{dir},%{version},%{?f10},%{?f11},%{?f12},%{?f13},%{?f14},%{?f15},%{?f16},%{protocol},%{?f18},%{src_ip},%{dest_ip},%{src_port},%{dest_port},%{?rest_of_msg}"
      }
    }
    mutate {
      convert => {
        "src_port" => "integer"
        "dest_port" => "integer"
      }
    }
  }
}
🧠 Technical Challenge: Solving Mapping Conflicts
During development, I encountered a Mapping Conflict in Kibana where dest_port was being stored as both a string and a long.

Cause: Trailing TCP flags (e.g., ,S,1024) were being appended to the port field in raw syslog data.

Solution: I implemented a "catch-all" field (%{?rest_of_msg}) in the Logstash dissect pattern to isolate the numerical port. I then performed an index deletion via the Elasticsearch API (DELETE /opnsense-logs-*) to re-index the data with clean integer types.

🕵️ Attack Simulation & Detection
To validate the pipeline, I performed the following actions from the Kali Linux node:

SYN Stealth Scan: sudo nmap -sS -p 1-1000 192.168.1.1

Targeted Service Probing: nc -zv 192.168.1.1 22

Results in Kibana:
Successful Blocks: Observed real-time "Red" block events in OPNsense Live View.

Visualization: Created a Kibana Dashboard showing the "Top 10 Most Targeted Ports" and a timeline of blocked connection attempts categorized by Protocol.

🚀 Key Learning Outcomes
Mastered Syslog forwarding and UDP listener configuration.

Deepened understanding of Firewall Rule Priority (Top-to-Bottom evaluation).

Gained experience in Elasticsearch Index Management and data typing.

Developed Regular Expression/Dissect patterns for log parsing.
