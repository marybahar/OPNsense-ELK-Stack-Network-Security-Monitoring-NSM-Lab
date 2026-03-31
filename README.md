# 🛡️ OPNsense + ELK Stack: Network Security Monitoring (NSM) Lab

## 📌 Project Overview
This project demonstrates the deployment and configuration of a full-stack **SIEM (Security Information and Event Management)** pipeline. Using **OPNsense** as the core firewall and the **Elastic Stack (ELK)** for centralized logging, I built a system capable of detecting, parsing, and visualizing real-time network threats.

The lab focuses on **Log Ingestion**, **Data Normalization**, and **Threat Visualization** by simulating reconnaissance attacks from a Kali Linux machine.

---

## 🏗️ Architecture & Topology
* **Firewall:** OPNsense v25.7 (Virtual Appliance)
* **SIEM Ingestion:** Logstash (Listening on UDP Port 5514)
* **Storage & Search:** Elasticsearch 8.x
* **Visualization:** Kibana 8.x
* **Attack Node:** Kali Linux 2024.x (Nmap, Netcat)

---

## 🛠️ Configuration: The Logstash Pipeline
To ensure high-quality data for analysis, I developed a custom **Logstash Dissect Filter**. This filter successfully handles OPNsense CSV-style syslog headers and maps them to ECS (Elastic Common Schema) compatible fields.

### `opnsense.conf` Filter Logic
```ruby
filter {
  if [type] == "syslog" {
    dissect {
      mapping => {
        # The %{?rest_of_msg} catches trailing TCP flags to prevent mapping conflicts
        "message" => "%{?f1},%{?f2},%{?f3},%{?f4},%{interface},%{reason},%{action},%{dir},%{version},%{?f10},%{?f11},%{?f12},%{?f13},%{?f14},%{?f15},%{?f16},%{protocol},%{?f18},%{src_ip},%{dest_ip},%{src_port},%{dest_port},%{?rest_of_msg}"
      }
    }
    mutate {
      convert => {
        "src_port" => "integer"
        "dest_port" => "integer"
      }
    }




## 🧠 Technical Challenge: Solving Mapping Conflicts
During development, I encountered a Mapping Conflict in Kibana where dest_port was being stored as both a string (text) and a long (number).

Cause: Trailing TCP flags (e.g., ,S,1024) were being appended to the port field in raw syslog data.

Solution: I implemented a "catch-all" field (%{?rest_of_msg}) in the Logstash dissect pattern to isolate the numerical port. I then performed an index cleanup via the Elasticsearch API to re-index the data with clean integer types:

Bash
curl -X DELETE "localhost:9200/opnsense-logs-*"
  }
}
