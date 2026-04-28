# CVE Nessus Coverage Checker

A high-performance CVE-to-Nessus plugin coverage analyzer with a modern web dashboard.

This tool allows you to:

* Check whether CVEs are covered by Nessus plugins
* Build a local searchable index of all Nessus plugins
* Perform instant CVE lookups after indexing
* Export results to Excel
* Visualize coverage with an interactive dashboard

---

## 🚀 Features

* ⚡ **Fast CVE lookup** (after initial indexing)
* 📊 **Modern dashboard UI** (HTML frontend)
* 🔄 **Incremental plugin index updates**
* 📁 **Upload CVEs via Excel, CSV, or text**
* 🧠 **Local caching (persistent storage)**
* 📤 **Excel export with formatting**
* 🔐 **Secure API-based Nessus integration**

---

## 🏗️ Architecture

```
Frontend (dashboard.html)
        ↓
Flask Backend (Python)
        ↓
Nessus API
        ↓
Local Cache (~/.cve_nessus_cache.json)
```

---

## 📦 Requirements

* Python **3.8+**
* Nessus Professional (API enabled)

### Python Dependencies

Automatically installed on first run:

```
flask
requests
openpyxl
```

---

## 📥 Installation

### 1. Clone Repository

```
git clone https://github.com/<your-username>/cve-nessus-checker.git
cd cve-nessus-checker
```

### 2. Add Files

Ensure both files are in the same directory:

```
cve_checker_simple.py
dashboard.html
```

---

## ▶️ Usage

### Start the Application

```
python3 cve_checker_simple.py
```

### Open Dashboard

```
http://localhost:5000
```

---

## 🔐 Connect to Nessus

1. Open Nessus UI
2. Navigate to:

```
My Account → API Keys → Generate
```

3. Enter in dashboard:

* Nessus URL (default: `https://localhost:8834`)
* Access Key
* Secret Key

---

## 🧠 How It Works

### Step 1 — Connect

Validates Nessus API connectivity.

### Step 2 — Build Index (IMPORTANT)

* Fetches all Nessus plugins
* Extracts CVEs from each plugin
* Stores locally in:

```
~/.cve_nessus_cache.json
```

⏱️ First run:

* ~10–15 minutes (depending on concurrency)

⚡ Subsequent runs:

* Incremental updates only (very fast)

---

### Step 3 — Scan CVEs

Input methods:

* Upload file (`.xlsx`, `.csv`, `.txt`)
* Paste CVEs
* Manual entry

Example:

```
CVE-2021-44228
CVE-2023-44487
```

---

## 📊 Output

For each CVE:

| Field        | Description                  |
| ------------ | ---------------------------- |
| Status       | Covered / Not Covered        |
| Plugin Count | Number of matching plugins   |
| Plugin IDs   | Associated Nessus plugin IDs |
| Plugin Name  | First matching plugin        |
| CVSS         | Severity score               |

---

## 📤 Export

* Export results to Excel
* Includes:

  * Covered CVEs
  * Not Covered CVEs
  * Color-coded formatting

---

## ⚙️ Configuration

### Concurrency Control

Adjust in UI:

```
Build concurrency: 5 – 80 (default: 30)
```

* Higher = faster indexing
* But increases load on Nessus server

---

## 📁 File Structure

```
.
├── cve_checker_simple.py   # Backend (Flask + API + logic)
├── dashboard.html          # Frontend UI
└── README.md               # Documentation
```

---

## 💾 Cache Behavior

* Stored at:

```
~/.cve_nessus_cache.json
```

* Contains:

  * All plugins
  * CVE mappings

### Important Notes

* Cache is **persistent**
* Not rebuilt every time
* Only **new plugins are fetched**

---

## 🛠️ API Endpoints (Internal)

| Endpoint           | Method | Description        |
| ------------------ | ------ | ------------------ |
| `/api/connect`     | POST   | Connect to Nessus  |
| `/api/build-index` | POST   | Build/update index |
| `/api/scan`        | POST   | Scan CVEs          |
| `/api/upload-cves` | POST   | Upload CVE file    |
| `/api/status`      | GET    | Live status        |
| `/api/abort-index` | POST   | Stop indexing      |

---

## ⚠️ Troubleshooting

### Connection Failed

* Verify Nessus URL
* Check API keys
* Ensure Nessus is running

---

### Index Not Building

* Check logs in UI
* Reduce concurrency
* Ensure API permissions

---

### No CVEs Detected

* Ensure correct format:

```
CVE-YYYY-NNNN
```

---

### SSL Warnings

Ignored intentionally:

```
urllib3.disable_warnings()
```

---

## 🔒 Security Notes

* API keys are used locally only
* No external data transmission
* Runs entirely on localhost

---

## 📈 Performance Tips

* Use concurrency = 30 (optimal)
* Avoid full rebuild unless required
* Use incremental updates regularly

---

## 🧪 Example Workflow

```
1. Start app
2. Connect to Nessus
3. Build index (first time only)
4. Upload CVE list
5. Run scan
6. Export results
```

---

## 📌 Limitations

* Requires Nessus Professional API access
* First index build is time-consuming
* Depends on Nessus plugin data accuracy

---

## 🤝 Contribution

Feel free to:

* Improve UI
* Optimize indexing
* Add new export formats

---

## ⭐ Acknowledgment

Built for security teams to quickly validate Nessus coverage against real-world CVEs.

---
