# 🔒 Hash Generator, Verifier & VirusTotal Analyzer

A powerful, zero-dependency Python tool for computing cryptographic hashes, verifying file integrity, and analyzing threat intelligence via the VirusTotal v3 API. Features both a rich command-line interface (CLI) and a sleek dark-mode desktop GUI.

---

## 🌟 Key Features

* **Multi-Algorithm Hashing**: Supports `SHA-256`, `MD5`, `SHA-512`, `SHA-1`, `BLAKE2b`, and `BLAKE2s`.
* **Flexible Inputs**: Hash individual local files, raw text strings, or recursively process entire directory structures.
* **Integrity Verification**: Create companion checksum files (`.sha256`, `.md5`) and verify file integrity to detect corruption or tampering.
* **VirusTotal API v3 Threat Analysis**:
  * Query VirusTotal's database of 70+ security vendor engines using file hashes (SHA-256 / MD5 / SHA-1).
  * Automatically upload local files for analysis if missing from VirusTotal.
  * View threat detection ratios, threat labels, reputation, and detailed vendor engine alerts.
  * Direct links to VirusTotal web reports.
* **Modern Dark-Mode GUI**: Built with Python Tkinter/TTK for a clean desktop user experience.
* **Zero External Dependencies**: Built entirely using Python's standard library (`hashlib`, `urllib`, `argparse`, `tkinter`).

---

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher installed.

```bash
python --version
```

### Installation

Clone or download the repository:

```bash
git clone https://github.com/your-repo/hashgenerator.git
cd hashgenerator
```

No `pip install` required! All core modules use standard Python libraries.

---

## 🖥️ Graphical User Interface (GUI)

Launch the dark-themed desktop application:

```bash
python hash_tool.py gui
```

### GUI Features

1. **File Hasher & Verifier**: Compute hashes, save companion checksum files, verify file integrity against expected hashes, and trigger quick VirusTotal scans.
2. **Text Hasher**: Real-time hash calculation for raw text input strings.
3. **Directory Hasher**: Recursively scan entire folders, compute file digests, display results in an interactive table, and export summary reports.
4. **VirusTotal Analyzer**: Configure your VirusTotal API key (with show/hide toggle), query hashes or files, view threat status badges, examine individual vendor detection results, and open permalinks in your web browser.

---

## 💻 Command Line Interface (CLI)

### 1. Hash Generation

* **Hash a file (SHA-256 default)**:
  ```bash
  python hash_tool.py generate --file document.pdf
  ```

* **Specify algorithm and save companion checksum file (`document.pdf.sha256`)**:
  ```bash
  python hash_tool.py generate --file document.pdf --algo sha256 --save
  ```

* **Hash a text string**:
  ```bash
  python hash_tool.py generate --text "Hello World" --algo md5
  ```

* **Recursively hash an entire directory**:
  ```bash
  python hash_tool.py generate --dir ./my_folder --algo sha256
  ```

---

### 2. File Verification

* **Verify a file against an expected hash digest**:
  ```bash
  python hash_tool.py verify --file document.pdf --hash 2fd4e1c67a2d28fced849ee1bb76e7391b93eb1271907845b0178d00d3027061
  ```

* **Verify using a companion `.sha256` checksum file**:
  ```bash
  python hash_tool.py verify --file document.pdf --hash-file document.pdf.sha256
  ```

---

### 3. VirusTotal Threat Analysis

#### Setting your VirusTotal API Key

Set your VirusTotal API v3 key as an environment variable:

* **Windows PowerShell**:
  ```powershell
  $env:VIRUSTOTAL_API_KEY="your_api_key_here"
  ```
* **Windows CMD**:
  ```cmd
  set VIRUSTOTAL_API_KEY=your_api_key_here
  ```
* **Linux / macOS**:
  ```bash
  export VIRUSTOTAL_API_KEY="your_api_key_here"
  ```

#### CLI VirusTotal Commands

* **Analyze a hash digest**:
  ```bash
  python hash_tool.py virustotal --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  ```

* **Analyze a local file**:
  ```bash
  python hash_tool.py virustotal --file sample.exe
  ```

* **Automatically upload file if not found in VirusTotal database**:
  ```bash
  python hash_tool.py virustotal --file sample.exe --upload
  ```

* **Perform VirusTotal threat check during hash generation or verification**:
  ```bash
  python hash_tool.py generate --file sample.exe --vt
  python hash_tool.py verify --file sample.exe --hash <expected_hash> --vt
  ```

---

## 🧪 Running Tests

Run the unit test suite:

```bash
python -m unittest test_hash_tool.py
```

Run the end-to-end CLI integration test runner:

```bash
python hash_test/run_cli_tests.py
```

---

## 📁 Project Structure

```
.
├── hash_tool.py                     # Main CLI entry point & core hashing functions
├── hash_gui.py                      # Desktop Graphical User Interface (Tkinter / TTK)
├── vt_client.py                     # VirusTotal API v3 client module (urllib based)
├── test_hash_tool.py                # Unit test suite with mocking for VirusTotal API
├── hash_generator_verifier_guide.md # In-depth technical reference & tutorial
├── hash_test/                       # Test assets and CLI test runner
└── README.md                        # Project documentation
```

---

## 📜 License

This project is open-source and available under the [MIT License](LICENSE).
