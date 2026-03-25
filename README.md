# 🔍 URLF – Advanced URL Analyzer

`urlf` is a powerful command-line tool written in Python for analyzing, decoding, and inspecting complex URLs. It is especially useful for security researchers, penetration testers, and developers who want to understand URL structures, detect vulnerabilities, and extract meaningful data.

---

## 🚀 Features

* 🔓 Automatically decodes URL-encoded strings (even double-encoded)
* 🌐 Extracts host, domain, username, path, and parameters
* ⚠️ Detects potentially **sensitive parameters**
* 🧬 Decodes Base64-encoded values
* 🎨 Colored output for better readability
* 📄 JSON output support for automation
* 💾 Save results to file

---

## 📦 Installation

```bash
git clone https://github.com/Shaikh-Khizer/urlf.git
cd urlf
python3 urlf.py -h
```

---

## 🧰 Usage

```bash
urlf [-h] [-j] [-nc] [-o OUTPUT] [url]
```

### Arguments

| Argument | Description                             |
| -------- | --------------------------------------- |
| `url`    | Input URL (can also be piped via stdin) |

### Options

| Option              | Description            |
| ------------------- | ---------------------- |
| `-h`, `--help`      | Show help message      |
| `-j`, `--json`      | Output in JSON format  |
| `-nc`, `--no-color` | Disable colored output |
| `-o`, `--output`    | Save output to a file  |

---

## 📌 Examples

### 🔹 Basic Usage

```bash
echo "encoded_url_here" | urlf
```

### 🔹 JSON Output

```bash
echo "encoded_url_here" | urlf -j
```

### 🔹 Save Output

```bash
urlf "https://example.com" -o output.txt
```

---

---

## 🛡️ Security Use Cases

* 🧪 Analyze authentication URLs (OAuth, SSO)
* 🕵️ Extract hidden or encoded data
* ⚠️ Identify sensitive parameters like tokens, states, etc.

---

## ⚙️ How It Works

1. Accepts URL input (direct or via stdin)
2. Decodes URL encoding recursively
3. Parses URL components (host, path, query params)
4. Inspects parameters for:

   * Sensitive data patterns
   * Base64 encoding
   * Redirect risks
5. Outputs structured results (human-readable or JSON)

---

## 📁 Output Options

* Terminal (default)
* JSON (`-j`)
* File (`-o output.txt`)



---

## 📜 License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Shaikh Khizer**  
Computer Science Student | Penetration Tester

---

