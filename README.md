# 0xYumeko XSSSpecter

This tool scans websites for various types of XSS vulnerabilities (Reflected, Stored, and DOM-based XSS).

## Features:
- Dynamic form detection
- XSS payload testing
- Output formatted in PrettyTable and saved to a file

## Installation:

```bash
git clone https://github.com/0xYumeko/XSSSpecter.git
cd XSSSpecter
pip install -r requirements.txt
```

## Usage:
`
```bash
python3 XSSSpecter.py -u http://example.com -p payloads.txt -o output.txt
```


## Example Output:


This section explains how to install the tool using `git clone` and `pip install`, and provides usage examples with command-line arguments. Adding an example output image will also make it easier for users to understand.

### 3. **Requirements File (`requirements.txt`)**

**Example:**
```txt
colorama==0.4.4
requests==2.25.1
beautifulsoup4==4.9.3
prettytable==2.1.0
```

