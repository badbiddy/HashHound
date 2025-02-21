# HashHound 🐾🔐

## Overview
HashHound is a Python tool designed to analyze an NT password hash dump and detect duplicate hashes, which indicate accounts that share the same password.

## 🔍 Why This is Important

Shared passwords across multiple accounts are a major security risk, allowing attackers to move laterally within a system after compromising a single account. HashHound helps detect such vulnerabilities quickly.

## ⚙️ Features
✅ Detects duplicate NT hashes to find accounts using the same password.
✅ Formatted table output for readability.
✅ CSV export option for reporting and further analysis.
✅ Handles large datasets efficiently.
✅ Command-line flags for flexibility.

## 💚 Installation

Step 1: Install Required Python Libraries

Ensure you have Python 3 installed and run:

```
pip install tabulate
```

## 🚀 Usage

Basic Usage
To analyze an NT hash dump:
```
python hashhound.py -f hashes.txt
```
Save Results to CSV
```
python hashhound.py -f hashes.txt -o results.csv
```
Help Menu
```
python hashhound.py -h
```

## 📂 Required File Format

The input file must follow this format:
```
username:RID:LM_hash:NT_hash:::
```
Example:
```
admin:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
user1:1001:aad3b435b51404eeaad3b435b51404ee:202cb962ac59075b964b07152d234b70:::
user2:1002:aad3b435b51404eeaad3b435b51404ee:202cb962ac59075b964b07152d234b70:::
```
Here, user1 and user2 share the same NT hash (202cb962ac59075b964b07152d234b70), meaning they have the same password.

## 📊 Sample Output

Analyzing NT password hash dump: hashes.txt

Accounts sharing the same password (same NT hash detected):
```
+----------------------------------+------------------+----------------------------------+
| NT Hash                          | Shared By (Count) | User Accounts                    |
+----------------------------------+------------------+----------------------------------+
| 5f4dcc3b5aa765d61d8327deb882cf99 | 3                | admin, user1, user2             |
| 202cb962ac59075b964b07152d234b70 | 5                | user3, user4, user5, user6, user7, +2 more |
+----------------------------------+------------------+----------------------------------+
```
## 🛠️ Notes & Limitations

HashHound does not crack passwords; it only identifies duplicate hashes.
Ensure you have permission before running this tool on any system.
