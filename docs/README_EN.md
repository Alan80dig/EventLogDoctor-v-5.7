# EVENTLOGDOCTOR V5.7 - COMPLETE DOCUMENTATION 🇺🇸

🔗 Russian Version: README_RU.md  


## 📋 CONTENTS
1. What is EventLogDoctor v5.7?
2. How It Works?
3. Quick Start
4. Complete Guide
5. AI Report Analysis
6. Security & Privacy
7. Frequently Asked Questions (FAQ)
8. Troubleshooting
9. For Developers

---

## 🔍 WHAT IS EVENTLOGDOCTOR?

EventLogDoctor v5.7 is a PowerShell script for comprehensive Windows system diagnostics optimized for artificial intelligence analysis.

## 🎯 KEY FEATURES:
- Windows Event Logs analysis (critical errors, warnings, patterns)
- Hardware diagnostics (CPU/disk temperatures, SMART status, RAM usage)
- System health check (services, disks, security)
- Hidden issues detection (disabled devices, suspicious tasks)
- Structured report generation for AI analysis

## 🛡️ OPERATING PRINCIPLES:
- Read-only mode - no system changes
- Privacy-focused - all data anonymized
- Local processing - everything stays on your computer
- Clarity - reports structured for AI and beginners

---

## ⚙️ HOW IT WORKS?

## 📋 DIAGNOSTIC PROCESS:

1. Run as Administrator → obtain required privileges
2. Collect system information → RAM, CPU, disks, Windows version
3. Analyze event logs → 400+ Windows logs from last 7 days
4. Check hardware → temperatures, disk SMART status
5. Generate structured report → optimized for AI analysis
6. Copy for AI → full report text ready for ChatGPT/Gemini/Copilot

## 📊 WHAT'S CHECKED:

## EVENT LOGS (High importance)
- 400+ Windows logs
- Critical errors and patterns

## HARDWARE (High importance)
- CPU/disk temperatures
- SMART status
- RAM usage

## SYSTEM (Medium importance)
- Services
- Disk space
- Updates

## SECURITY (Medium importance)
- Antivirus
- Firewall
- Hidden tasks

## DEVICES (Low importance)
- Disabled/problem devices

---

## 🚀 QUICK START

### ⚠️ CRITICALLY IMPORTANT FOR CORPORATE USERS:

## DO NOT RUN THIS SCRIPT ON WORK COMPUTERS WITHOUT EXPLICIT PERMISSION.

# REQUIRED PERMISSIONS:

- ✅ Information Security Department
- ✅ System Administrator / IT Department
- ✅ Department Manager (if required)

# WITHOUT PERMISSION YOU MAY:
- Violate corporate security policies
- Face disciplinary action
- Be held liable

# ACTION ORDER:
1. Get permission → 2. Run the script

---

# STEP 1: DOWNLOAD
- Download the latest version:
- https://github.com/alan80dig/EventLogDoctor v5.7/releases/latest

# STEP 2: RUN
1. Right-click on EventLogDoctor.ps1
2. Select "Run as administrator"
3. Confirm launch (Y or N)

# STEP 3: ANALYZE
1. Copy ALL text from the generated report
2. Paste into ChatGPT, Gemini, Claude, or other AI
3. Ask questions (examples below)

---

## 📖 COMPLETE GUIDE

# SUPPORTED SYSTEMS:

- ✅ Windows 10 (all builds)
- ✅ Windows 11 (all builds)
- ⚠️ Windows 8.1/7 (limited support)
- ❌ Windows XP/Vista (not supported)

# REQUIREMENTS:
- PowerShell 5.1 or higher
- Administrator rights
- ~100 MB free space
- 2+ GB RAM

# LAUNCH PARAMETERS:
- Script runs without parameters
- Analysis period: default 7 days
- Output folder: C:\WindowsDiagnostics\
- Language: auto-detected

# REPORT STRUCTURE:

- WindowsDiagnostics/
- ├── Diagnostics_Report_20260201_1425.txt  # Full report for AI
- └── Quick_Summary_20260201_1425.txt       # Brief summary

---

## 🤖 AI REPORT ANALYSIS

- WHY AI?
- Windows logs contain thousands of technical messages. EventLogDoctor v5.7 structures them into a clear format that AI can analyze - - like an experienced system administrator.

## 📋 EXAMPLE QUESTIONS FOR AI:

# FOR BEGINNERS:
- "What are the top 3 issues in this report?"
- "Are disk errors dangerous? What should I do?"
- "Is high CPU temperature normal?"
- "How to clean up RAM?"

# FOR ADVANCED USERS:
- "What's the root cause of WMI 5858 errors?"
- "How to interpret error patterns at 18:00?"
- "Should I worry about 177 disabled devices?"
- "How to repair WMI repository?"

## 🎯 EXAMPLE AI ANALYSIS:

# QUESTION: "What are the top 3 issues in this report?"

- AI ANSWER:
1. 🔴 Critical disk errors (ID 507) - possible HDD failure
   Recommendation: Immediately backup data, check disk with CrystalDiskInfo
   
2. 🟡 High RAM usage (87%) - insufficient memory
   Recommendation: Close unnecessary programs, add RAM if possible
   
3. 🟠 WMI errors (ID 5858) - system component corruption
   Recommendation: Run in admin command prompt: winmgmt /resetrepository

---

## 🔒 SECURITY & PRIVACY

### ⚠️ CORPORATE USAGE:

## MANDATORY STEPS BEFORE RUNNING IN WORK ENVIRONMENT:
1. Coordination with IT department - obtain written permission
2. Security policy check - ensure compliance with corporate rules
3. Notification - inform about diagnostic run time
4. Backup - save important data just in case
5. Reporting - provide results to IT specialists

## WHAT THE SCRIPT DOES NOT DO:

- ❌ Doesn't change system settings
- ❌ Doesn't install software
- ❌ Doesn't send data to the internet
- ❌ Doesn't require registration
- ❌ Doesn't collect personal information

## DATA ANONYMIZATION:
- Original: DESKTOP-USER123\Ivanov
- After: DESK****\USER_****
- Original: 192.168.1.100
- After: 192.168.*.*

# SECURITY VERIFICATION:
1. Open source - anyone can review the logic
2. Read-only - no registry or system file writes
3. Local analysis - all data stays on your PC

---

## ❓ FREQUENTLY ASKED QUESTIONS (FAQ)

- ❔ QUESTION: Is the script safe?
- ANSWER: Yes. The script works in "read-only" mode, doesn't make system changes. Code is open for review.

- ❔ QUESTION: Why admin rights are needed?
- ANSWER: Reading some event logs and hardware information requires elevated privileges.

- ❔ QUESTION: How long does the check take?
- ANSWER: Typically 2-5 minutes depending on disk speed and log quantity.

- ❔ QUESTION: Can I run it on a work computer?
- ANSWER:
- DO NOT RUN without permission. Get explicit permission from:
  1. Company Information Security Department
  2. System Administrator or IT Department

### IMPORTANT: Running diagnostic tools in corporate environment without permission may violate security policies and lead to disciplinary action.

# MANDATORY ACTION ORDER:
1. Obtain written permission from responsible persons
2. Coordinate run time
3. Provide diagnostic results to IT department
4. Only then run the script

- ❔ QUESTION: How often should I run the check?
- ANSWER: Recommended:
- When problems appear - for diagnostics
- Once a month - for prevention
- After installing updates - for stability check

- ❔ QUESTION: Script shows "Temperature: N/A"
- ANSWER: Some systems don't provide temperature data through standard interfaces. This is normal.

---

## 🔧 TROUBLESHOOTING

# PROBLEM: "Access denied" when running
# SOLUTION:
1. Close the script
2. Right-click → "Run as administrator"
3. Or open PowerShell as admin and run: .\EventLogDoctor v5.7.ps1

# PROBLEM: "Cannot load logs"
# SOLUTION:
1. Check if "Windows Event Log" service is running
2. Start service: net start eventlog
3. Restart script

# PROBLEM: PowerShell errors
# SOLUTION:
1. Update PowerShell: winget upgrade Microsoft.PowerShell
2. Check execution policy: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
3. Restart PowerShell

# PROBLEM: Reports not created
# SOLUTION:
1. Check write permissions in C:\WindowsDiagnostics\
2. Check antivirus - it might block file creation
3. Run PowerShell as administrator

---

## 👨‍💻 FOR DEVELOPERS

# PROJECT DEVELOPMENT
- EventLogDoctor v5.7 is a complete tool with clearly defined functionality. Core features are stable and thoroughly tested.

# PROJECT STRUCTURE:
- EventLogDoctor v5.7.ps1
- ├── Data collection functions (Get-SystemInformation, Check-Temperatures...)
- ├── Analysis functions (Analyze-Events, Check-GhostDevices...)
- ├── Report functions (Create-Reports)
- └── Main script

## CORE FUNCTIONS:

- Get-SystemInformation
- Collects system information: RAM, CPU, disks, Windows version.

- Analyze-Events
- Analyzes event logs, finds error patterns.

- Create-Reports
- Generates structured reports for AI analysis.

## TESTING:
- Test mode run: .\EventLogDoctor v5.7.ps1 | Out-File test_report.txt
- Specific function check: Get-SystemInformation | ConvertTo-Json | Out-File system_info.json

---

## 📞 SUPPORT

# FOUND A BUG?
1. Restart script with admin rights
2. Check if version is current
3. If problem persists - save report for analysis

- ACKNOWLEDGMENTS:
- Thank you to everyone using EventLogDoctor for system diagnostics!

---

## 📢 SPREAD THE KNOWLEDGE!

Like EventLogDoctor v5.7? Tell your friends and colleagues!

⭐ Star on GitHub: https://github.com/alan80dig/EventLogDoctor v5.7

EventLogDoctor - Making Windows diagnostics accessible to everyone! 🖥️🔧

---

Last update: February 2026 | Documentation version: 1.0

