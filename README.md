🔍 Process Inspector – Suspicious Process & Parent Relationship Analyzer
Process Inspector is a C++ Windows tool that enumerates all running processes and detects suspicious activity based on:

Process names (e.g., cmd.exe, powershell.exe) 

Unusual parent-child relationships (e.g., cmd.exe spawned by explorer.exe) (From sans guide and manual test)

(Work in progress) Analyze Process command-line arguments in powershell or cmd (Work in progress)

Looping analysis every 5 seconds for continuous monitoring

⚠️

The parent process whitelist is customizable in isLegitParent().

The tool is designed to be run on a clean virtual machine, with no other third-party applications running, to avoid false positives.

If you're running legitimate applications, be sure to add their parent-child relationships to the isLegitParent() whitelist.
