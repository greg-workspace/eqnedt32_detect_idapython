# How to use eqnedt_cve_detect.py to detect CVE of EQNEDT32.exe?
## Enable gflags to attach EQNEDT32.exe
```shell
# gflags_cmd.bat
```
## Using IDA to open EQNEDT32.exe
## Click the exploitable RTF file (Be careful)
## Press Alt+F9 and insert eqnedt_cve_detect.py, and run the script. (Change hostname to localhost)
## The IDA Debugger will find the CVE and break at end of return instruction.
