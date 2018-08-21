cd\
net config Workstation  > report.txt
systeminfo >> report.txt
net users >> report.txt
ipconfig /all >> report.txt
route print >> report.txt
arp -A >> report.txt
netstat -ano >> report.txt
netsh firewall show state >> report.txt  
netsh firewall show config >> report.txt
schtasks /query /fo LIST /v >> report.txt
tasklist /SVC >> report.txt
net start >> report.txt
DRIVERQUERY >> report.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt
findstr /si password *.xml *.ini *.txt >> report.txt
reg query HKLM /f password /t REG_SZ /s >> report.txt
reg query HKCU /f password /t REG_SZ /s >> report.txt
cd\"Program Files"
dir /s *.exe *.ini >> ..\report.txt
cd\"Program Files (x86)"
dir /s *.exe *.ini >> ..\report.txt
cd\
