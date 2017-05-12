# Windows Enumeration for Privilege Escalation

net config Workstation

systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

hostname

net users

ipconfig /all

route print

arp -A

netstat -ano

netsh firewall show state	

netsh firewall show config

schtasks /query /fo LIST /v

tasklist /SVC

net start

DRIVERQUERY

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

dir /s *pass* == *cred* == *vnc* == *.config*

findstr /si password *.xml *.ini *.txt

reg query HKLM /f password /t REG_SZ /s

reg query HKCU /f password /t REG_SZ /s

sc qc Spooler

**Unquoted Service Paths**

# When executing any of the sysinternals tools for the first time the user will be presented with a GUI
add an extra command line flag to automatically accept the EULA.

accesschk.exe /accepteula 

***Find all weak folder permissions per drive.***
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\

***Find all weak file permissions per drive.***
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*

accesschk.exe -ucqv Spooler


*** Unquoted Service Paths ***
A vulnerability that occurs if a service executable path is not enclosed with quotation marks and contains space.

To identify these unquoted services you can run this command on Windows Command Shell:

wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

All services with unquoted executable paths will be listed:

meterpreter > shell
Process 4024 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C:\Users\testuser\Desktop>wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
Vulnerable Service                                      Vulnerable Service                   C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe                   Auto       
C:\Users\testuser\Desktop>

**Sources:**

http://www.fuzzysecurity.com/tutorials/16.html

https://technet.microsoft.com/en-us/sysinternals/bb664922

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

https://hackmag.com/security/elevating-privileges-to-administrative-and-further/

http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html

