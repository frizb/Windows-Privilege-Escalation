# Windows-Privilege-Escalation
My big 'Ol List of Windows Privilege Escalation Techniques and Scripts sorted by difficultly (Easy, Medium, Hard).

*Easy*

**Passwords**
Passwords can be one of the easiest methods of privledge escalation and there are some tools that can help with this process.


**CopyAndPasteFileDownloader.bat**

Windows file transfer script that can be pasted to the command line. File transfers to a Windows machine can be tricky without a Meterpreter shell. The following script can be copied and pasted into a basic windows reverse and used to transfer files from a web server (the timeout 1 commands are required after each new line)

**CopyAndPasteEnum.bat**

No File Upload Required Windows Privlege Escalation Basic Information Gathering (based on the fuzzy security tutorial).
Copy and paste the following contents into your remote Windows shell in Kali to generate a quick report

**enumeration.md** 

Basic notes on Windows Enumeration from the OSCP.

**windows_recon.bat**

An uploadable batch file for performing basic windows enumeration.


**References**
https://medium.com/@hakluke
https://daya.blog/2018/01/06/windows-privilege-escalation/
https://pentestlab.blog/2017/04/19/stored-credentials/
https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/

