Dim fso, configFile
Dim params, paramsArray, CONFIGDIR, i, prefixLen
Dim CONFIG_LOG_LEVEL, CONFIG_CLEARTEXT_BACKEND_TARGET, CONFIG_INGEST_SECRET, CONFIG_ENABLE_SYSMON, CONFIG_ENABLE_FORWARDED
Dim CONFIG_ENABLE_FOLLOWER, CONFIG_TAG_NAME, CONFIG_FILE_FILTER, CONFIG_WATCHED_FOLDER
Const Quote = """"
Const Backtick = "`"
Const NumFixedParams = 9
Set fso = CreateObject("Scripting.FileSystemObject")

params = Session.Property("CustomActionData")
paramsArray = split(params, "|")
CONFIGDIR = paramsArray(0)
CONFIG_LOG_LEVEL = paramsArray(1)
CONFIG_CLEARTEXT_BACKEND_TARGET = paramsArray(2)
CONFIG_ENABLE_SYSMON = paramsArray(3)
CONFIG_ENABLE_FORWARDED = paramsArray(4)
CONFIG_ENABLE_FOLLOWER = paramsArray(5)
CONFIG_TAG_NAME = paramsArray(6)
CONFIG_FILE_FILTER = paramsArray(7)
CONFIG_WATCHED_FOLDER = paramsArray(8)

' the secret is last and may itself contain the separator
prefixLen = 0
For i = 0 To NumFixedParams - 1
  prefixLen = prefixLen + len(paramsArray(i)) + 1
Next
CONFIG_INGEST_SECRET = mid(params, prefixLen + 1)

Set configFile = fso.CreateTextFile(CONFIGDIR & "windows.cfg", True)

configFile.WriteLine ("[Global]")
configFile.WriteLine ("Ingest-Secret = " & Backtick & CONFIG_INGEST_SECRET & Backtick)
configFile.WriteLine ("Connection-Timeout = 0")
configFile.WriteLine ("Insecure-Skip-TLS-Verify = true")
configFile.WriteLine ("#note that backslashes (\) are an escape character and must be escaped themselves")
configFile.WriteLine ("Cleartext-Backend-Target=" & CONFIG_CLEARTEXT_BACKEND_TARGET & " #example of adding a cleartext connection")
configFile.WriteLine ("#Cleartext-Backend-Target=127.1.0.1:4023 #example of adding another cleartext connection")
configFile.WriteLine ("#Encrypted-Backend-Target=127.1.1.1:4024 #example of adding an encrypted connection")
configFile.WriteLine ("#Ingest-Cache-Path=""C:\\ProgramData\\gravwell\\windows\\windows.cache""")
configFile.WriteLine ("#Max-Ingest-Cache=1024 #Number of MB to store, localcache will only store 1GB before stopping.  This is a safety net")
configFile.WriteLine ("Log-Level=" & CONFIG_LOG_LEVEL)
configFile.WriteLine ("Max-Files-Watched=64")
configFile.WriteLine ()
configFile.WriteLine ("############# Windows Event Log channels #############")
configFile.WriteLine ("[EventChannel ""system""]")
configFile.WriteLine ("	Tag-Name=windows")
configFile.WriteLine ("	Channel=System")
configFile.WriteLine ()
configFile.WriteLine ("[EventChannel ""application""]")
configFile.WriteLine ("	Tag-Name=windows")
configFile.WriteLine ("	Channel=Application")
configFile.WriteLine ()
configFile.WriteLine ("[EventChannel ""security""]")
configFile.WriteLine ("	Tag-Name=windows")
configFile.WriteLine ("	Channel=Security")
configFile.WriteLine ()
configFile.WriteLine ("[EventChannel ""setup""]")
configFile.WriteLine ("	Tag-Name=windows")
configFile.WriteLine ("	Channel=Setup")
configFile.WriteLine ()
If CONFIG_ENABLE_FORWARDED="Checked" Then
configFile.WriteLine ("[EventChannel ""forwarded events""]")
configFile.WriteLine ("	Tag-Name=windows")
configFile.WriteLine ("	Channel=""ForwardedEvents""")
configFile.WriteLine ()
End If
If CONFIG_ENABLE_SYSMON="Checked" Then
configFile.WriteLine ("[EventChannel ""sysmon""]")
configFile.WriteLine ("	Tag-Name=sysmon")
configFile.WriteLine ("	Channel=""Microsoft-Windows-Sysmon/Operational""")
configFile.WriteLine ()
End If
configFile.WriteLine ("############# File followers #############")
If CONFIG_ENABLE_FOLLOWER="Checked" Then
configFile.WriteLine ("[Follower ""installer""]")
configFile.WriteLine ("	Base-Directory = " & Backtick & CONFIG_WATCHED_FOLDER & Backtick)
configFile.WriteLine ("	File-Filter=" & Backtick & CONFIG_FILE_FILTER & Backtick)
configFile.WriteLine ("	Tag-Name=" & Backtick & CONFIG_TAG_NAME & Backtick)
configFile.WriteLine ("	Assume-Local-Timezone=true")
configFile.WriteLine ()
Else
configFile.WriteLine ("#[Follower ""cbs""]")
configFile.WriteLine ("#	Base-Directory=""C:\\Windows\\Logs\\CBS""")
configFile.WriteLine ("#	File-Filter=""*.log""")
configFile.WriteLine ("#	Tag-Name=cbs")
configFile.WriteLine ("#	Assume-Local-Timezone=true")
configFile.WriteLine ()
End If
configFile.WriteLine ("############# ETW (Event Tracing for Windows) sessions #############")
configFile.WriteLine ("# ETW events are rendered as JSON.  Each section is one real-time ETW session.")
configFile.WriteLine ("#[ETW ""process""]")
configFile.WriteLine ("#	Tag-Name=etw")
configFile.WriteLine ("#	Provider=Microsoft-Windows-Kernel-Process")
configFile.WriteLine ("#	Level=information")
configFile.WriteLine ("#	Match-Any-Keyword=0x10 #WINEVENT_KEYWORD_PROCESS")
configFile.WriteLine ("#")
configFile.WriteLine ("#[ETW ""dns""]")
configFile.WriteLine ("#	Tag-Name=etw-dns")
configFile.WriteLine ("#	Provider=Microsoft-Windows-DNS-Client")
configFile.WriteLine ("#	Event-ID=3008")
configFile.WriteLine ("#")
configFile.WriteLine ("# Threat-Intelligence requires the ingester to run as an antimalware protected process")
configFile.WriteLine ("#[ETW ""threat-intel""]")
configFile.WriteLine ("#	Tag-Name=etw-ti")
configFile.WriteLine ("#	Provider=Microsoft-Windows-Threat-Intelligence")
configFile.WriteLine ("#	Match-Any-Keyword=KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE")
configFile.WriteLine ("#	Match-Any-Keyword=KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE")

configFile.Close
