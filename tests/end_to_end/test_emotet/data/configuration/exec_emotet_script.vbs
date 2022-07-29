set shell = CreateObject("WScript.Shell")
shell.run"C:\temp\trigger-emotet.exe"
WScript.Sleep 10000
shell.SendKeys "{ENTER}"
WScript.Sleep 10000
shell.SendKeys "{ENTER}"
