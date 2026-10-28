' Starts the PHISH-X service with no window (used by install_autostart.bat).
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = fso.GetParentFolderName(WScript.ScriptFullName) & "\src"
sh.Run "pythonw server.py", 0, False
