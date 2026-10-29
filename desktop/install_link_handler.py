"""
Registers PHISH-X Link Guard as a web browser in Windows (current user only, no admin needed).
Afterwards: Windows Settings -> Apps -> Default apps -> choose "PHISH-X Link Guard" for HTTP and HTTPS.
Undo: python install_link_handler.py --remove   (then pick your normal browser as default again)
"""
import json
import os
import subprocess
import sys

if os.name != "nt":
    sys.exit("This installer is for Windows.")
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import linkguard

APP = "PHISH-X Link Guard"
PROGID = "PHISHXLinkGuardURL"
KEY_APP = r"Software\Clients\StartMenuInternet\PHISHXLinkGuard"
pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
if not os.path.exists(pyw):
    pyw = sys.executable
CMD = f'"{pyw}" "{os.path.join(HERE, "linkguard.py")}" "%1"'


def put(path, name, value):
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)


def remove_tree(path):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            while True:
                try:
                    sub = winreg.EnumKey(k, 0)
                except OSError:
                    break
                remove_tree(path + "\\" + sub)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def install():
    b = linkguard.real_browser()
    if not b:
        sys.exit("Could not find Chrome or Edge. Install one first.")
    with open(linkguard.CONFIG, "w") as f:
        json.dump({"browser": b}, f)          # remembered so we never hand links back to ourselves
    put(r"Software\Classes\\" + PROGID, "", APP + " URL")
    put(r"Software\Classes\\" + PROGID + r"\shell\open\command", "", CMD)
    put(KEY_APP, "", APP)
    put(KEY_APP + r"\Capabilities", "ApplicationName", APP)
    put(KEY_APP + r"\Capabilities", "ApplicationDescription", "Checks links for phishing before they open")
    put(KEY_APP + r"\Capabilities\URLAssociations", "http", PROGID)
    put(KEY_APP + r"\Capabilities\URLAssociations", "https", PROGID)
    put(r"Software\RegisteredApplications", "PHISHXLinkGuard", KEY_APP + r"\Capabilities")
    print("Registered. Your real browser stays:", b)
    print("Now open Windows Settings > Apps > Default apps, search 'PHISH-X', and set it as the default for HTTP and HTTPS.")
    subprocess.Popen(["cmd", "/c", "start", "ms-settings:defaultapps"])


def remove():
    remove_tree(KEY_APP)
    remove_tree(r"Software\Classes\\" + PROGID)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\RegisteredApplications", 0, winreg.KEY_WRITE) as k:
            winreg.DeleteValue(k, "PHISHXLinkGuard")
    except FileNotFoundError:
        pass
    print("Removed. Set your normal browser as default again in Windows Settings > Default apps.")


if __name__ == "__main__":
    remove() if "--remove" in sys.argv else install()
