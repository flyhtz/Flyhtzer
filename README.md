# Flyhtzer
Flyhtzer is a Discord Bot/Webhook based Rat stealing passwords cookies and much more!

# THE ONLY USE FOR THIS PROGRAM IS EDUCATIONAL PURPOSES DONT USE IT FOR ANY ILLEGAL ACTIVITY

# Usage
How to use Flyhtzer:

**Open cmd in directory of "Flyhtzer.py"**

**Than type**

```bash

pip install -r requirements.txt

```

**Change the SWITCHES to your liking (True/False)**

**Add your webhook on line 156**

**Change the Bot-Token on line 904 [Discord developer portal](https://discord.com/developers/applications)** *(optional if runrat = False)*

**Convert Flyhtzer to an EXE using pyinstaller** *(optional but recommended)*

**(How to conver Flyhtzer.py to exe)**

**Open cmd in directory of "Flyhtzer.py"**

**Than type**

```bash

pyinstaller --onefile Flyhtzer.py 

```

**wait for the program to finish and you will find your exe in the "dist" folder**



# Features
    
**PC Logger** 💻 

    Basic Information
      [1] Desktop Name
      [2] PC Username
      [3] BootTime
      [4] OS Version
      [5] HWID
      [6] Windows Key

    Roblox Cookies (requires python on pc atm!)
      [1] List of browser roblox cookies
      [2] The browsers they came from
      
    Minecraft Accounts
      [1] Usernames
      [2] Emails
      [3] Sessions
      [4] Tokens
      
    RAM
      [1] Total     GB
      [2] Available GB
      [3] Used      GB
      [4] Usage      %

    Local Network
      [1] Local IP
      [2] MAC Address

    IP Information
      [1] IP Address
      [2] Country
      [3] City
      [4] Coordinates (Lat/Long)

**Files Sent** 📁 *(Most from true/false Switches)*

      [1] Browser Passwords
      [2] Browser History
      [3] Browser Cookies
      [4] Basic Network
      [5] Full PC Scrape
      [6] Desktop Picture
      [7] Camera Picture

**Switches** ✔❌ *(Can be True/False)*

    [1] Add File to Startup
    [2] Minecraft Logger
    [3] Scrape PC
    [4] Scrape Network
    [5] Scrape Discord
    [6] Browser History
    [7] Browser Cookies
    [8] Roblox Cookies
    [9] Inject into Discord
    [0] Custom Payload
    [1] Hide Terminal
    [2] Send Login Script
    [3] Camera Picture
    [4] Desktop Picture
    [5] Add Accounts to MongoDB
    

**RAT** 🐀 *(Commands for bot)*

    [PREFIX: >]

    >menu
      [1] shell        [RCE and control/audit files  ]
      [2] spying       [Surveillance related tools   ]
      [3] system       [Gather information on the PC ]
      [4] admin        [Gather information on the PC ]
      [5] misc         [Miscellaneous Commands       ]
      [6] information  [Information about Flyhtzer   ]

    Shell Commands (Execute shell-like commands and control all files)
      [1] cmd <command> <embed/file>    [Executes Custom Command on Victims PC ]
      [2] download <file>               [Download any file from Victims PC     ]
      [3] upload <attachment> <name>    [Upload any file to TEMP Directory     ]
      [4] read <file> <embed/file>      [Sends File Content from any file      ]
      [5] delete <file>                 [Deletes any file from Victims PC      ]

    Surveillance Commands (Surveillance Related Tools)
      [1] monitoroff   [Turns all victims monitors on       ]
      [2] monitoron    [Turns all Victims monitors off      ]
      [3] screenshot   [Sends screenshot of Victims screen  ]
      [4] camera       [Sends a photo from victims camera   ]

    System Commands (Information Scraping Tools)
      [1] scrapecomputer [Sends full PC Scrape         ]
      [2] systeminfo     [Sends SystemInfo CMD         ]
      [3] drivers        [Sends all System Drivers     ]
      [4] tasks          [Sends Running Processes      ]

    Admin Commands (Requires admin perms)
      [1] blockinput   [Blocks mouse and keyboard inputs      ]
      [2] unblockinput [Unblocks mouse and keyboard inputs    ]
      [3] criticalproc [Makes PC bluescreen if program closes ]

    Miscellaneous Commands (Can't fit into categories)
      [1] endtask <taskname>            [Kills a task from the taskname        ]
      [2] setwallpaper <attachment>     [Sets Victims wallpaper to Attachment  ]
      [3] saymessage <message>          [Voices any message on Victims PC      ] 
      [4] messagebox <message>          [Shows a custom MessageBox Message     ]  

    Flyhtzer Commands (Commands Related to Flyhtzer)
      [1] showdb                        [Display all records in your Database     ]
      [2] cleardb                       [Clear all logs in your Database          ]
      [3] switches                      [Displays all switch values (True/False)  ]
      [4] credits                       [Displays credits for Flyhtzer (me lol)   ]
