"""
Sauron - Net Attack/Monitor Dashboard 
    (created by kizzycpt)
- contains simulated attacks
- neofetch like system information
- IDS monitoring and counter intelligence tools
"""

# Libraries
import os
import sys
import time
import math
import math
import threading
import platform
import json
import urllib.request
import urllib.error
import csv
import argparse

from datetime import datetime
from collections import deque
from pathlib import Path
from rich.console import Console


#Local Packages
from modes.netscan import scan_mode
from modes.IDS import IDS


#Instances
c = Console()


# Important Dependency Checks

try: #psutil check
    import psutil
except ImportError:
    c.print("[red]\n[!] Error: Missing Required Module 'psutil'[!]")
    print("\n📦 INSTALL INSTRUCTIONS:\n")

    #OS Detection for specific installation instructions
    if sys.platform == "linux":
        #Distro Contingencies
        try:
            with open('etc/os-release', 'r') as f:
                os_information = f.read().low()

                if 'kali' in os_information or 'debian' in os_information or 'ubunti' in os_information:
                    print("  Option 1 (Best - via apt):")
                    print("    sudo apt install python3-psutil python3-blessed")
                    print("\n  Option 2 (via pip):")
                    print("    pip3 install psutil blessed --break-system-packages")
                else:
                    print("  sudo pip3 install psutil blessed")
        except:
            print("  sudo pip3 install psutil blessed")
    
    
    elif sys.platform == "win32":
        print("  pip install psutil blessed")

    else: #Probably MacOS or something:
        print("  pip3 install psutil blessed")
    

    print("\n  Or You may install from the requirements text file:")
    print("    pip3 install -r requirements.txt --break-system-packages")
    print("\n")

    sys.exit(1)

try: #blessed check
    from blessed import terminal
except ImportError:
    c.print("[red]\n[!] Error: Missing Required Module 'psutil'[!]")
    print("\n📦 INSTALL INSTRUCTIONS:\n")

    #OS Detection for specific installation instructions
    if sys.platform == "linux":
        #Distro Contingencies
        try:
            with open('etc/os-release', 'r') as f:
                os_information = f.read().low()

                if 'kali' in os_information or 'debian' in os_information or 'ubunti' in os_information:
                    print("  Option 1 (Best - via apt):")
                    print("    sudo apt install python3-psutil python3-blessed")
                    print("\n  Option 2 (via pip):")
                    print("    pip3 install psutil blessed --break-system-packages")
                else:
                    print("  sudo pip3 install psutil blessed")
        except:
            print("  sudo pip3 install psutil blessed")
    
    
    elif sys.platform == "win32":
        print("  pip install psutil blessed")

    else: #Probably MacOS or something:
        print("  pip3 install psutil blessed")
    

    print("\n  Or You may install from the requirements text file:")
    print("    pip3 install -r requirements.txt --break-system-packages")
    print("\n")

    sys.exit(1)


#-------------------------------------------------------------------------------------------------------------
# Configs
#-------------------------------------------------------------------------------------------------------------

#Enabling Windows VT100 terminal for RGB colors and UTF-8
if sys.platform -- 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32

        #Enable ANSI escape code processing
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

        # Set UTF-8 output encoding
        sys.stdout.reqonfigure(encoding='utf-8')
    
    except:
        pass

# Version follows Semantic Versioning (SemVer): MAJOR.MINOR.PATCH
# MAJOR: Breaking changes, MINOR: New features, PATCH: Bug fixes
VERSION = "1.6.4"

def rgb(r, g, b):
    """Create RGB color escape code"""
    return f'\033[38;2;{r};{g};{b}m'

def rgb_bg(r, g, b):
    """Create RGB background color escape code"""
    return f'\033[48;2;{r};{g};{b}m'

RESET = '\033[0m'

#-------------------------------------------------------------------------------------------------------------
#Images
#-------------------------------------------------------------------------------------------------------------

# Static Death Star ASCII art for flat display - compact version
DEATH_STAR_STATIC = [
    "                             .-------===-=+=-:                               ",
    "                       .-------:=-======-===+=++++=.                         ",
    "                    :----:------=-=-=-===-=++++=+++***-                      ",
    "                 :-----::::---:=---:=====--+=++=+**+**+**-                   ",
    "               --::--::.:::-::--:=---==+=--===#%#####*+++*##                 ",
    "            .-::.:::::.:::::------:--=====-=-%%#####**+++==*#*.              ",
    "           :-::.::::.::::::::::-:-::=======+=#%%%###**+=--=:+##+             ",
    "         .:--::.::::.......:..:::-:--=+-=====%%%%##%#++=-:----###:           ",
    "        :-:-::.::.: ...... ...:::--::=-==---==#%%%%%%%+--------#%%*          ",
    "       :-::::.::: ........ ..:::::-::==-=---==+#%%%%%%#--:---=-+#%%*         ",
    "      -:---:...:. .:.::... .::::::-::--=----===+*#%%%@#==----+-+#%%%#        ",
    "     ::---....:: ..:.:.... .:-:::::-::---=---===+++*%###**++=++=###%%%+      ",
    "    .-:--:-:.:-:...::.:... .:::::::-::--===--===++++++*#####***####%%%%-     ",
    "    =------...:. ..:.:.::..:::::::--:-===---===++++++++*******#####%%%%.     ",
    "   :-------...:.  .:...:.. .........::::::-----=====++++++***######%%%%+     ",
    "   ----::......-+=----====-----------====+++******######********###%%%%#     ",
    "   -::-=*#=:......::.....:..:::::::--::-----=-====+++++++++**#%%%%%%%%%%:    ",
    "   *+-:::::::::.::::::::.::::--:::--=-:---====++*+**++******##*###%%%%%%=    ",
    "  .-------:::--::::--:::.:::----:--==-:===+++=++*+********#*##*#%%%%%%%%*    ",
    "  .+-=-----:-----:-----:.:-:----:-===--===+=+=+****+**#*###*%###%%%%%%%%#    ",
    "  .+==----:--=------=---::-===--:=+===-===++++***##**####%####%%%%#%%#%%*    ",
    "   +====-----==---=====-:---====-===+=-+++++++***#***#######%#%%%%#%%%#%-    ",
    "   =+=======-=========----======-=+++==++++*++**###**##%####%%#%%%#%%%%%.    ",
    "   =*+++=====-===-===+=====++++++=+++++*++***+++*%#*#**#######%%%#%%%%%*     ",
    "   .+++++=+=--====-++=++=+=*++++++++++**+****+**###*#*#######%%%%%%%%%%=     ",
    "    =*++++++===+++=++=++=++******++**+*#+****+*#*########%%#%%%%%%%%%%#      ",
    "     **++++++==+=========++++++*+++**#**+***##***########%#%%%%%#%%#%%       ",
    "     :**+*+*+++**++++++++++*****+*+**#*#**####**########%%#%%%#%%%%%%-       ",
    "      -#******++*******+*++****#+**###*#**####*#########%#%%%%%%%#%%-        ",
    "       -#********#*#***#****######*###*###%######%%%%%%%%%%%%%%%#%%-         ",
    "        .##*#*******########*%####*##%#%#%#%%%%%%%%%%%%%%%%%%%%%%%           ",
    "          +%#########%#####%##%#%###%%#%%%%%%%%%%%%%%%%#%%%%%%%%*            ",
    "           :#%##%#%%#%%%##%%%%%#%%#%%%%%%%%%%%%%%%%%%%%%%%%%%%#.             ",
    "             :%%%%###%#########%%%%%#%%%%%%%%%%%%%%%%%%%%%%%%:               ",
    "               :#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#.                 ",
    "                  +%@@%%%%%%@%@%%%%%%%%%%%%%@%@%%%%%%%%#=                    ",
    "                     -%%@%@@%%@@@@@@%@@@%%@@@%%%%%%%%-                       ",
    "                         :+@@@@@@@@@%%%%%%@%%@%%+:                           ",
    "                               .-===+++==-:.                                 ",
    "                                    ...                                      ",
    "                                                                             ",
]

# Earth bitmap data (120x60 equirectangular projection)
EARTH_MAP = [
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                             # ####### #################                                    #                           ",
    "                       #    #   ### #################            ###                                                    ",
    "                      ###  ## ####       ############ #                        ##         ########        #####         ",
    "                  ## ###   #  ### ##      ###########                         #    #### ################   ###          ",
    "      ######## ###### #### # #  #  ###     #########              #######        # ## ##################################",
    " ### ###########################    ####   #####      #          ####### ###############################################",
    "      ########################       ##    ####                #### ####################################################",
    "      ### # #################      ##        #                ##### # ##########################################  ##    ",
    "                ##############     #####                   #     #  #######################################      ##     ",
    "                 ################ #######                # #   ###########################################      ##      ",
    "                  ########################                 ################################################             ",
    "                    ###################  ##                ################################################             ",
    "                   ################### #                    ##########  ####  ############################              ",
    "                   ##################                    ##### ##  ###    ### ##########################                ",
    "                   #################                     ###       # ######## ######################  #    #            ",
    "                    ###############                       #  ###       ##############################  #  #             ",
    "                     #############                        ######        #############################                   ",
    "                       ######## #                        ############################################                   ",
    "                      # ####     #                      ##################### #######################                   ",
    "                       # ###      #                    ################# ######    #################                    ",
    "                         ###  #   #                    ################## ######     ####  #####                        ",
    "                          #####   # #                  ################## #####      ###    ####                        ",
    "                             ####                      ################### ###       ##      ####   #                   ",
    "                               #    #                  ####################           #      # ##                       ",
    "                                #  #####                #####################         #      # #     ##                 ",
    "                                   ######                #### ###############          #      #    #                    ",
    "                                   ########                     ############                 ##   ##                    ",
    "                                  #########                     ###########                   #  ####                   ",
    "                                  #############                 ##########                    ##### #     ##            ",
    "                                 ################                ########                                  ## #         ",
    "                                  ###############                #########                         ## #    # #          ",
    "                                   #############                 #########                                              ",
    "                                   ############                  #########  #                         # ##  #           ",
    "                                     ##########                 #########  ##                        ########           ",
    "                                     ##########                  #######   ##                      ###########     #    ",
    "                                     ########                    #######   #                      #############         ",
    "                                     #######                     ######                           ##############        ",
    "                                     #######                      #####                            #############        ",
    "                                     ######                       ####                             ###   ######         ",
    "                                    #####                                                                  ####       # ",
    "                                    #####                                                                              #",
    "                                    ###                                                                      #        # ",
    "                                    ###                                                                             ##  ",
    "                                    ##                                                                                  ",
    "                                   ##                                                                                   ",
    "                                    ##                                                                                  ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                       #                                                                                ",
    "                                      #                                #  ##########   ########################         ",
    "                                   #####                 ########################## #################################   ",
    "                  # ## #   #############              #############################################################     ",
    "        ## #########################             ##################################################################     ",
    "           ######################## #  #  ##     #################################################################      ",
    "    ##################################################################################################################  ",
    "########################################################################################################################",
]

# ASCII Logos for neofetch-style display (from neofetch repo issue #1466)
LOGOS = {
    "Windows": [
        " ....::  ll",
        " ll  llllll",
        " ll  llllll",
        " ll  llllll",
        "",
        " ll  llllll",
        " ll  llllll",
        " ll  llllll",
        " ``  llllll",
    ],
    "Linux": [
        "    ___",
        "   (.. |",
        "   (<> |",
        "  / __  \\",
        " ( /  \\ /|",
    ],
    "Darwin": [  # macOS
        "      .:'",
        "  __ :'__",
        " .'`__`-'",
        " :__/  ",
        " :/'",
    ],
}

#-------------------------------------------------------------------------------------------------------------
# Objects
#-------------------------------------------------------------------------------------------------------------

class IPIntelligence:
    """IP Gelocation and Threat Mapping"""

    def __init__(self):
        self.cache = {} # {ip: {geo_data, threat_data, timestamp}}
        self.cache_ttl = 3600 #1hr
    
    
    def get_geolocation(self, ip):
        """Get geoloacation for IP using ip-api.com"""

        #check cache
        if ip in self.cache:
            cached = self.cache[ip]
            if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                return cached.get('geo')
        
        
        #defaulting for private IPs (v4 & v6)
        if ip.startswith(('10.', '192.168.', '172.16.', '127.', 'localhost', 'fe80:', '::1', 'fc00', 'fd00')):

            geo_data = {
                'country': 'LOCAL',
                'countryCode' : 'LO',
                'city' : 'Private Network',
                'isp' : 'Local Network',
                'threat': 'SAFE',
            }

            self.cache[ip] = {'geo': geo_data, 'timestamp': time.time()}
            return geo_data
        
        
        try:
            # ip-api.com free tier request. (45 requests per minute)
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
            
