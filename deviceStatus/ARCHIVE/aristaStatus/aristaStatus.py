import sys
import os
import re
import time
import json
import threading
import pprint
import pyeapi
import datetime
import subprocess
import getpass
import argparse
import concurrent.futures
from pathlib import Path


def logit(text):
    """Function accepts string and prints to logfile"""
    global logfile
    f = open(logfile, "a")
    if f:
        f.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "  " + text + "\n")
        f.close()
    else:
        print("%s  Failed to open %s") % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), logfile)


def getArgs():
    """Function to get inventory and mode arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--inventory", default=None, required=True, help="Name of the inventory file", action="append"
    )
    parser.add_argument("-e", "--makeEapi", default=None, help="Build .eapi.conf file", action="store_true")
    args = parser.parse_args()

    inventory = args.inventory[0]
    # print("Inventory: " + inventory);logit("Inventory: " + inventory)

    if len(args.inventory) > 1:
        sys.exit("Only one inventory file allowed")

    if args.makeEapi:
        # print("mkeapi is true")
        mkeapi = True
    else:
        # print("mkeapi is false")
        mkeapi = False

    return inventory, mkeapi


def getInventory(file):
    """
    Function to read inventory file and return dictionary
    """
    tmpdict = {}
    with open(file) as f:
        for line in f:
            switch = line.rstrip().replace(".mgmt.", ".")
            tmpdict[switch] = {}
            if "msw" not in switch:
                tmpdict[switch]["updown"] = "Down/Down"
                tmpdict[switch]["peerstate"] = "INIT"
                tmpdict[switch]["maintmode"] = "INIT"
                tmpdict[switch]["mlagstate"] = "INIT"
            else:
                tmpdict[switch]["updown"] = "Down"
                tmpdict[switch]["peerstate"] = "INIT"
                tmpdict[switch]["maintmode"] = ""
                tmpdict[switch]["mlagstate"] = ""

    # pprint.pprint(tmpdict)
    logit(json.dumps(tmpdict, indent=4))
    return tmpdict


def makeEapiConf(switchlist):
    """
    Function to create .eapi.conf for given switches and password
    Sometimes have to run the script twice.  Need to debug
    """
    password = getpass.getpass(prompt="\n - Arista Admin password: ")

    if os.path.exists(str(Path.home()) + "/.eapi.conf") == True:
        logit("backing up .eapi.conf")
        r = os.rename(
            str(Path.home()) + "/.eapi.conf",
            str(Path.home()) + "/.eapi.conf.%s.bk" % datetime.datetime.now().strftime("%Y-%m-%d"),
        )
    logit("creating new .eapi.conf")
    f = open(str(Path.home()) + "/.eapi.conf", "w+")
    if f:
        f.write("[DEFAULT]\n" + "username: admin\n" + "transport: https\n" + "password: " + password + "\n")
    for switch in switchlist:
        f.write("[connection:" + switch + "]\n" + "host: " + switch + "\n")
        if "msw" not in switch and "mgmt" not in switch:
            # conditional for 3 and 4 digit site codes
            if len(switch.rsplit(".")[-1]) == 4:
                switchmgmt = switch[: len(switch) - 5] + ".mgmt" + switch[len(switch) - 5 :]
            else:
                switchmgmt = switch[: len(switch) - 4] + ".mgmt" + switch[len(switch) - 4 :]
            f.write("[connection:" + switchmgmt + "]\n" + "host: " + switchmgmt + "\n")
    f.close()
    return


def getPeerStatus(switch, peergroup):
    """Function to get and returne uplink BGP peer state"""
    pstate = ""

    try:
        node = pyeapi.connect_to(switch)
    except:
        logit(str(switch) + " failed EAPI connect")

    # Hack to make work easily for all switch types
    if "msw" not in switch:
        switch = switch.rstrip().replace(".mgmt.", ".")

    try:
        showbgp = node.enable("show ip bgp peer-group ")
        if peergroup in showbgp[0]["result"]["vrfs"]["default"]["peerGroups"]:
            showbgp = showbgp[0]["result"]["vrfs"]["default"]["peerGroups"][peergroup]
        elif "SUPER-SPINE" in showbgp[0]["result"]["vrfs"]["default"]["peerGroups"]:
            # case for SSP uplinked dsr
            showbgp = showbgp[0]["result"]["vrfs"]["default"]["peerGroups"]["SUPER-SPINE"]
        peers = str(len(showbgp["staticPeers"]))
        uppeers = 0
        for peer in showbgp["staticPeers"]:
            if showbgp["staticPeers"][peer]["peerState"] == "Established":
                uppeers += 1
        pstate = str(uppeers) + "/" + peers
        # print(switch + ": " +pstate)

    # set Unknown if eapi fails
    except:
        pstate = "unknown"

    if switches[switch]["peerstate"] != pstate:
        logit(str(switch) + " pstate is now " + pstate)

    return pstate


def getMmState(switch, switchmgmt):
    """Function to get and return maintenance mode state"""
    mmstate = ""
    # get Maintenance State
    try:
        node = pyeapi.connect_to(switchmgmt)
    except:
        logit(str(switchmgmt) + " failed EAPI connect")

    try:
        showmaintenance = node.enable("show maintenance")
        if "System" in showmaintenance[0]["result"]["units"]:
            mode = showmaintenance[0]["result"]["units"]["System"]["state"]
            # print("state in showmaintenance "+mode)
        else:
            mode = "Disabled"

        if mode == "active":
            if switches[switch]["maintmode"] != "NoMaint":
                logit(str(switch) + " is now NoMaint")
            mmstate = "NoMaint"
        elif mode == "maintenanceModeEnter":
            if switches[switch]["maintmode"] != "EnteringMaint":
                logit(str(switch) + " is now EnteringMaint")
            mmstate = "EnteringMaint"
        elif mode == "underMaintenance":
            if switches[switch]["maintmode"] != "UnderMaint":
                logit(str(switch) + " is now UnderMaint")
            mmstate = "UnderMaint"
        else:
            if switches[switch]["maintmode"] != "Disabled":
                logit(str(switch) + " is now Disabled")
            mmstate = "Disabled"
    # set unknown state if eapi fails
    except:
        mmstate = "Unknown"

    return mmstate


def getMlagState(switch, switchmgmt):
    """Function to get and return mlag state"""
    try:
        node = pyeapi.connect_to(switchmgmt)
    except:
        logit(str(switchmgmt) + " failed EAPI connect")

    try:
        showmlag = node.enable("show mlag | grep state", encoding="text")
        mlstate = showmlag[0]["result"]["output"].split(" : ")
        mlstate = mlstate[1].strip()
        mlstate = mlstate.lstrip()

    # set Uknown if eapi fails
    except:
        mlstate = "Unknown"

    return mlstate


def getStatus(switch):
    """Function get status from switch and log changes"""
    # init state
    mmstate, mlstate = "", ""
    # ping lo0
    output = subprocess.Popen(["ping", "-w", "1", "-c", "1", switch], stdout=subprocess.PIPE).communicate()[0]

    # Status for all non-msw
    if "msw" not in switch:
        # conditional for 3 and 4 digit site codes
        if len(switch.rsplit(".")[-1]) == 4:
            switchmgmt = switch[: len(switch) - 5] + ".mgmt" + switch[len(switch) - 5 :]
        else:
            switchmgmt = switch[: len(switch) - 4] + ".mgmt" + switch[len(switch) - 4 :]

        output2 = subprocess.Popen(["ping", "-w", "1", "-c", "1", switchmgmt], stdout=subprocess.PIPE).communicate()[0]
        if "100%" in str(output):
            ud1 = "Down"
        else:
            ud1 = "Up"
        if "100%" in str(output2):
            ud2 = "Down"
        else:
            ud2 = "Up"
        updown = ud1 + " / " + ud2
        if switches[switch]["updown"] != updown:
            logit(str(switch) + " is now " + updown)

        # Get BGP peer state
        if (updown == "Down / Up") or (updown == "Up / Up"):
            # Get maintenance mode
            mmstate = getMmState(switch, switchmgmt)
            # Get Pstate and Mlstate
            if "esr" in switch or "csr" in switch:
                pstate = getPeerStatus(switchmgmt, "UPLINK")
                mlstate = getMlagState(switch, switchmgmt)
            elif "ssp" in switch or "dsr" in switch:
                # assumes uplink to BSR. workaround in getPeerStatus
                pstate = getPeerStatus(switchmgmt, "BSR")
            else:
                pstate = switches[switch]["peerstate"]
        # keep existing state if dont match case
        elif updown == "Up / Down":
            pstate = switches[switch]["peerstate"]
            mmstate = switches[switch]["maintmode"]
            mlstate = switches[switch]["mlagstate"]
        # set state if switch is down
        else:
            pstate = "SwitchDown"
            mmstate = "SwitchDown"
            mlstate = "SwitchDown"

    # MSW status
    else:
        # ping status
        if "100%" in str(output):
            updown = "Down"
            pstate = "SwitchDown"
        else:
            updown = "Up"
            pstate = getPeerStatus(switch, "INTERNAL-MSR")
        if switches[switch]["updown"] != updown:
            logit(str(switch) + " is now " + updown)

    return updown, pstate, mmstate, mlstate


def main():
    global logfile
    global switches
    logfile = "./arista_status_%s.log" % datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    f1 = open(logfile, "w+")
    logit("Script Start")
    f1.close()

    inventory, mkeapi = getArgs()
    switches = getInventory(inventory)
    if mkeapi:
        makeEapiConf(switches)
        print("Created .eapi.conf")
        print("Now restart Script without eapi option")
        sys.exit()

    logit("Starting Status Checks")

    """Iterate over inventory"""
    while True:
        try:
            os.system("clear")
            os.system("date")
            time.sleep(1)
            print("Switch             \tlo0/mgmt\tPeerState\tMaintenance   \tMlag")
            print("-------------------\t------- \t---------\t-----------   \t----")
            # Print current contents of the dictionary
            for switch in switches:
                print(
                    switch.ljust(
                        24,
                    )
                    + switches[switch]["updown"].ljust(16)
                    + switches[switch]["peerstate"].ljust(16)
                    + switches[switch]["maintmode"].ljust(16)
                    + switches[switch]["mlagstate"]
                )
            # Collect new results
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_switch = {executor.submit(getStatus, switch): switch for switch in switches}
                for future in concurrent.futures.as_completed(future_to_switch):
                    switch = future_to_switch[future]
                    (
                        switches[switch]["updown"],
                        switches[switch]["peerstate"],
                        switches[switch]["maintmode"],
                        switches[switch]["mlagstate"],
                    ) = future.result()
            time.sleep(20)

        except KeyboardInterrupt:
            break

    logit("Status Checking Complete")

    return


if __name__ == "__main__":
    main()
