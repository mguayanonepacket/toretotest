# Jose Carbonell
# v0.2

import time
from pathlib import Path
import os.path
import os
import pyeapi
import shutil
from ncclient import manager
import subprocess
import shlex
from jnpr.junos import Device, command
from TestFunctions import *
from NBFunctions import *
from postchecks_con_pdu import O_S_device
import concurrent.futures
from concurrent.futures import TimeoutError
from multiprocessing import Pool
import argparse
from pygnmi.client import gNMIclient
import logging
import requests


def getRackList(rackListProvided):
    rackList = []
    coreRack = False
    for item in rackListProvided:
        if item.find("core") != -1:

            rackRange = item.strip("core").split("-")
            coreRack = True

        else:
            rackRange = item.strip("rk").split("-")
        if len(rackRange) == 1:  # Only one rack is passed as an argument
            if coreRack:
                rackList.append("core" + str(rackRange[0]).zfill(1))
            else:
                rackList.append("rk" + str(rackRange[0]).zfill(2))

        else:  # Rack range passed as an argument

            tmpRackList = list(range(int(rackRange[0]), int(rackRange[1]) + 1))
            if coreRack:
                for i in range(0, len(tmpRackList)):
                    rackList.append("core" + str(tmpRackList[i]).zfill(1))
            else:
                for i in range(0, len(tmpRackList)):
                    rackList.append("rk" + str(tmpRackList[i]).zfill(2))

    return rackList


def getArguments():
    # Function that gets the arguments and depending of the options returns the variablos required to execute the different iptions. Ir return the username used for JUniper devices, site name,
    # pod, rack range and a variable onlyCreateFile that is used when the script only needs to generate the EAPI config file.

    # Construct an argument parser
    all_args = argparse.ArgumentParser()

    # Add arguments to the parser
    all_args.add_argument(
        "-c", "--ConfigFile", help="Create the EAPI config file for Arista devices", action="store_true"
    )
    all_args.add_argument(
        "-r", "--Racks", required=False, help="Introduce single rack or a rack range (ex. -r rk05 or -r rk05-6)"
    )
    all_args.add_argument("-s", "--Site", required=True, help="Introduce site name (ex. -s fr2)", default=False)
    all_args.add_argument("-p", "--Pod", required=False, help="Introduce pod number (ex. -p 1)", default=False)
    all_args.add_argument(
        "-u", "--User", default=os.getenv("USER"), help="Introduce the username for Juniper devices (ex. -u myuser)"
    )
    all_args.add_argument("-d", "--Device", required=False, help="Introduce the hostname of the device")

    args = vars(all_args.parse_args())

    username = args["User"].lower()
    siteName = args["Site"].lower()
    coreRack = False
    racks = ""
    device = ""

    # Get the hostname of the device we want to run post-checks on
    if args["Device"]:
        device = args["Device"]

    # Get the pod if provided as an argument
    if args["Pod"]:
        pod = "p0" + str(args["Pod"])
    else:
        pod = ""

    # Find the rack range if provided as an argument
    if args["Racks"]:
        racks = getRackList(args["Racks"].split(","))

    # If -c option is provided, this will create the EAPI config only. No check will be made.
    if args["ConfigFile"]:

        onlyCreateFile = True

    else:

        onlyCreateFile = False

    return onlyCreateFile, racks, username, siteName, pod, device


def append_multiple_lines(file_name, lines_to_append):

    with open(file_name, "a+") as file_object:
        appendEOL = False
        file_object.seek(0)

        data = file_object.read()
        if len(data) > 0:
            appendEOL = True

        for line in lines_to_append:
            # If file is not empty then append '\n' before first line for
            # other lines always append '\n' before appending line
            if appendEOL == True:
                file_object.write("\n")
            else:
                appendEOL = True

            file_object.write(line)
        file_object.close()

    return


def threadRunTests(host, deviceType, username, siteName, deviceModel):
    # Function that runs all the tests for each of the threads. Returns a string to report if the post-checks were successful or not.
    print("Starting post-checks for", host)

    if checkReachability(host, deviceType):

        if deviceType == "s_linux" or deviceType == "o_linux":  # Servertech and opengear devices
            conn = ""  # connection api are defined in the postchecks_con_pdu file
            errorsFound = False
            testResult = checkRancidTag(
                conn, host, deviceType
            )  # TEST 14 check rancid tag for the devices. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True
            testResult = O_S_device(host, getGSCode(deviceModel))
            if not testResult:
                errorsFound = True
        else:
            logging.getLogger("pygnmi").setLevel(logging.ERROR)
            if deviceType == "arista_eos":  # ARISTA DEVICES
                deviceOS = deviceType
                try:
                    conn = pyeapi.connect_to(host)

                except:
                    print(
                        "\nWARNING: Connection to the device "
                        + host
                        + " failed. Check username or password or try again later\n"
                    )
                    sys.exit("Connection failure for the device " + host + ". No checks were made.")

            if deviceType == "juniper_junos":  # JUNIPER DEVICES
                deviceOS = deviceType
                conn = Device(
                    host=host,
                    ssh_private_key_file=str(Path.home()) + "/.ssh/" + str(os.environ["RSA_KEY_NAME"]),
                    huge_tree=True,
                )  ### CREATE

                try:
                    conn.open()
                    conn.timeout = 60

                except:
                    print(
                        "\nWARNING: Connection to the device "
                        + host
                        + " failed. Check username or password or try again later\n"
                    )
                    sys.exit("Connection failure for the device " + host + ". No checks were made.")

            if deviceType == "sr_linux":  # NOKIA DEVICES
                deviceOS = deviceType
                conn = ""  # Connection is not required as gnmi is used to get the information
                # Disable SSL warnings from pygnmi

            # Start with the tests
            errorsFound = False
            testResult = checkGSVersion(
                conn, host, getGSCode(deviceModel), deviceType
            )  # TEST 1 check Software version. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkDevSNNB(
                conn, host, deviceType
            )  # TEST 2 Check serial number. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkDevInterfacesNB(
                conn, host, deviceType, siteName
            )  # TEST 3 Check interfaces match NB interfaces. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkInterfacesStatus(
                conn, host, deviceType
            )  # TEST 4 Check interface status. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkIntOptPWLevels(
                conn, host, deviceType
            )  # TEST 5 Check interface optic power levels. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkDevLogs(
                conn, host, deviceType
            )  # TEST 6 Check interfaces flapping in logs. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkEnvironment(
                conn, host, deviceType
            )  # TEST 7 Check environment. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkBGPNeighbors(
                conn, host, deviceType
            )  # TEST 8 Check bgp neighbor status. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkInterfaceErrors(
                conn, host, deviceType
            )  # TEST 9 ping flood and check interface errors. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkAristaAliases(
                conn, host, deviceType
            )  # TEST 10 check if all the aliases are configured on the Arista devices. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkLo2IPAddresses(
                conn, host, deviceType
            )  # TEST 11 checks the Lo2 ip address are the same in esra and esrb (in Netbox and configured on the devices) and Lo2 configured for csrs. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkSflowAndMTU(
                conn, host, deviceType
            )  # TEST 12 checks sflow on transit/pni/ix conections and jumbo MTU value. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkNHdefault(
                conn, host, deviceType
            )  # TEST 13 check NH for the default route on vrf PACKET INTERNAL to be the ip of the BBR. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkRancidTag(
                conn, host, deviceType
            )  # TEST 14 check rancid tag for the devices. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkPacketbotUser(
                conn, host, deviceType
            )  # TEST 15 check if packetbot user is configured on Nokia devices. It returns True if sucessful, False if errors found
            if not testResult:
                errorsFound = True

            testResult = checkHostsFiles(
                conn, host, deviceType
            )  # TEST 16 check if the device has been added on /etc/hosts file
            if not testResult:
                errorsFound = True

            testResult = checkMswDhcpRelay(
                conn, host, deviceType
            )  # TEST 17 check dhcp helper is set correctly on the msw
            if not testResult:
                errorsFound = True

        if errorsFound:
            if deviceType == "juniper_junos":
                conn.close()
            return "Post-checks failed for " + host + " - Check the report in REPORT folder for details"

        else:

            if deviceType == "juniper_junos":
                conn.close()
            return "Post-checks completed successfully for " + host
    else:

        return "Post-checks failed for " + host + " - device unreachable. No checks will be made."


def createAristaAPIConfigFile(devices, numDevices):
    # Creates the EAPI config file using the Arista device information provided as an argument. It does not return anything
    for n in range(1, numDevices):
        if devices[n]["type"] == "Arista":
            password = os.environ["ARISTA_PW"]
            lines2append = [
                "[connection:" + devices[n]["hostname"] + "]",
                "host: " + devices[n]["hostname"],
                "transport: https",
                "username: admin",
                "password: " + password,
            ]
            append_multiple_lines(str(Path.home()) + "/.eapi.conf", lines2append)

    return


def getNokiaInformation(host, infoPath):
    targetDevice = (host, "6030")
    with gNMIclient(
        target=targetDevice, username="monitoring", password=os.environ["MONITORING_PW"], skip_verify=True
    ) as gc:
        result = gc.get(path=[infoPath])
    return result


if __name__ == "__main__":

    if len(sys.argv) - 1 < 2:

        print("::HELP::")
        print(
            "Usage: postchecks -s {site name} [-r {racks}] [-p {pod number}] [-u {username}]  [-d {device name}] [-c ] \n"
        )
        print("Params:\n")
        print(
            "-c option to generate the Arista Config file - Required for the first run to avoid EAPI connection errors \n"
        )
        print(
            "-u username user for Juniper devices. This argument is optional. If not provided, it will use your linux username.\n"
        )
        print("-s site name. This argument is mandatory\n")
        print("-p pod number. This argument is optional. If not defined, both pods will be done\n")
        print("-d device name. This argument is optional. It runs post-checks only on the provided device \n")
        print(
            "-r rack or rack range. This argument is optional. If defined, only the devices of those racks will be checked along with neighboring devices\n"
        )
        print("- Example: Postchecks -s tr2 -u jcarbonell -c \n")
        print("- STEP 1: Postchecks -s tr2 -u jcarbonell -c \n")
        print("- STEP 2: Postchecks -s tr2 -u jcarbonell\n")
        print(
            "- More examples here: https://github.com/packethost/networkOperations/blob/master/Deployments/postchecks/README.md \n"
        )

        sys.exit(0)

    else:

        racks = []
        coreRack = False
        # Get arguments
        onlyCreateFile, racks, username, siteName, pod, device = getArguments()

        # Get devices depending on the arguments provided
        (
            dsrs,
            numDSR,
            esrs,
            numESR,
            bsrs,
            numBSR,
            bbrs,
            numBBR,
            mdrs,
            numMDR,
            msrs,
            numMSR,
            msws,
            numMSW,
            fws,
            numFW,
            csrs,
            numCSR,
            mrrs,
            numMRR,
            ssps,
            numSSP,
            css,
            numCSS,
            pdus,
            numPDU,
        ) = getDevsNB(siteName, pod, racks, device)

        if not onlyCreateFile:

            # Creation of lists of devices/sites/usernames that will be used to create the threads afterwards
            hostnameList = []
            deviceModelList = []
            deviceTypeList = []
            usernameList = []
            siteList = []
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                dsrs, numDSR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                esrs, numESR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                bbrs, numBBR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                bsrs, numBSR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                csrs, numCSR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                mdrs, numMDR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                msrs, numMSR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                msws, numMSW, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                ssps, numSSP, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                fws, numFW, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                mrrs, numMRR, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                css, numCSS, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )
            hostnameList, deviceModelList, deviceTypeList, usernameList, siteList = convert2List(
                pdus, numPDU, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList
            )

            print("\n ###################################################################################")
            print(" ## Post-check script for Juniper, Arista, Nokia, Opengear and ServerTech devices ##")
            print(" ###################################################################################\n")
            # Create report file
            createMSExcelReport(hostnameList, deviceTypeList)

            # #Thread creation
            with concurrent.futures.ThreadPoolExecutor(10) as pool:
                # Iterate the results from map performed in separate threads, wait a limited time for the thread responses (15000 seg)
                try:
                    for result in pool.map(
                        threadRunTests,
                        hostnameList,
                        deviceTypeList,
                        usernameList,
                        siteList,
                        deviceModelList,
                        timeout=20000,
                    ):
                        print(result)

                except TimeoutError:
                    print("Waited too long for: " + str(result))

            # Consolidates all the MS Excel reports in one file (It was done in separate Excel filesper device because there are issues when multiple threads try to write to one common file)
            if mergeMSExcelReports():
                print("Post-check report created sucessfully.")
            else:
                print("Error while creating the Post-check report.")

            # Clean temporary files
            if os.path.exists(str(Path.home()) + "/.eapi.conf") == True:

                r = os.remove(str(Path.home()) + "/.eapi.conf")

            if os.path.exists("EXCELREPORTS") == True:
                r = shutil.rmtree("EXCELREPORTS")

        else:

            # EAPI Conf file creation for Arista devices

            print("\n #############################################################")
            print(" ## Post-check script for Juniper, Arista and Nokia devices ##")
            print(" #############################################################\n")

            if (
                os.path.exists(str(Path.home()) + "/.eapi.conf") == True
            ):  # If a previous config file exists, it is deleted
                r = os.remove(str(Path.home()) + "/.eapi.conf")

            createAristaAPIConfigFile(dsrs, numDSR)
            createAristaAPIConfigFile(esrs, numESR)
            createAristaAPIConfigFile(msws, numMSW)
            createAristaAPIConfigFile(csrs, numCSR)
            createAristaAPIConfigFile(ssps, numSSP)
            createAristaAPIConfigFile(msrs, numMSR)

            if os.path.exists(str(Path.home()) + "/.eapi.conf") == True:
                print("EAPI Config file created successfully. Please, re-run the script without the option -c.")

        print("\n[END]\n")
