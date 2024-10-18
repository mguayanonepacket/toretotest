# Jose Carbonell
# v0.3
import pynetbox
import os
from requests.auth import HTTPBasicAuth
import pandas as pd
import requests
import re
import json
import pprint
from difflib import SequenceMatcher
from io import StringIO


def find_closest_match(input_value, options, min_similarity_ratio=0.29):
    # Use max() with a custom key function to find the option with the most matched characters
    input_value_lower = input_value.lower()
    options_lower = [str(option).lower() for option in options]
    similarities = [SequenceMatcher(None, input_value_lower, option).ratio() for option in options_lower]

    if not similarities:
        return None  # No valid match found

    # Find the option with the maximum similarity ratio (closest match)
    max_similarity = max(similarities)
    closest_match = options[similarities.index(max_similarity)]

    # Check if the maximum similarity ratio is above the minimum required
    if max_similarity < min_similarity_ratio:
        return None  # If not, consider it invalid
    return closest_match


def getGSCode(DevHWtype):
    # Function that gets the GS Code version for each device type from the WIki. Returns the GS code version for each device type.
    url = "https://equinixjira.atlassian.net/wiki/rest/api/content/145714063861?expand=body.storage"
    GSCode = {}
    jira_user = os.environ["JIRA_USER"]
    jira_token = os.environ["JIRA_TOKEN"]
    auth = HTTPBasicAuth(jira_user, jira_token)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = requests.request("GET", url, headers=headers, auth=auth)

    pds = pd.read_html(StringIO(response.json()["body"]["storage"]["value"]))

    wikiModels = []

    for table in pds:
        for row in table.iloc:
            if row["Hardware Type"] not in wikiModels and row["Hardware Type"] not in GSCode.keys():
                wikiModels.append(row["Hardware Type"])
                if not pd.isna(row["Test Version"]):
                    GSCode[row["Hardware Type"]] = row["Test Version"]
                else:
                    GSCode[row["Hardware Type"]] = row["Version"]
    model = find_closest_match(DevHWtype, wikiModels)

    return GSCode[model]


def getDevInterfacesNB(hostname):
    # Function that gets the interface infomation for the device provided as an arguments and returns a dictionary with the connected interfaces, the neighboring device and neighbor's port (it skips port connected to site controllers)
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    results = nb.dcim.interfaces.filter(device=hostname)

    n = 1
    devInterfaces = {}
    for interfaces in results:

        if bool(interfaces.connected_endpoints_reachable) == True and hasattr(
            interfaces.connected_endpoints[0], "device"
        ):

            if hasattr(
                interfaces.connected_endpoints[0].device, "name"
            ):  # Only the interfaces with connected_endpoints_reachable != NULL and skip interfaces connected to site controller servers
                if not interfaces.connected_endpoints[0].device.name.startswith("prod-") and not (
                    hasattr(interfaces.mode, "value")
                ):
                    devInterfaces[n] = {
                        "localHost": hostname,
                        "localInterface": interfaces.name,
                        "localInterfaceID": interfaces.id,
                        "neighbor": interfaces.connected_endpoints[0].device.name,
                        "neighborInterface": interfaces.connected_endpoints[0].name,
                        "mode": "physical",
                    }
                    n = n + 1

                elif not interfaces.connected_endpoints[0].device.name.startswith("prod-"):

                    devInterfaces[n] = {
                        "localHost": hostname,
                        "localInterface": interfaces.name,
                        "localInterfaceID": interfaces.id,
                        "neighbor": interfaces.connected_endpoints[0].device.name,
                        "neighborInterface": interfaces.connected_endpoints[0].name,
                        "mode": interfaces.mode.value,
                    }
                    n = n + 1

    return devInterfaces


def getDevLoopbacksNB(hostname):
    # Function that gets the interface infomation for the device provided as an arguments and returns a dictionary with the connected interfaces, the neighboring device and neighbor's port (it skips port connected to site controllers)
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    results = nb.ipam.ip_addresses.filter(device=hostname, role="loopback")
    n = 1
    devLoopbacks = {}
    for loopbacks in results:
        if loopbacks.assigned_object.name.find("lo2") != -1:
            if loopbacks.family.label == "IPv4":
                devLoopbacks[n] = {"localHost": hostname, "interface": "loopback2", "addr": loopbacks.address}
                n = n + 1
        else:
            if loopbacks.family.label == "IPv4":
                devLoopbacks[n] = {"localHost": hostname, "interface": "loopback0", "addr": loopbacks.address}
                n = n + 1

    return devLoopbacks


def getInterfaceIPaddresses(hostname, interfaceID):
    # Function that gets the ip address of a device interface. It returns a string of the ip address

    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    results = nb.ipam.ip_addresses.filter(device=hostname, interface_id=interfaceID)

    n = 1
    InterfaceIPAddr = {}

    for addrs in results:
        InterfaceIPAddr[n] = {"localInterfaceID": interfaceID, "Address": addrs.address}
        n = n + 1

    return InterfaceIPAddr


def getSNfromNB(hostname):
    # Function that gets the hostname (string) and returns the sn (string)
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    devices = nb.dcim.devices.get(name=hostname)
    sn = devices.serial

    return sn


def getNeighboringDSRs(hostname, dsrs, numDSR):
    # Function used to derived the dsrs from the dsrs if the rack option is used. This fucntion is only called from getDevsNB. Returns a dictionary with the
    # dsr information and a variable with the number of dsrs
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    results = nb.dcim.interfaces.filter(device=hostname)

    for interfaces in results:

        if bool(interfaces.connected_endpoints_reachable) == True and hasattr(interfaces.connected_endpoint, "device"):

            if hasattr(
                interfaces.connected_endpoint.device, "name"
            ):  # ONLY THE INTERFACES WITH connected_endpoints_reachable != NULL and skip interfaces connected to site controller servers
                if interfaces.connected_endpoint.device.name.find("dsr") != -1:

                    list_of_all_values = [value for elem in dsrs.values() for value in elem.values()]
                    if interfaces.connected_endpoint.device.name not in list_of_all_values:
                        device = nb.dcim.devices.get(name=interfaces.connected_endpoint.device.name)
                        dsrs[numDSR] = {
                            "hostname": device.name,
                            "IP": device.primary_ip4.address,
                            "type": device.device_type.manufacturer.name,
                            "model": device.device_type.model,
                        }
                        numDSR = numDSR + 1

    return dsrs, numDSR


def getNeighboringMSRs(hostname, msrs, numMSR):
    # Function used to derived the dsrs from the msrs if the rack option is used. This fucntion is only called from getDevsNB. Returns a dictionary with the
    # msr information and a variable with the number of msrs
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    results = nb.dcim.interfaces.filter(device=hostname)

    for interfaces in results:

        if bool(interfaces.connected_endpoints_reachable) == True and hasattr(interfaces.connected_endpoint, "device"):

            if hasattr(
                interfaces.connected_endpoint.device, "name"
            ):  # ONLY THE INTERFACES WITH connected_endpoints_reachable != NULL and skip interfaces connected to site controller servers
                if interfaces.connected_endpoint.device.name.find("msr") != -1:
                    list_of_all_values = [value for elem in msrs.values() for value in elem.values()]
                    if interfaces.connected_endpoint.device.name not in list_of_all_values:
                        device = nb.dcim.devices.get(name=interfaces.connected_endpoint.device.name)
                        msrs[numMSR] = {
                            "hostname": device.name,
                            "IP": device.primary_ip4.address,
                            "type": device.device_type.manufacturer.name,
                            "model": device.device_type.model,
                        }
                        numMSR = numMSR + 1

    return msrs, numMSR


def getDevsNB(siteName, pod, rackList, device):
    # Function that gets all the devices from Netbox according the the options provided as an argument. Returns several dictionaries with all the device
    # information classified by role (drs, msr, bbr ...) and variables with the number of devices in each role
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    if device:
        devices = nb.dcim.devices.filter(site=siteName, name=device)
    else:
        devices = nb.dcim.devices.filter(site=siteName)

    numDSR = 1
    numESR = 1
    numBSR = 1
    numBBR = 1
    numMDR = 1
    numMSR = 1
    numMSW = 1
    numFW = 1
    numCSR = 1
    numMRR = 1
    numSSP = 1
    numCSS = 1
    numPDU = 1
    dsrs = {}
    esrs = {}
    bsrs = {}
    bbrs = {}
    mdrs = {}
    msrs = {}
    msws = {}
    fws = {}
    csrs = {}
    mrrs = {}
    ssps = {}
    css = {}
    pdus = {}

    for device in devices:

        if (
            device.name.find("cp") == -1
            and device.name.find("lg") == -1
            and device.name.find("prod-") == -1
            and device.name.find("euse") == -1
            and device.name.find("network-utils") == -1
            and (device.status.value == "active" or device.status.value == "staged")
        ):
            hostname = device.name
            rack = device.rack.name

            if not (bool(device.primary_ip4) == True):
                ip = ""

            else:
                ip = device.primary_ip4.address

            deviceType = device.device_type.manufacturer.name
            deviceModel = device.device_type.model

            # NODE DEFINITION
            if len(rackList) == 0:  # If no racks passed as arguments for the script
                if hostname.find("dsr") != -1 and hostname.find(pod) != -1:

                    dsrs[numDSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numDSR = numDSR + 1

                elif hostname.find("esr") != -1 and hostname.find(pod) != -1:

                    esrs[numESR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numESR = numESR + 1

                elif hostname.find("bsr") != -1 and hostname.find(pod) != -1:

                    bsrs[numBSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numBSR = numBSR + 1

                elif hostname.find("bbr") != -1 and hostname.find(pod) != -1:

                    bbrs[numBBR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numBBR = numBBR + 1

                elif hostname.find("mdr") != -1 and hostname.find(pod) != -1:

                    mdrs[numMDR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMDR = numMDR + 1

                elif hostname.find("msr") != -1 and hostname.find(pod) != -1:

                    msrs[numMSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMSR = numMSR + 1

                elif hostname.find("msw") != -1 and hostname.find(pod) != -1:

                    msws[numMSW] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMSW = numMSW + 1

                elif hostname.find("fw") != -1 and hostname.find(pod) != -1:

                    fws[numFW] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numFW = numFW + 1

                elif hostname.find("csr") != -1 and hostname.find(pod) != -1:

                    csrs[numCSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numCSR = numCSR + 1

                elif hostname.find("mrr") != -1 and hostname.find(pod) != -1:

                    mrrs[numMRR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMRR = numMRR + 1

                elif hostname.find("ssp") != -1 and hostname.find(pod) != -1:

                    ssps[numSSP] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numSSP = numSSP + 1

                elif re.findall(r"cs[0-9].", hostname, re.I) and hostname.find(pod) != -1:

                    css[numCSS] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numCSS = numCSS + 1

                elif hostname.find("pdu") != -1 and hostname.find(pod) != -1:

                    pdus[numPDU] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numPDU = numPDU + 1

            else:  # If racks are passed as an argument of the script

                if hostname.find("dsr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    dsrs[numDSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numDSR = numDSR + 1

                elif hostname.find("esr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    esrs[numESR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numESR = numESR + 1
                    dsrs, numDSR = getNeighboringDSRs(hostname, dsrs, numDSR)

                elif hostname.find("bsr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    bsrs[numBSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numBSR = numBSR + 1

                elif hostname.find("bbr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    bbrs[numBBR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numBBR = numBBR + 1

                elif hostname.find("mdr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    mdrs[numMDR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMDR = numMDR + 1

                elif hostname.find("msr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    msrs[numMSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMSR = numMSR + 1

                elif hostname.find("msw") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    msws[numMSW] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMSW = numMSW + 1
                    msrs, numMSR = getNeighboringMSRs(hostname, msrs, numMSR)

                elif hostname.find("fw") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    fws[numFW] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numFW = numFW + 1

                elif hostname.find("csr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    csrs[numCSR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numCSR = numCSR + 1

                elif hostname.find("mrr") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    mrrs[numMRR] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numMRR = numMRR + 1

                elif hostname.find("ssp") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    ssps[numSSP] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numSSP = numSSP + 1

                elif (
                    re.findall(r"cs[0-9].", hostname, re.I)
                    and hostname.find(pod) != -1
                    and rack.split(".")[0] in rackList
                ):

                    css[numCSS] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numCSS = numCSS + 1

                elif hostname.find("pdu") != -1 and hostname.find(pod) != -1 and rack.split(".")[0] in rackList:

                    pdus[numPDU] = {"hostname": hostname, "IP": ip, "type": deviceType, "model": deviceModel}
                    numPDU = numPDU + 1

    return (
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
    )


def compareInterfaces(i1, i2):
    # Function that recieves the dictionario of the Netbox interfaces and the diccionario of the interfaces derived from LLDP and compares them.
    # It returns or eaither an empty dictionary or a dicctionary with the interfaces that don't match
    noMatch = {}
    matchIndex = 1
    noMatchIndex = 1
    for n in i1.keys():
        lastMatchIndex = matchIndex
        for i in i2.keys():

            if (
                (str(i1[n]["localHost"]) == str(i2[i]["localHost"]))
                and (str(i1[n]["localInterface"]) == str(i2[i]["localInterface"]))
                and (str(i1[n]["neighbor"]).replace(".packet.net", "") == str(i2[i]["neighbor"]))
                and (str(i1[n]["neighborInterface"]) == str(i2[i]["neighborInterface"]))
            ):
                matchIndex = matchIndex + 1
                break
        if lastMatchIndex == matchIndex:
            noMatch[noMatchIndex] = {
                "localHost": i1[n]["localHost"],
                "localInterface": i1[n]["localInterface"],
                "neighbor": str(i1[n]["neighbor"]).replace(".packet.net", ""),
                "neighborInterface": i1[n]["neighborInterface"],
            }
            noMatchIndex = noMatchIndex + 1

    return noMatch


def convert2List(dic, num, hostnameList, deviceModelList, deviceTypeList, usernameList, username, siteName, siteList):
    # Function used to convert the dictionaries into lists and update the lists that are used to generate the threads for the devices.
    for n in range(1, num):
        hostnameList.append(dic[n]["hostname"])
        deviceModelList.append(dic[n]["model"])
        siteList.append(siteName)
        if dic[n]["type"] == "Arista":
            deviceTypeList.append("arista_eos")
            usernameList.append("admin")
        elif dic[n]["type"] == "Nokia":
            deviceTypeList.append("sr_linux")
            usernameList.append("packetbot")
        elif dic[n]["type"] == "Juniper":
            deviceTypeList.append("juniper_junos")
            usernameList.append(username)
        elif dic[n]["type"] == "Opengear":
            deviceTypeList.append("o_linux")
            usernameList.append("root")
        elif dic[n]["type"] == "ServerTech":
            deviceTypeList.append("s_linux")
            usernameList.append("admn")

    return hostnameList, deviceModelList, deviceTypeList, usernameList, siteList


def NBgetTags(host):
    # Function that get the tags on the device and return a list
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    results = nb.dcim.devices.filter(name=host)
    devTags = []
    for value in results:
        for tag in value.tags:
            devTags.append(str(tag))
    return devTags


def NBgetNameFromIP(ip):
    # This function returns the name of a devices given an ip
    nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
    results = nb.ipam.ip_addresses.filter(address=ip)
    for values in results:
        devName = str(values.assigned_object.device.name)
    return devName
