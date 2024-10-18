#!/usr/bin/python3
import sys
import os
import json
import time
import datetime
import subprocess
import argparse
import logging
import socket
import multiprocessing
from netopslib.gnmi import arista, nokia
from netopslib.netbox import nb_device
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor, TimeoutError


class SuppressSpecificErrorLogging(logging.Filter):
    def filter(self, record):
        # Suppress the specific log message
        if (
            "Corruption detected" in record.getMessage()
            or "SSL routines:OPENSSL_internal:SSLV3_ALERT_BAD_RECORD_MAC" in record.getMessage()
            or "The SSL certificate cannot be retrieved from" in record.getMessage()
            or "Stream removed" in record.getMessage()
            or "ssl_transport_security_utils.cc" in record.getMessage()
            or "Decryption error: TSI_DATA_CORRUPTED" in record.getMessage()
        ):
            return False

        if "Failed to setup gRPC channel, trying change cipher" in record.getMessage():
            return False
        return True


class deviceStatus:
    def __init__(self):
        # Checking the environment variable
        if not os.getenv("MONITORING_PW"):
            print("ERROR: Monitoring password Environment variable is not set")
            sys.exit()
        elif not os.getenv("NB_API_KEY") or not os.getenv("NB_URL"):
            print("ERROR: Netbox URL and NB API key Environment variable is not set")
            sys.exit()
        self.logfile = "./device_status_%s.log" % datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        inventory = self.getArgs()
        self.switches = self.getInventory(inventory)
        self.gnmi_arista = arista("monitoring", os.environ["MONITORING_PW"])
        self.gnmi_nokia = nokia("monitoring", os.environ["MONITORING_PW"])
        self.max_processes = 4  # Maximum number of simultaneus processes

    def logit(self, message):
        """Function accepts string and prints to logfile"""
        with open(self.logfile, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

    def device_mgmt_name(self, switch_string):
        # Initialize switch and switch_mgmt as the original input
        switch = switch_string
        switch_mgmt = switch_string

        # Check if the string starts with 'msw'
        if switch_string.startswith("msw"):
            # If it contains '.mgmt.' before the last '.', remove it
            if ".mgmt." in switch_string:
                switch = switch_string.replace(".mgmt.", ".", 1)
                switch_mgmt = switch
        else:
            # For other cases (non-msw strings)
            if ".mgmt." in switch_string:
                # If '.mgmt.' is already in the string, remove it to get the base switch name
                switch = switch_string.replace(".mgmt.", ".", 1)
            else:
                # Check if the string has more than one part separated by dots
                if "." in switch_string:
                    parts = switch_string.rsplit(".", 2)  # Split into up to three parts from the right
                    if len(parts) > 1 and parts[-2] != "mgmt":
                        # Create switch_mgmt by inserting 'mgmt' before the last section
                        switch_mgmt = (
                            f"{parts[0]}.{parts[1]}.mgmt.{parts[2]}"
                            if len(parts) == 3
                            else f"{parts[0]}.mgmt.{parts[1]}"
                        )
                else:
                    # Handle the special case like 'ssp2.ny5' or 'ssp2.mgmt.ny5'
                    parts = switch_string.split(".")
                    if len(parts) == 2:
                        # If the string has two parts like 'ssp2.ny5'
                        if parts[1] == "mgmt":
                            switch = f"{parts[0]}.{parts[1]}"
                            switch_mgmt = switch
                        else:
                            switch_mgmt = f"{parts[0]}.mgmt.{parts[1]}"
                    elif len(parts) == 3 and parts[1] == "mgmt":
                        # If the string is already like 'ssp2.mgmt.ny5', return base and mgmt forms
                        switch = f"{parts[0]}.{parts[2]}"
                        switch_mgmt = switch_string
                    else:
                        switch_mgmt = switch_string

        return switch, switch_mgmt

    def ping_device(self, switch):
        """Function to check the device reachability"""
        # Ping the device to check reachability
        ping_command = ["ping", "-w", "1", "-c", "1", switch]
        result = subprocess.run(ping_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode  # returns 0 when device is reachable

    def check_port_reachability(self, device_name: str, port: int = 6030):
        """Check if a specific port is reachable on device."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Timeout in seconds

        try:
            sock.connect((device_name, port))
            return True
        except socket.timeout:
            self.logit(f"{device_name} GNMI port time out")
            return False
        except socket.error as e:
            self.logit(f"{device_name} GNMI port Error {str(e)}")
            return False
        finally:
            sock.close()

    def getArgs(self):
        """Function to get the inventory argument"""
        parser = argparse.ArgumentParser(description="Process inventory file.")
        parser.add_argument("-i", "--inventory", required=True, help="Name of the inventory file")
        args = parser.parse_args()

        return args.inventory

    def getInventory(self, file):
        """
        Function to read inventory file and return dictionary
        """
        tmpdict = {}
        nb = nb_device(os.environ["NB_URL"], os.environ["NB_API_KEY"])
        default_values = {
            "updown": "Down/Down",
            "peerstate": "INIT",
            "scpeerstate": "INIT",
            "maintmode": "INIT",
            "mlagstate": "INIT",
            "version": "INIT",
            "svrPortState": "INIT",
        }
        msw_values = {
            "updown": "Down",
            "peerstate": "INIT",
            "scpeerstate": "INIT",
            "maintmode": "",
            "mlagstate": "",
            "version": "INIT",
            "svrPortState": "INIT",
        }
        with open(file) as f:
            for line in f:
                switch = line.rstrip().replace(".mgmt.", ".")
                dev_type = nb.get_device_manufacturer(switch)
                tmpdict[switch] = {"dev_type": dev_type}

                # Use msw_values if "msw" is in the switch name, otherwise use default_values
                tmpdict[switch].update(msw_values if "msw" in switch else default_values)

        self.logit(json.dumps(tmpdict, indent=4))
        return tmpdict

    def _count_peers(self, neighbors, peergroup):
        """Helper function to count peers based on peer group and session state"""
        total_peers = established_peers = 0

        for neighbor in neighbors:
            if neighbor["peer-group"] in peergroup:
                total_peers += 1
                if neighbor["session-state"] == "established":
                    established_peers += 1
        return total_peers, established_peers

    def getAristaPeerStatus(self, switch_mgmt, peergroup):
        """Function to get and return uplink/control nodes BGP peer state for Arista devices"""

        # Check if GNMI port is reachable
        if self.check_port_reachability(switch_mgmt) != True:
            return "GNMI", "DOWN"

        try:
            showbgp = self.gnmi_arista.get_arista_bgp_all_peers(switch_mgmt)  # Make GNMI request
        except Exception as e:
            self.logit(f"{switch_mgmt} Error: {str(e)} - Retrying...")
            time.sleep(5)
            try:
                showbgp = self.gnmi_arista.get_arista_bgp_all_peers(switch_mgmt)  # Retry GNMI request
            except Exception as e:
                self.logit(f"{switch_mgmt} Error: {str(e)} - Request failed")
                return "UNKNOWN", "UNKNOWN"

        # Initialize peer counts
        total_peers = established_peers = 0
        sc_total_peers = sc_established_peers = 0

        # Iterate through updates and count peers
        for update in showbgp.get("notification", [])[0].get("update", []):
            peer_group = update["val"].get("openconfig-network-instance:peer-group")
            session_state = update["val"].get("openconfig-network-instance:session-state")

            if peer_group in peergroup:
                total_peers += 1
                if session_state == "ESTABLISHED":
                    established_peers += 1

            if peer_group in ["MLAG-VRF-PACKET-INTERNAL", "SITE-CONTROLLER"]:
                sc_total_peers += 1
                if session_state == "ESTABLISHED":
                    sc_established_peers += 1

        # Generate peer state strings
        pstate = f"{established_peers}/{total_peers}"
        sc_pstate = f"{sc_established_peers}/{sc_total_peers}" if sc_total_peers else "-"

        return pstate, sc_pstate

    def getNokiaPeerStatus(self, switch_mgmt, peergroup):
        """Function to get and return uplink/control nodes BGP peer state for Nokia devices"""
        # Check if GNMI port is reachable
        if self.check_port_reachability(switch_mgmt) != True:
            return "GNMI", "DOWN"

        try:
            showbgp = self.gnmi_nokia.get_nokia_bgp_all_peers(switch_mgmt)  # Make GNMI request

            # Initialize peer counters
            site_controller_peers = established_site_controller_peers = 0
            uplink_peers = established_uplink_peers = 0

            # Iterate through network instances
            for network_instance in showbgp["notification"][0]["update"][0]["val"][
                "srl_nokia-network-instance:network-instance"
            ]:
                instance_name = network_instance["name"]
                neighbors = network_instance.get("protocols", {}).get("srl_nokia-bgp:bgp", {}).get("neighbor", [])

                if instance_name == "PACKET-INTERNAL-IP-VRF":
                    site_controller_peers, established_site_controller_peers = self._count_peers(
                        neighbors, "SITE-CONTROLLER"
                    )
                elif instance_name == "default":
                    uplink_peers, established_uplink_peers = self._count_peers(neighbors, peergroup)

            # Format peer state strings
            pstate = f"{established_uplink_peers}/{uplink_peers}"
            sc_pstate = f"{established_site_controller_peers}/{site_controller_peers}" if site_controller_peers else "-"

        except Exception as e:
            self.logit(f"{switch_mgmt} NOKIA BGP Peer GNMI Request failed: {str(e)}")
            return "UNKNOWN", "UNKNOWN"

        return pstate, sc_pstate

    def getSvrPortStatus(self, switch_mgmt, dev_type):
        """Function to get and return uplink/control nodes BGP peer state for Nokia devices"""
        if dev_type != "Nokia":
            return "-"

        if self.check_port_reachability(switch_mgmt) != True:  # Check if GNMI port is reachable
            return "GNMI-DOWN"

        target_port_desc = {"HARDWARE", "CUST", "DELIVERY"}
        total_ports = up_ports = 0

        try:
            ports_info = self.gnmi_nokia.get_nokia_interface(
                host=switch_mgmt, fields=["description", "admin-status", "oper-status"]
            )  # GNMI request to the device
            for name, details in ports_info.items():
                port_name = name
                description = details["description"].upper()
                if any(desc in description for desc in target_port_desc) and port_name.startswith("ethernet"):
                    total_ports += 1
                    if details["oper-status"] == "up" and details["admin-status"] == "enable":
                        up_ports += 1

        except Exception as e:
            self.logit(f"{switch_mgmt} NOKIA GNMI Port Status Request failed: {str(e)}")
            return "Error"

        return f"{up_ports}/{total_ports}"

    def getPeerStatus(self, switch, dev_type):
        """Function to get and return Site-Controller and uplink BGP peer state"""
        switch, switch_mgmt = self.device_mgmt_name(switch)

        peergroups = {
            "Arista": [
                "UPLINK",
                "V6-UPLINK",
                "MLAG",
                "V6-MLAG",
                "SUPER-SPINE",
                "V6-SUPER-SPINE",
                "VXLAN",
                "BSR",
                "INTERNAL-MSR",
            ],
            "Nokia": [
                "UPLINK",
                "V6-UPLINK",
                "TOR-PEER",
                "V6-TOR-PEER",
                "TOR-PEER-EVPN",
                "SUPER-SPINE",
                "V6-SUPER-SPINE",
                "VXLAN",
                "BSR",
                "INTERNAL-MSR",
            ],
        }

        if dev_type in peergroups:
            if dev_type == "Arista":
                pstate, sc_pstate = self.getAristaPeerStatus(switch_mgmt, peergroups[dev_type])
            elif dev_type == "Nokia":
                pstate, sc_pstate = self.getNokiaPeerStatus(switch_mgmt, peergroups[dev_type])

            # Log changes in peer state
            switch_data = self.switches[switch]
            if switch_data["peerstate"] != pstate:
                self.logit(f"{switch} pstate is now {pstate}")
            if switch_data["scpeerstate"] != sc_pstate:
                self.logit(f"{switch} SC pstate is now {sc_pstate}")

            return pstate, sc_pstate

        return None, None

    def getMmState(self, switch, switch_mgmt, dev_type):
        """Function to get and return maintenance mode state"""

        mmstate = "GNMI-DOWN" if self.check_port_reachability(switch_mgmt) != True else "UNKNOWN"

        state_mapping = {
            "Arista": {"active": "NoMaint", "maintenanceModeEnter": "EnteringMaint", "underMaintenance": "UnderMaint"},
            "Nokia": {"Disable": "NoMaint", "Enable": "UnderMaint"},
        }

        # Check device reachability
        if self.check_port_reachability(switch_mgmt) != True:
            return "GNMI-DOWN"

        try:
            if dev_type == "Arista":
                showmaintenance = self.gnmi_arista.get_arista_system_maintenance(switch_mgmt)
            elif dev_type == "Nokia":
                showmaintenance = self.gnmi_nokia.get_nokia_system_maintenance(switch_mgmt)
            else:
                return mmstate

            # Map state to the corresponding mode
            mmstate = state_mapping[dev_type].get(showmaintenance, "Disabled")

            # Log the change if the mode has been updated
            if self.switches[switch]["maintmode"] != mmstate:
                self.logit(f"{switch} is now {mmstate}")

        except:
            self.logit(f"{switch_mgmt} GNMI System Maintenance request failed")
            mmstate = "UNKNOWN"

        return mmstate

    def getMlagState(self, switch_mgmt, dev_type):
        """Function to get and return mlag state"""

        if dev_type != "Arista":
            return "-"

        if self.check_port_reachability(switch_mgmt) != True:
            return "GNMI-DOWN"

        try:
            mlagInfo = self.gnmi_arista.get_arista_mlag_status(switch_mgmt)
            mlstate = mlagInfo["mstatus"]

            # Check if any ports are error disabled
            if mlagInfo["errdisabled"]:
                return "ML Timer On"

            return mlstate
        except Exception as e:
            self.logit(f"{switch_mgmt} GNMI MLAG Request Failed - {e}")
            return "UNKNOWN"

    def getdeviceVersion(self, switch, dev_type):
        """Function to get and return current version"""
        # Determine management switch name
        switch, switch_mgmt = self.device_mgmt_name(switch)

        # Check device reachability
        if self.check_port_reachability(switch_mgmt) != True:
            return "GNMI-DOWN"

        try:
            if dev_type == "Arista":
                version = "EOS: " + self.gnmi_arista.get_arista_version(switch_mgmt)
            elif dev_type == "Nokia":
                version = "SRL: " + self.gnmi_nokia.get_nokia_version(switch_mgmt)
            else:
                raise ValueError("Unsupported device type")

        except Exception as e:
            self.logit(f"{switch} Version Request Failed: {e}")
            version = "UNKNOWN"

        # Log version change if necessary
        if self.switches.get(switch, {}).get("version") != version:
            self.logit(f"{switch} Version is now {version}")

        return version

    def getStatus(self, switch):
        """Function to get the status from switch and log changes."""
        # Determine management switch name
        switch, switch_mgmt = self.device_mgmt_name(switch)

        dev_type = self.switches[switch]["dev_type"]
        mmstate, mlstate, version, svrPortState = "", "", "", ""

        # Ping device
        output = self.ping_device(switch)
        output2 = self.ping_device(switch_mgmt) if "msw" not in switch else 0

        # Getting Firmware Version running on the device.
        version = self.getdeviceVersion(switch, dev_type)

        # Set updown status
        updown = (
            f"{'Down' if output != 0 else 'Up'} / {'Down' if output2 != 0 else 'Up'}"
            if "msw" not in switch
            else "Down" if output != 0 else "Up"
        )

        if self.switches[switch]["updown"] != updown:
            self.logit(f"{switch} is now {updown}")

        # Non-MSW Status
        if "msw" not in switch:
            if updown in ["Down / Up", "Up / Up"]:
                mmstate = self.getMmState(switch, switch_mgmt, dev_type)
                mlstate = self.getMlagState(switch_mgmt, dev_type) if "esr" in switch else ""
                pstate, sc_pstate = (
                    self.getPeerStatus(switch_mgmt, dev_type)
                    if any(role in switch for role in ["esr", "csr", "ssp", "dsr"])
                    else (self.switches[switch]["peerstate"], self.switches[switch]["scpeerstate"])
                )
                svrPortState = self.getSvrPortStatus(switch_mgmt, dev_type) if "esr" in switch else "-"
            else:
                # Preserve existing state if partial or complete down state
                pstate, sc_pstate, mmstate, mlstate, version, svrPortState = (
                    self.switches[switch][key]
                    for key in ["peerstate", "scpeerstate", "maintmode", "mlagstate", "version", "svrPortState"]
                )
                if updown == "Down / Down":
                    version, pstate, sc_pstate, mmstate, mlstate, svrPortState = (
                        "SwitchDown" if "Device Not Found" not in dev_type else dev_type,
                        "SwitchDown",
                        "SwitchDown",
                        "SwitchDown",
                        "SwitchDown",
                        "SwitchDown",
                    )

        # MSW Status
        else:
            if output != 0:
                updown = "Down"
                pstate, sc_pstate, svrPortState = "SwitchDown", "SwitchDown", "SwitchDown"
                version = "SwitchDown" if "Device Not Found" not in dev_type else dev_type
            else:
                pstate, sc_pstate = self.getPeerStatus(switch, dev_type)
                svrPortState = "-"

        return dev_type, version, updown, pstate, sc_pstate, mmstate, mlstate, svrPortState

    def create_switch_threads(self, switch_list, thread_data_queue):
        """Create and manage threads to get status for a list of switches."""
        thread_data = {}
        timeout_duration = 20
        with ThreadPoolExecutor(max_workers=40) as executor:  # CREATE THREADS
            futures = {executor.submit(self.getStatus, switch=switch): switch for switch in switch_list}

            for future in as_completed(futures):
                switch = futures[future]

                try:
                    dev_type, version, updown, pstate, sc_pstate, mmstate, mlstate, svrPortState = future.result(
                        timeout=timeout_duration
                    )
                except TimeoutError:
                    self.logit(f"{switch} - Thread exceeded {timeout_duration} seconds. Setting status to Error.")
                    dev_type = version = updown = pstate = sc_pstate = mmstate = mlstate = svrPortState = "Error"
                except Exception as e:
                    self.logit(f"{switch} - Error encountered: {str(e)}. Setting status to Error.")
                    dev_type = version = updown = pstate = sc_pstate = mmstate = mlstate = svrPortState = "Error"

                # dev_type,version,updown,pstate,sc_pstate,mmstate,mlstate,svrPortState=future.result(timeout=25)
                thread_data[switch] = {
                    "dev_type": dev_type,
                    "version": version,
                    "updown": updown,
                    "peerstate": pstate,
                    "scpeerstate": sc_pstate,
                    "maintmode": mmstate,
                    "mlagstate": mlstate,
                    "svrPortState": svrPortState,
                }

            thread_data_queue.put(thread_data)

    def process_switches(self, switch_list):
        # Thread data queue initialization
        thread_data_queue = multiprocessing.Queue()
        try:
            self.create_switch_threads(switch_list, thread_data_queue)
            thread_results = []
            while not thread_data_queue.empty():
                thread_results = thread_data_queue.get()
            return thread_results
        except Exception as e:
            print(f"An error occurred: {e}")
            self.logit(f"Error during thread initialization: {e}")
            return {
                switch: {
                    "updown": "Unknown",
                    "version": "Unknown",
                    "peerstate": "Unknown",
                    "scpeerstate": "Unknown",
                    "maintmode": "Unknown",
                    "mlagstate": "Unknown",
                    "svrPortState": "Unknown",
                }
                for switch in switch_list
            }

    def main(self):
        with open(self.logfile, "w+") as f1:
            self.logit("Script Start")

        inventory = self.getArgs()
        switches = self.getInventory(inventory)

        self.logit("Starting Status Checks")

        """Iterate over inventory"""
        while True:
            try:
                os.system("clear")
                print("Ctrl + C to end script")
                os.system("date")
                time.sleep(1)
                print(
                    "Switch             \tlo0/mgmt\tPeerState\tCN-CR   \tMaintenance   \tMlag    \tSvrPortState \tFirmware"
                )
                print(
                    "-------------------\t--------\t---------\t-----    \t-----------  \t----    \t------------ \t--------"
                )

                # Print current contents of the dictionary and allocate switches to different processes
                switchesPerThread = [[] for _ in range(self.max_processes)]
                for i, switch in enumerate(switches):
                    print(
                        switch.ljust(
                            24,
                        )
                        + switches[switch]["updown"].ljust(16)
                        + switches[switch]["peerstate"].ljust(16)
                        + switches[switch]["scpeerstate"].ljust(16)
                        + switches[switch]["maintmode"].ljust(16)
                        + switches[switch]["mlagstate"].ljust(16)
                        + switches[switch]["svrPortState"].ljust(16)
                        + switches[switch]["version"].ljust(16)
                    )
                    # Asign switches to processes
                    switchesPerThread[i % self.max_processes].append(switch)

                with ProcessPoolExecutor(max_workers=self.max_processes) as executor:
                    futures = [executor.submit(self.process_switches, switch_list) for switch_list in switchesPerThread]
                    for future, switch_list in zip(futures, switchesPerThread):
                        try:
                            # Wait for the process to complete, with a timeout of 25 seconds
                            thread_results = future.result(timeout=25)
                            if thread_results:
                                for switch, switch_data in thread_results.items():
                                    switches[switch].update(switch_data)
                        except TimeoutError:
                            # If a process takes more than 25 seconds, mark all its values as Unknown
                            for switch in switch_list:
                                switches[switch] = {
                                    "updown": "Unknown",
                                    "version": "Unknown",
                                    "peerstate": "Unknown",
                                    "scpeerstate": "Unknown",
                                    "maintmode": "Unknown",
                                    "mlagstate": "Unknown",
                                    "svrPortState": "Unknown",
                                }
                            self.logit(f"Timeout: Process for {switch_list} exceeded 25 seconds and was terminated.")
                            continue
                        except Exception as e:
                            # Handle any other exceptions to avoid freezing
                            self.logit(f"Error: Process for {switch_list} encountered an error: {str(e)}")
                            continue

                time.sleep(30)

            except KeyboardInterrupt:
                break

        self.logit("Status Checking Complete")
        return


if __name__ == "__main__":
    # Created a custom logger for pygnmi.client
    pygnmi_logger = logging.getLogger("pygnmi.client")
    pygnmi_logger.setLevel(logging.ERROR)

    # Custom filter to the pygnmi.client logger
    suppress_filter = SuppressSpecificErrorLogging()
    pygnmi_logger.addFilter(suppress_filter)

    # Handler to ensure the filter is applied correctly
    handler = logging.StreamHandler()
    handler.setLevel(logging.ERROR)
    handler.addFilter(suppress_filter)
    pygnmi_logger.addHandler(handler)

    instance = deviceStatus()
    instance.main()
