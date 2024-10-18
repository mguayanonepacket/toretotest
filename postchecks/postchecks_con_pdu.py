import pynetbox
import paramiko
import requests
import json
import re
import concurrent.futures
import threading
import sys
import base64
import TestFunctions
import subprocess
import ipaddress
import time
import os
import hashlib
from datetime import datetime

conn = ""
output_lock = threading.Lock()
utc_time = datetime.utcnow()

# <--To ignore certificate errors-->
import urllib3

urllib3.disable_warnings()
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":HIGH:!DH:!aNULL"
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ":HIGH:!DH:!aNULL"
except AttributeError:
    pass
# <----------------------------!
# <--Netbox Variables-->
for CheckVars in ["NB_URL", "NB_API_KEY", "OPEN_PASS", "PDU_PASS"]:
    if not os.getenv(CheckVars):
        print("ERROR: Environment variable " + CheckVars + " is not set")
        sys.exit()

nb = pynetbox.api(os.environ["NB_URL"], os.environ["NB_API_KEY"])  # calling pynetbox api


def is_private_ipv4(ip):  # Check if the given IPv4 address is private or not.
    try:
        ip_addr = ipaddress.IPv4Address(ip)
        return ip_addr.is_private
    except ValueError:
        return False


class Opengear:
    def __init__(self, nb_info, firmware):
        # Initializing variables to reuse within class
        self.nb_name = str(nb_info.name)
        self.nb_model = str(nb_info.device_type)
        self.nb_serial = str(nb_info.serial)
        self.nb_ip4 = str(nb_info.primary_ip4.address)
        self.ip_id = str(nb_info.primary_ip4.id)
        self.firm = firmware
        self.upgrading = 0
        self.upgrade_required = False
        self.serial_match = None

        # initiating API session
        self.session = requests.session()
        self.session.verify = False
        base_url = "https://" + self.nb_name + ".packet.net/api/v1.5"

        # Getting SESSION ID for making API requests
        self.auth_url = f"{base_url}/sessions"
        self.payload = json.dumps({"username": "root", "password": os.environ["OPEN_PASS"]})
        self.content_type = {"Content-Type": "application/json"}
        auth_response = self.session.post(self.auth_url, headers=self.content_type, data=self.payload)
        if auth_response.status_code != 200:  # Calling API Error handling functions in case response is not 200
            getattr(self, f"code_{str(auth_response.status_code)}")(self.nb_name)
        self.session_id = auth_response.json()["session"]  # This SESSION ID is required for making all API requests.

        # Initializing valiables required to make API request
        self.headers = {"Authorization": f"Token {self.session_id}", "Content-Type": "application/json"}
        self.serial_url = f"{base_url}/serialPorts"
        self.node_url = f"{base_url}/nodeDescription"
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Submit each function to the executor
            futures = [executor.submit(func) for func in [self.get_nodes, self.get_ports, self.pmshell_check]]

            # Wait for all futures to complete
            concurrent.futures.wait(futures)

    # Functions For the API Error handling
    def code_304(self, dev):
        errors = {"Error 304": f"Error 304 - {dev} is too busy, please try again in a while"}
        TestFunctions.printReport(conn, dev, "Test 1 failed for " + dev, errors, "-", "other")
        return False

    def code_400(self, dev):
        errors = {"Error 400": f"Error 400 - Invalid request for {dev}"}
        TestFunctions.printReport(conn, dev, "Test 1 failed for " + dev, errors, "-", "other")
        return False

    def code_401(self, dev):
        errors = {"Error 401": f"Error 401 - Authentication failure for device {dev}"}
        TestFunctions.printReport(conn, dev, "Test 1 failed for " + dev, errors, "-", "other")
        return False

    def code_404(self, dev):
        errors = {"Error 404": f"Error 404 - Requested {dev} does not exist or is unavailable"}
        TestFunctions.printReport(conn, dev, "Test 1 failed for " + dev, errors, "-", "other")
        return False

    def code_500(self, dev):
        errors = {"Error 500": f"Error 500 - Internal Error for device {dev}"}
        TestFunctions.printReport(conn, dev, "Test 1 failed for " + dev, errors, "-", "other")
        return False

    def compare_versions(self, nb_ver, dev_ver):
        v1_components = nb_ver.split(".")
        v2_components = dev_ver.split(".")
        for v1_comp, v2_comp in zip(v1_components, v2_components):
            # Check if both components are numeric
            if v1_comp.isdigit() and v2_comp.isdigit():
                v1_comp = int(v1_comp)
                v2_comp = int(v2_comp)
                if v1_comp > v2_comp:
                    return "Upgrade"
                elif v1_comp < v2_comp:
                    return "Downgrade"
            else:
                # If one of the components is non-numeric
                if v1_comp > v2_comp:
                    return "Upgrade"
                elif v1_comp < v2_comp:
                    return "Downgrade"
                # If both components are equal, continue to the next component

        # If all components are equal, return the longer version as the greater version
        if len(v1_components) > len(v2_components):
            return "Upgrade"
        elif len(v1_components) < len(v2_components):
            return "Downgrade"

    def get_nodes(
        self,
    ):  # This function handles the IPV4, Device Model, Device Serial, Hostname & Firmware details. Also upgrade the OS if not in Gold Master version
        try:
            if is_private_ipv4(self.nb_ip4[:-3]):  # Getting the private IP address from Netbox
                ipv4 = self.nb_ip4[:-3]
            else:
                ip = nb.ipam.ip_addresses.get(self.ip_id)
                if ip.nat_inside:
                    ipv4 = ip.nat_inside.address[:-3]
                else:
                    ipv4 = "No private ip updated in NETBOX"
            # Creating Netbox Dictionary for comparision
            nb_dict = {
                "4 Serial": self.nb_serial,
                "2 Model": self.nb_model,
                "3 IPv4": ipv4,
                "5 Hostname": self.nb_name,
                "6 Firmware": self.firm,
            }

            # Calling Opengear API with nodeDescription to retrieve run-time details about the device
            node_response = self.session.get(self.node_url, headers=self.headers, timeout=10)
            if node_response.status_code != 200:  # Calling API Error handling functions in case response is not 200
                getattr(self, f"code_{str(node_response.status_code)}")(self.nb_name)
            node_output = json.loads(node_response.content)
            ipv4_addresses = set()
            for interface in node_output["interfaces"]:
                for ipv4_address in interface["ipv4_addresses"]:
                    ipv4_addresses.add(ipv4_address)

            # Creating Device dictionary with retrieved values from API for the comparision with Netbox Dictionary
            device_dict = {
                "4 Serial": node_output["serial_number"],
                "2 Model": node_output["model_number"],
                "3 IPv4": ipv4_address,
                "5 Hostname": node_output["hostname"],
                "6 Firmware": node_output["firmware_version"],
            }
            # Comparing the Netbox and Device Dictionaries.
            for key in nb_dict:
                if key in device_dict and nb_dict[key] != device_dict[key]:
                    errors = {key: f"MISMATCH Netbox: {nb_dict[key]} and Device: {device_dict[key]}"}
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} failed for " + self.nb_name, errors, " - ", "other"
                    )

                    if key == "4 Serial":
                        self.serial_match = False
                    if key == "2 Model" or key == "3 IPv4":
                        self.update_nb(key, device_dict[key])
                    # If firmware mismatch, wait for all other checks to finish and upgrade
                    if key == "6 Firmware":
                        U_action = self.compare_versions(nb_dict[key], device_dict[key])
                        self.upgrading += 1
                        self.upgrade_required = True
                        while self.upgrading < 3:  # Sleep until rest of the post checks are complete
                            time.sleep(1)
                        print(f"{U_action[:-1]}ing {self.nb_name}")
                        self.OGupgrade(node_output["model_number"][:4].lower(), U_action)
                        # Generate new session ID as device will restart
                        new_auth = self.session.post(self.auth_url, headers=self.content_type, data=self.payload)
                        if (
                            new_auth.status_code != 200
                        ):  # Calling API Error handling functions in case response is not 200
                            getattr(self, f"code_{str(new_auth.status_code)}")(self.nb_name)
                        new_session_id = new_auth.json()[
                            "session"
                        ]  # This SESSION ID is required for making all API requests.
                        new_headers = {"Authorization": f"Token {new_session_id}", "Content-Type": "application/json"}

                        firm_response = self.session.get(self.node_url, headers=new_headers, timeout=10)
                        firm_output = json.loads(firm_response.content)
                        if node_output["firmware_version"] != firm_output["firmware_version"]:
                            Firmware = firm_output["firmware_version"]
                            errors = {
                                U_action: f"{self.nb_name} is {U_action}d from {node_output['firmware_version']} to {firm_output['firmware_version']}"
                            }
                            TestFunctions.printReport(
                                conn, self.nb_name, f"Test 6 " + self.nb_name, errors, " - ", "other"
                            )
                        else:
                            errors = {
                                U_action: f"Unable to {U_action} {self.nb_name}. Current Firmware version is {firm_output['firmware_version']}"
                            }
                            TestFunctions.printReport(
                                conn, self.nb_name, f"Test 6 " + self.nb_name, errors, " - ", "other"
                            )
                else:
                    if key == "4 Serial":
                        self.serial_match = True
                    Firmware = node_output["firmware_version"]
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} successfull for " + self.nb_name, "", " - ", "other"
                    )

            # to update the sw fields in NB
            dev_info = nb.dcim.devices.filter(name=self.nb_name)
            for nb_firm in dev_info:
                nb_firm.update({"custom_fields": {"software_version": Firmware}})
                nb_firm.update({"custom_fields": {"software_version_last_checked": utc_time.strftime("%Y-%m-%d")}})
                nb_firm.save()

            # Update eth0 mac address from device to netbox
            nb_interface = nb.dcim.interfaces.filter(device=self.nb_name, name="eth0")
            for inter in nb_interface:
                if not inter.mac_address:
                    inter.mac_address = node_output["mac_address"]
                    inter.save()
            if self.upgrade_required == True:
                print("Postchecks complete for", self.nb_name)
        except Exception as e:
            print(f"Opengear nodes: {str(e)}")
            exception = {f"Opengear": f"Exception nodes {self.nb_name}{str(e)}"}
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 10 Exception" + self.nb_name, exception, " - ", "other"
            )
        if errors:
            return False
        else:
            return True

    def get_ports(self):  # This function checks the console port labels against the Netbox Console port entries
        nb_dict = {}
        errors = {}
        device_dict = {}
        try:
            # NETBOX API request to get the Console ports with endpoints
            console_server_ports = nb.dcim.console_server_ports.filter(device=self.nb_name)
            for port in console_server_ports:
                if port.connected_endpoints_reachable and hasattr(port.connected_endpoints[0], "device"):
                    nb_dict[port.name[5:]] = port.connected_endpoints[0].device.name

            # Opengear API call with serialPorts to retrieve the serial port information.
            serial_response = self.session.get(self.serial_url, headers=self.headers, timeout=10)
            if serial_response.status_code != 200:  # Calling API Error handling functions in case response is not 200
                getattr(self, f"code_{str(serial_response.status_code)}")(self.nb_name)
            serial_output = json.loads(serial_response.content)
            for item in serial_output["serialports"]:
                if "." in item["label"]:
                    device_dict[item["id"][4:]] = item["label"]

            # Comparing the Netbox And Device Dictionaries
            diff_keys = set(nb_dict.keys()) ^ set(device_dict.keys())

            # Getting the additional serial ports connected in device but not defined in Netbox
            diff_vals = set(k for k in nb_dict if k in device_dict and nb_dict[k] != device_dict[k])

            # Print the keys and values for the different keys with different values
            if not diff_vals:
                TestFunctions.printReport(
                    conn, self.nb_name, "Test 7 Console labels successfull for " + self.nb_name, "", "-", "other"
                )
            else:
                for k in diff_vals:
                    errors.update(
                        {
                            f"Port {k}": f"Name Mismatch for Console Port {k} NETBOX: {nb_dict[k]} and Device: {device_dict[k]}"
                        }
                    )

            # Print the keys and values for additional keys in either dictionary
            for k in diff_keys:
                if k in nb_dict:
                    errors.update({f"Port {k}": f"Additional Port {k} -> {nb_dict[k]} found in NETBOX"})
                else:
                    errors.update({f"Port {k}": f"Additional Port {k} -> {device_dict[k]} found in DEVICE"})
        except Exception as e:
            print(f"Opengear ports: {str(e)}")
            exception = {f"Opengear": f"Exception ports {self.nb_name}{str(e)}"}
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 10 Exception" + self.nb_name, exception, " - ", "other"
            )

        # Printing the Final Issues (Label mismatch and additional ports found)
        if errors:
            TestFunctions.printReport(
                conn, self.nb_name, "Test 7 Console labels failed for " + self.nb_name, errors, "-", "other"
            )
            self.upgrading += 1
            return False
        else:
            self.upgrading += 1
            return True

    def OGupgrade(self, code, upgrade_action):  # This function is to upgrade the Opengear Firmware
        local_file_path = f"/opt/ansible/software/opengear/{code}xx-{self.firm}.flash"  # Get the firmware on DC13 or SV15 server, Depending on the CM or IM device and Gold Master defined in Wiki
        remote_script_path = "/var/mnt/OGupgrade.sh"
        remote_file_path = f"/var/mnt/{code}xx-{self.firm}.flash"
        if upgrade_action == "Downgrade":
            cmd = f"netflash {remote_file_path} -i"
        else:
            cmd = f"netflash {remote_file_path}"

        try:
            print(
                f"{datetime.utcnow().strftime('%a %d %b %Y %I:%M:%S %p UTC')} Initiating {upgrade_action} for {self.nb_name}, This may take upto 6 minutes"
            )
            # Create an SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the remote device
            ssh.connect(self.nb_name, username="root", password=os.environ["OPEN_PASS"])

            # Create an SFTP session
            sftp = ssh.open_sftp()

            # Transfer the file
            print(
                f"{datetime.utcnow().strftime('%a %d %b %Y %I:%M:%S %p UTC')} Uploading {local_file_path} to device {self.nb_name}"
            )
            sftp.put(local_file_path, remote_file_path)
            print(
                f"{datetime.utcnow().strftime('%a %d %b %Y %I:%M:%S %p UTC')} Upload to device {self.nb_name} {remote_file_path} is complete."
            )

            # writing upgrade.sh to execute the upgrade
            shell_script = f"""
            #!/bin/bash
            config -e /var/tmp/my-backup.opg
            sleep 3
            {cmd}
            """

            # Create a temporary local script file
            with open(f"{self.nb_name}.sh", "w") as local_file:
                local_file.write(shell_script)

            # Upload the local script to the remote device

            with ssh.open_sftp().file(remote_script_path, "w") as remote_file:
                with open(f"{self.nb_name}.sh", "r") as local_file:
                    remote_file.write(local_file.read())

            # Make the script executable
            print(
                f"{datetime.utcnow().strftime('%a %d %b %Y %I:%M:%S %p UTC')} Executing {upgrade_action} and rebooting device {self.nb_name}."
            )
            ssh.exec_command(f"chmod +x {remote_script_path}")

            # Execute the remote shell script
            ssh.exec_command(remote_script_path)

            time.sleep(180)
            self.ping_device()
            if upgrade_action == "Downgrade":
                ssh.connect(self.nb_name, username="root", password=os.environ["OPEN_PASS"])
                ssh.exec_command("config -a")
                time.sleep(10)
                ssh.close()

            errors = {upgrade_action: f"{upgrade_action} is initiated on {self.nb_name}"}

            # Clean up:
            print(
                f"{datetime.utcnow().strftime('%a %d %b %Y %I:%M:%S %p UTC')} {upgrade_action} Complete for {self.nb_name}"
            )
            os.remove(f"{self.nb_name}.sh")

        except Exception as e:
            print(f"Device {upgrade_action} Failed: {str(e)}")
            errors = {upgrade_action: f"Unable to {upgrade_action} {self.nb_name}, Error: {str(e)}"}
            TestFunctions.printReport(conn, self.nb_name, f"Test 6 " + self.nb_name, errors, " - ", "other")

    def pmshell_check(
        self,
    ):  # This Function check the devices physically connected to serial ports of opengear and captures their hostname
        with output_lock:
            try:
                # SSH session setup
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(self.nb_name, username="root", password=os.environ["OPEN_PASS"])

                # Calling Opengear API to get the serial port Labels
                serial_response = self.session.get(self.serial_url, headers=self.headers, timeout=10)
                if (
                    serial_response.status_code != 200
                ):  # Calling API Error handling functions in case response is not 200
                    getattr(self, f"code_{str(serial_response.status_code)}")(self.nb_name)
                else:
                    # initializing the dictionaries for comparison
                    nb_dict = {}
                    device_dict = {}
                    errors = {}

                    # checking connections of the ports updated with label name
                    serial_output = json.loads(serial_response.content)
                    for item in serial_output["serialports"]:
                        if "." in item["label"]:
                            portid = item["id"]
                            pportid = self.nb_name + item["id"]
                            nb_dict.update({pportid: item["label"]})  # Created Dictionary from opengear api call labels
                            # Preparing Expect script commands to upload and execute, calling ports with labels
                            script = """
                            #!/usr/bin/expect
                            set timeout 3
                            spawn pmshell -l {portid}
                            send -- "\r"
                            expect ":" { send "~.\r" }
                            """
                            expect_script = script.replace("{portid}", portid)
                            # Write expect script to a temporary file
                            script_filename = "expect_script.exp"
                            with open(script_filename, "w") as script_file:
                                script_file.write(expect_script)
                            # Upload the expect script to the remote device
                            try:
                                sftp_client = ssh_client.open_sftp()
                                sftp_client.put(script_filename, f"/var/mnt/{script_filename}")
                                sftp_client.close()
                            except OSError as e:
                                ssh_client.exec_command(
                                    "reboot"
                                )  # Reboot the Opengear device In case it throws OSError
                                print(self.nb_name, "Rebooted due to OS error, waiting for device to be reachable")
                                time.sleep(120)
                                self.ping_device()
                                print(
                                    f"Please run the Postchecks for Device {self.nb_name} again adding flag -d for device only."
                                )
                                OSerrors = {
                                    "OSError": f"Postchecks failed on {self.nb_name} due to OSError. A Reboot is executed, Please run the postchecks again on device by adding flag -d for device only."
                                }
                                TestFunctions.printReport(
                                    conn, self.nb_name, f"Test 10 " + self.nb_name, OSerrors, " - ", "other"
                                )

                            # Execute the expect script
                            stdin, stdout, stderr = ssh_client.exec_command(f"expect /var/mnt/{script_filename}")

                            # Wait for the command to complete
                            stdout.channel.recv_exit_status()

                            # Save the output
                            output = stdout.read().decode().splitlines()

                            last_line = (
                                output[-1].strip() if output and output[-1].strip() else "No device"
                            )  # When no response is received on serial port

                            # Several cases defined to read all possible known outputs on serial port
                            if last_line:
                                if "@" in last_line:
                                    pattern = r"@([\w.]+)"
                                    matches = re.findall(pattern, last_line)
                                    if matches:
                                        for match in matches:
                                            device_dict.update({pportid: match})
                                else:
                                    if last_line.startswith(
                                        "No device"
                                    ):  # in case of no connected device or device down
                                        device_dict.update({pportid: last_line})
                                    elif last_line.startswith("Username:"):  # in case of PDU
                                        device_dict.update({pportid: "pdu"})
                                    elif last_line.startswith("login:"):  # for Juniper (BBR/BSR/MDR/FW/MRR/MSR)
                                        if any(
                                            "Amnesiac" in s for s in output
                                        ):  # When config is not loaded on one routing engine.
                                            device_dict.update(
                                                {pportid: "Device in Amnesiac mode, Make sure this is a backup RE"}
                                            )
                                        else:
                                            elements_with_dots = []
                                            for item in output:
                                                # Use a regular expression to find elements with one or more dots
                                                matches = re.findall(r"\w+\.\w+", item)

                                                # Add the matches to the result list
                                                elements_with_dots.extend(matches)
                                            device_dict.update({pportid: [".".join(elements_with_dots)][0]})

                                    elif (
                                        last_line.startswith("msw")
                                        or last_line.startswith("esr")
                                        or last_line.startswith("csr")
                                        or last_line.startswith("dsr")
                                        or last_line.startswith("ssp")
                                        or last_line.startswith("pdu")
                                    ):  # for arista and nokia
                                        first_word = last_line.split()[0]
                                        device_dict.update({pportid: first_word})

                                    elif last_line.startswith("root>"):
                                        device_dict.update({pportid: "Device Not configured"})

                                    else:
                                        errors.update(
                                            {"Error": f"Unkown device connected to {portid}, Output: {last_line}"}
                                        )  # If none of the above defined cases match
                                        TestFunctions.printReport(
                                            conn,
                                            self.nb_name,
                                            f"Test 8 failed for " + self.nb_name,
                                            errors,
                                            " - ",
                                            "other",
                                        )
                            else:
                                errors.update(
                                    {"Error": "Expect script failed"}
                                )  # If no labels are retrived on Opengear API call
                                TestFunctions.printReport(
                                    conn, self.nb_name, f"Test 8 failed for " + self.nb_name, errors, " - ", "other"
                                )
                                return False

                        # Comparing the dictionaries
                        for key in nb_dict:
                            if key in device_dict and nb_dict[key][: len(device_dict[key])] != device_dict[key]:
                                port_index = key.find("port")
                                port_number = key[port_index + 4 :]
                                errors.update(
                                    {
                                        key: f"Port: {port_number} MISMATCH Label: {nb_dict[key]} -> Device: {device_dict[key]}"
                                    }
                                )

                    # print("device", device_dict)
                    # print("nb", nb_dict)
                    # Clean up: remove the modified script file
                    os.remove("expect_script.exp")

                if errors:
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test 8 failed for " + self.nb_name, errors, " - ", "other"
                    )
                    self.upgrading += 1
                    if self.upgrade_required == False:
                        print("Postchecks complete for", self.nb_name)
                    return False
                else:
                    TestFunctions.printReport(
                        conn,
                        self.nb_name,
                        f"Test 8 Console port connections successfull for " + self.nb_name,
                        "",
                        " - ",
                        "other",
                    )
                    self.upgrading += 1
                    if self.upgrade_required == False:
                        print("Postchecks complete for", self.nb_name)
                    return True
            except Exception as e:
                print(f"Opengear pmshell: {self.nb_name}{str(e)}")
                exception = {f"Opengear": f"Exception pmshell {self.nb_name}{str(e)}"}
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 10 Exception" + self.nb_name, exception, " - ", "other"
            )

    def ping_device(self):  # Function will keep pinging the device until its reachable
        # Initialize a counter for received TTL values
        duration = 120  # 2 minutes, waited 180 seconds before calling function
        start_time = time.time()
        elapsed_time = 0
        ttl_count = 0

        while ttl_count < 10 and elapsed_time < duration:
            try:
                # Run the ping command and capture the output
                result = subprocess.run(
                    ["ping", "-c", "1", self.nb_name], stdout=subprocess.PIPE, text=True, check=True
                )

                # Extract the TTL value from the ping output using a regular expression
                ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
                elapsed_time = time.time() - start_time

                if ttl_match:
                    received_ttl = int(ttl_match.group(1))
                    ttl_count += 1

                else:
                    print("TTL not found in the ping output.")

            except subprocess.CalledProcessError:
                time.sleep(1)
                print(
                    f"Waiting for {self.nb_name} to be reachable, {duration - int(time.time() - start_time)} seconds left."
                )

        print(f"Device {self.nb_name} is now reachable")
        return True

    def update_nb(self, key, value):
        while self.serial_match is None:
            time.sleep(1)
            print(self.serial_match)
        if self.serial_match is True:
            if key == "3 IPv4":
                dev_info = nb.dcim.devices.filter(name=self.nb_name)
                for device in dev_info:
                    # Get the existing primary IP address (if it exists)
                    primary_ip = device.primary_ip
                    if primary_ip:
                        # Update the IP address
                        primary_ip.address = f"{value}/25"
                        primary_ip.save()
                nb_errors = {"NB UPDATED": f"Netbox is updated with the device IPV4 {value}/25 for {self.nb_name}"}
                TestFunctions.printReport(conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other")
            elif key == "2 Model":
                device_type = nb.dcim.device_types.filter(model=value)
                if device_type:
                    for device_types in device_type:
                        id = device_types.id
                    # Find the device by name or other identifier
                    devices = nb.dcim.devices.filter(name=self.nb_name)
                    for device in devices:
                        # Update the device type
                        device.device_type.id = device_types.id
                        device.save()
                        nb_errors = {"NB UPDATED": f"Netbox is updated with the device type {value} for {self.nb_name}"}
                        TestFunctions.printReport(
                            conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other"
                        )
                else:
                    nb_errors = {"NB ERROR": f"Device Type {value} do not exist in Netbox"}
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other"
                    )
            else:
                nb_errors = {"NB ERROR": f"Cannot update {key} for device {self.nb_name}"}
                TestFunctions.printReport(conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other")
        else:
            nb_errors = {
                "NB ERROR": f"Device Serial doesnt match with Netbox, please make sure its the right device and run the Postchecks for Device {self.nb_name} again adding flag -d for device only."
            }
            TestFunctions.printReport(conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other")


class ServerTech:
    def __init__(self, nb_info, firmware):
        # Initializing variables to reuse within class
        errors = {}
        self.nb_name = str(nb_info.name)
        self.nb_model = str(nb_info.device_type)
        self.nb_serial = str(nb_info.serial)
        if (nb_info.primary_ip4) is not None:
            self.nb_ip4 = str(nb_info.primary_ip4)
        else:
            self.nb_ip4 = "NONEeee"
        self.firm = firmware
        self.serial_match = None
        self.upgrading = 0
        self.upgrade_required = False

        # Encrypting PDU Passwords
        credential1 = f"admn:{os.environ['PDU_PASS']}"
        auth1 = credential1.encode("utf-8")
        # Defining API header for New Password
        self.headers_1 = {
            "Authorization": f"Basic {base64.b64encode(auth1).decode('utf-8')}",
            "Content-Type": "application/json",
        }

        # Defining URL variables for JAWS api call
        self.base_url = "https://" + self.nb_name + ".packet.net/jaws/"
        self.outlet_info = "control/outlets"
        self.network_info = "config/info/network"
        self.system_info = "config/info/system"
        self.units_info = "config/info/units"
        self.user_info = "config/users/local/admn"

        response = requests.request(
            "GET", "https://" + self.nb_name + ".packet.net/", headers=self.headers_1, verify=False, timeout=10
        )
        if response.status_code == 200:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                # Submit each function to the executor
                futures = [
                    executor.submit(func)
                    for func in [self.get_system, self.get_units, self.get_network, self.get_outlets]
                ]

                # Wait for all futures to complete
                concurrent.futures.wait(futures)
        elif "PDU_OLDPASS" in os.environ and response.status_code != 200:
            self.update_pass()
        else:
            errors.update(
                {
                    "LOGIN_ERR": "Unable to login. check if PDU DNS is done and is reachable. If its a legacy site PDU, export the optional enviroment variable PDU_OLDPASS and re-run for this device with flag -d"
                }
            )
            TestFunctions.printReport(conn, self.nb_name, "Test 1 failed for " + self.nb_name, errors, "-", "other")

    # Functions For the JAWS API Error handling
    def code_503(self, PDU):
        errors = {"Error 503": f"Error 503 {PDU} is too busy, please try again in a while"}
        TestFunctions.printReport(conn, PDU, "Test 1 failed for " + PDU, errors, "-", "other")
        return False

    def code_405(self, PDU):
        errors = {"Error 405": f"Error 405 Invalid request for {PDU}"}
        TestFunctions.printReport(conn, PDU, "Test 1 failed for " + PDU, errors, "-", "other")
        return False

    def code_404(self, PDU):
        errors = {"Error 404": f"Error 404 Requested {PDU} does not exist or is unavailable"}
        TestFunctions.printReport(conn, PDU, "Test 1 failed for " + PDU, errors, "-", "other")
        return False

    def generate_hex_string(self):
        # Encode the new password string as bytes
        plaintext_bytes = os.environ["PDU_PASS"].encode("utf-8")

        # Calculate the SHA256 hash
        sha256_hash = hashlib.sha256(plaintext_bytes).hexdigest()

        # Convert the hash to uppercase
        sha256_hash_upper = sha256_hash.upper()
        return sha256_hash_upper

    def update_pass(self):
        errors = {}
        # Encrypting PDU Passwords
        credential = f"admn:{os.environ['PDU_OLDPASS']}"
        auth = credential.encode("utf-8")
        secure = self.generate_hex_string()
        # Defining API header for Old Password
        headers = {
            "Authorization": f"Basic {base64.b64encode(auth).decode('utf-8')}",
            "Content-Type": "application/json",
        }
        payload = json.dumps({"password_secure": secure})
        response = requests.request(
            "PATCH", self.base_url + self.user_info, headers=headers, data=payload, verify=False, timeout=10
        )
        if response.status_code == 204:
            print("password updated for " + self.nb_name)
            errors = {f"Servertech": f"Password updated for {self.nb_name}"}
            TestFunctions.printReport(conn, self.nb_name, f"Test 11 Exception" + self.nb_name, errors, " - ", "other")
            O_S_device(self.nb_name, self.firm)
        else:
            errors.update(
                {
                    "LOGIN_ERR": "Unable to login using old password, make sure the correct old password is provided, else update the password manually and then re-run for this device with flag -d"
                }
            )
            TestFunctions.printReport(conn, self.nb_name, "Test 1 failed for " + self.nb_name, errors, "-", "other")

    def get_system(
        self,
    ):  # This function is comparing Device Firmware against Gold Master and upgrade if firware is not Gold Master
        nb_dict = {"Firmware": self.firm}

        errors = {}
        payload = ""

        # Calling JAWS API for system
        response = requests.request(
            "GET", self.base_url + self.system_info, headers=self.headers_1, data=payload, verify=False, timeout=10
        )
        if response.status_code == 200:
            device_info = json.loads(response.content)

            # Split the input string by the word 'Version'
            split_string = device_info["firmware"].split("Version", 1)

            # Check if 'version' was found in the string
            if len(split_string) > 1:
                # Get the characters after 'version' without spaces
                version_info = split_string[1].strip()
            else:
                version_info = "No Version found."
            Firmware = version_info
            device_dict = {"Firmware": version_info}
        else:
            getattr(self, f"code_{str(response.status_code)}")(
                self.nb_name
            )  # Calling API Error handling functions in case response is not 200

        # Comparing the Dictionaries
        for key in nb_dict:
            if key in device_dict and nb_dict[key] != device_dict[key]:
                errors.update({key: f"MISMATCH: Netbox: {nb_dict[key]} and Device: {device_dict[key]}"})
                TestFunctions.printReport(
                    conn, self.nb_name, f"Test 2 Firmware failed for " + self.nb_name, errors, " - ", "other"
                )
                self.upgrading += 1
                self.upgrade_required = True
                while self.upgrading < 4:  # sleep until rest of the postchecks complete
                    time.sleep(1)
                print(f"Initiating upgrade for {self.nb_name}, This may take upto 6 minutes")
                self.STupgrade()
                firm_response = requests.request(
                    "GET",
                    self.base_url + self.system_info,
                    headers=self.headers_1,
                    data=payload,
                    verify=False,
                    timeout=10,
                )
                if firm_response.status_code == 200:
                    firm_info = json.loads(firm_response.content)
                    if firm_info["firmware"] != device_info["firmware"]:
                        # Split the input string by the word 'Version'
                        firm_string = firm_info["firmware"].split("Version", 1)
                        # Check if 'version' was found in the string
                        if len(firm_string) > 1:
                            # Get the characters after 'version' without spaces
                            new_version = firm_string[1].strip()
                        else:
                            new_version = "No Version found."
                        Firmware = new_version
                        upgrade_errors = {
                            "UPGRADE": f"{self.nb_name} is upgraded from {device_info['firmware'][-4:]} to {firm_info['firmware'][-4:]}"
                        }
                        TestFunctions.printReport(
                            conn, self.nb_name, f"Test 2 " + self.nb_name, upgrade_errors, " - ", "other"
                        )
                    else:
                        upgrade_errors = {
                            "UPGRADE": f"Unable to upgrade {self.nb_name}. Current Firmware version is {firm_info['firmware']}"
                        }
                        TestFunctions.printReport(
                            conn, self.nb_name, f"Test 2 " + self.nb_name, upgrade_errors, " - ", "other"
                        )
                else:
                    getattr(self, f"code_{str(response.status_code)}")(
                        self.nb_name
                    )  # Calling API Error handling functions in case response is not 200

        # to update the sw fields in NB
        dev_info = nb.dcim.devices.filter(name=self.nb_name)
        for nb_firm in dev_info:
            nb_firm.update({"custom_fields": {"software_version": Firmware}})
            nb_firm.update({"custom_fields": {"software_version_last_checked": utc_time.strftime("%Y-%m-%d")}})
            nb_firm.save()

        if self.upgrade_required == True:
            print("Postchecks complete for", self.nb_name)

        if errors:
            return False
        else:
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 2 Firmware successfull for " + self.nb_name, "", " - ", "other"
            )
            return True

    def get_units(self):  # This function compares Device Serial and Device Model
        nb_dict = {"3 Serial": self.nb_serial, "4 Model": self.nb_model}

        payload = ""
        errors = {}

        # Make the JAWS API request for units
        try:
            response = requests.request(
                "GET", self.base_url + self.units_info, headers=self.headers_1, data=payload, verify=False, timeout=10
            )

            if response.status_code == 200:
                device_info = json.loads(response.content)
                device_dict = {
                    "3 Serial": device_info[0]["product_serial_number"],
                    "4 Model": device_info[0]["model_number"],
                }

            else:
                getattr(self, f"code_{str(response.status_code)}")(
                    self.nb_name
                )  # Calling API Error handling functions in case response is not 200

            # Comparing the dictionaries
            for key in nb_dict:
                if key in device_dict and nb_dict[key] != device_dict[key]:
                    errors = {key: f"MISMATCH: Netbox: {nb_dict[key]}, Device: {device_dict[key]}"}
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} failed for " + self.nb_name, errors, " - ", "other"
                    )
                    if key == "3 Serial":
                        self.serial_match = False
                    if key == "4 Model":
                        self.update_nb(key, device_dict[key])
                else:
                    if key == "3 Serial":
                        self.serial_match = True
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} successfull for " + self.nb_name, "", " - ", "other"
                    )
        except Exception as e:
            print(f"Servertech Units: {str(e)}")
            exception = {f"Servertech": f"Exception Units {self.nb_name}{str(e)}"}
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 10 Exception" + self.nb_name, exception, " - ", "other"
            )
        if errors:
            self.upgrading += 1
            return False
        else:
            self.upgrading += 1
            return True

    def get_network(self):  # This function compares the eth0 MAC and device primary IPV4 against Netbox
        try:
            # Calling Netbox api to get eth0 Mac
            interface_names = ["eth0", "Net1", "NET"]
            nb_interface = nb.dcim.interfaces.filter(device=self.nb_name, name__in=interface_names)
            for inter in nb_interface:
                if inter.mac_address is not None:
                    mac = inter.mac_address.replace(":", "-")
                else:
                    mac = None
            errors = {}
            payload = ""

            nb_dict = {"5 MAC": mac, "6 IP4": self.nb_ip4[:-3]}

            # Making the JAWS API request for network
            response = requests.request(
                "GET", self.base_url + self.network_info, headers=self.headers_1, data=payload, verify=False, timeout=10
            )

            if response.status_code == 200:
                device_info = json.loads(response.content)
                device_dict = {"5 MAC": device_info["ethernet_mac_address"], "6 IP4": device_info["ipv4_address"]}
            else:
                getattr(self, f"code_{str(response.status_code)}")(
                    self.nb_name
                )  # Calling API Error handling functions in case response is not 200
            # Comparing the dictionaries

            for key in nb_dict:
                if key in device_dict and nb_dict[key] != device_dict[key]:
                    errors = {key: f"MISMATCH: Netbox: {nb_dict[key]}, Device: {device_dict[key]}"}
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} failed for " + self.nb_name, errors, " - ", "other"
                    )

                    self.update_nb(key, device_dict[key])
                else:
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} successfull for " + self.nb_name, "", " - ", "other"
                    )

        except Exception as e:
            print(f"Servertech Network: {str(e)}")
            exception = {f"Servertech": f"Exception Network {self.nb_name}{str(e)}"}
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 10 Exception" + self.nb_name, exception, " - ", "other"
            )
        if errors:
            self.upgrading += 1
            return False
        else:
            self.upgrading += 1
            return True

    def get_outlets(self):  # This function checks the running status of power outlets
        payload = ""
        errors = {}

        # Make the JAWS API request for outlets
        try:
            response = requests.request(
                "GET", self.base_url + self.outlet_info, headers=self.headers_1, data=payload, verify=False, timeout=10
            )

            if response.status_code == 200:
                device_info = json.loads(response.content)
                # Getting the outlets with status not On
                off_states = [d["id"] for d in device_info if d["state"] != "On"]
                if off_states:
                    errors.update({"outlets": f"Outlets in off state: {', '.join(off_states)}"})

                # Calling Netbox API to get Power outlet endpoints, to update the Power Outlet Lables on the PDU
                power_outlets = nb.dcim.power_outlets.filter(device=self.nb_name)
                for poutlet in power_outlets:
                    if poutlet.connected_endpoints is not None:
                        port_name = [d["name"] for d in device_info if d["id"] == str(poutlet)]
                        if str(poutlet.connected_endpoints[0].device)[:3] != str(port_name[0])[:3]:
                            # Calling function to update Power outlet label on PDU
                            self.update_outlet_name(
                                str(poutlet),
                                str(poutlet.connected_endpoints[0]),
                                str(poutlet.connected_endpoints[0].device),
                            )
            else:
                getattr(self, f"code_{str(response.status_code)}")(
                    self.nb_name
                )  # Calling API Error handling functions in case response is not 200
        except Exception as e:
            print(f"Servertech Outlets: {str(e)}")
            errors.update({"outlets": f"{str(e)}"})
        if errors:
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 7 Outlet Power failed for " + self.nb_name, errors, " - ", "other"
            )
            if self.upgrade_required == False:
                print("Postchecks complete for", self.nb_name)
            self.upgrading += 1
            return False
        else:
            TestFunctions.printReport(
                conn, self.nb_name, f"Test 7 Outlet Power successfull for " + self.nb_name, "", " - ", "other"
            )
            if self.upgrade_required == False:
                print("Postchecks complete for", self.nb_name)
            self.upgrading += 1
            return True

    def update_outlet_name(
        self, port_id, port_name, port_device
    ):  # This Function updated the Power outlet lables on PDU

        last_dot_index = port_device.rfind(".")
        if last_dot_index != -1:  # Check if a dot was found
            # Extract the part of the string before the last dot
            result = port_device[:last_dot_index]
        else:
            # If no dot was found, keep the original string
            result = port_device

        pname = re.sub(r"[^a-zA-Z0-9]", "_", result + " " + port_name)
        # Make the JAWS API request to update the power outlet label
        if len(pname) > 32:  # outlet name should be less than 32 characters, no space
            pname = pname[:15] + pname[-15:]
        try:
            payload = json.dumps({"name": pname})
            response = requests.request(
                "PATCH",
                self.base_url + "config/outlets/" + port_id,
                headers=self.headers_1,
                data=payload,
                verify=False,
                timeout=10,
            )
            if response.status_code != 204:
                getattr(self, f"code_{str(response.status_code)}")(self.nb_name)

        except Exception as e:
            print(f"Power Outlet update Failed: {str(e)}")

    def STupgrade(self):  # This function upgrades the PDU to the Gold Master Version
        # Replace the variables in shell script
        variables_to_replace = {
            "$SECRET": os.environ["PDU_PASS"],
            "$DEVICE": self.nb_name,
            "$FILE": f"/opt/ansible/software/servertech/pro-v{self.firm.replace('.','')}.bin",
        }
        # Read the original shell script
        with open("STupgrade.sh", "r") as file:
            original_script = file.read()

        # Replace variables in the script
        for variable, replacement in variables_to_replace.items():
            original_script = original_script.replace(variable, replacement)

        # Write the modified script to a temporary file
        with open(f"{self.nb_name}.sh", "w") as file:
            file.write(original_script)

        # Execute the modified script
        try:
            process = subprocess.Popen(
                ["sudo", "bash", f"{self.nb_name}.sh"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            while True:
                output = process.stdout.readline()
                if output == "" and process.poll() is not None:
                    break
                if output:
                    print(output.strip())

        except Exception as e:
            print("An error occurred:", str(e))

        # Clean up: remove the modified script file
        os.remove(f"{self.nb_name}.sh")
        return

    def update_nb(self, key, value):
        while self.serial_match is None:
            time.sleep(1)
        if self.serial_match is True:
            if key == "5 MAC":
                interface_names = ["eth0", "Net1", "NET"]
                nb_interface = nb.dcim.interfaces.filter(device=self.nb_name, name__in=interface_names)
                for inter in nb_interface:
                    inter.mac_address = value.replace(":", "-")
                    inter.save()
                nb_errors = {
                    "NB UPDATED": f'Netbox is updated with the device mac {value.replace("-", ":")} for {self.nb_name}'
                }
                TestFunctions.printReport(conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other")
            elif key == "6 IP4":
                # first remove all IP assigned to interface

                interface_names = ["eth0", "Net1", "NET"]
                ip_prefixes = nb.ipam.ip_addresses.filter(device=self.nb_name, name__in=interface_names)
                for ip in ip_prefixes:
                    ip.delete()

                # second if IP already exsits, if not, create ip address
                ip_info = nb.ipam.ip_addresses.filter(address=f"{value}/25")
                if ip_info:
                    for info in ip_info:
                        iD = info.id
                else:
                    interface = nb.dcim.interfaces.filter(device=self.nb_name, name__in=interface_names)
                    for item in interface:
                        iD = item.id
                        nAME = item.name
                # Create a new IP address for the interface
                ip_obj = nb.ipam.ip_addresses.create(address=f"{value}/25")
                ip_obj.status.value = "active"
                ip_obj.assigned_object_type = "dcim.interface"
                ip_obj.assigned_object_id = iD
                ip_obj.description = f"{self.nb_name}::{nAME}"
                iD = ip_obj.id
                ip_obj.save()

                # Third, update ip as primary
                dev_info = nb.dcim.devices.filter(name=self.nb_name)
                for item in dev_info:
                    item.primary_ip4 = iD
                    item.save()

                nb_errors = {"NB UPDATED": f"Netbox is updated with the device IPV4 {value}/25 for {self.nb_name}"}
                TestFunctions.printReport(conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other")
            elif key == "4 Model":
                device_type = nb.dcim.device_types.filter(model=value)
                if device_type:
                    for device_types in device_type:
                        id = device_types.id
                    # Find the device by name or other identifier
                    devices = nb.dcim.devices.filter(name=self.nb_name)
                    for device in devices:
                        # Update the device type
                        device.device_type.id = device_types.id
                        device.save()
                        nb_errors = {"NB UPDATED": f"Netbox is updated with the device type {value} for {self.nb_name}"}
                        TestFunctions.printReport(
                            conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other"
                        )
                else:
                    nb_errors = {"NB ERROR": f"Device Type {value} do not exist in Netbox"}
                    TestFunctions.printReport(
                        conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other"
                    )
            else:
                nb_errors = {"NB ERROR": f"Cannot update {key} for device {self.nb_name}"}
                TestFunctions.printReport(conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other")
        else:
            nb_errors = {
                "NB ERROR": f"Device Serial doesnt match with Netbox, please make sure its the right device and run the Postchecks for Device {self.nb_name} again adding flag -d for device only."
            }
            TestFunctions.printReport(conn, self.nb_name, f"Test {key} " + self.nb_name, nb_errors, " - ", "other")


def O_S_device(
    host, firmware
):  # This is the main function which calls the Netbox API to get the manufacturer and then call its class

    device = nb.dcim.devices.get(name=host)
    if device.device_type.manufacturer.name.lower() == "opengear":
        return Opengear(device, firmware)
    elif device.device_type.manufacturer.name.lower() == "servertech":
        return ServerTech(device, firmware)
    else:
        print("Not a ServerTech or Opengear Device")
        sys.exit()
