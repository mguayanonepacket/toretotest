#!/usr/bin/env python3
from pygnmi.client import gNMIclient
from pathlib import Path
from jira import JIRA
import datetime
import argparse
import pynetbox
import requests
import logging
import pyeapi
import time
import sys
import os


DOMAIN = ".packet.net"
NB_URL = "https://netbox.packet.net"
ECX_URL = "https://api.equinix.com"


class _Auth:
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r


class ECX:
    """This class is used to access Equinix Customer Portal"""

    def __init__(
        self,
        url,
        key,
        secret,
    ):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        body = {
            "grant_type": "client_credentials",
            "client_id": key,
            "client_secret": secret,
        }
        r = requests.post(f"{url}/oauth2/v1/token", json=body, headers=headers)
        r.raise_for_status()
        json = r.json()
        if "access_token" not in json:
            raise RuntimeError("No access_token in ECX auth response. This may indicate an authentication failure.")
        token = json["access_token"]
        self.auth = _Auth(token)
        self.url = url

    def _request(self, path, params={}, json=None, method="get", headers={}, paginated=False):
        """This function makes API Request calls, default method is GET"""
        try:
            f = requests.__dict__[method]
        except KeyError:
            raise ValueError(f"{method} is not a valid HTTP method")
        if not callable(f):
            raise ValueError(f"{method} is not a valid HTTP method")
        # some endpoints do pagination and some don't??????
        if paginated:
            params.update({"pageSize": 100})
            content = []
            while True:
                r = f(
                    f"{self.url}/{path}",
                    params=params,
                    json=json,
                    headers=headers,
                    auth=self.auth,
                )
                j = r.json()
                if r.status_code != 200:
                    msg = f"Response code {r.status_code} while requesting {self.url}/{path}. Body was {json}."
                    if "errorMessage" in j:
                        msg += f" Error message from API: {j['errorMessage']}"
                    else:
                        msg += f" Raw error message from API: {j}"
                    raise RuntimeError(msg)
                content.extend(j["content"])
                if j["isLastPage"]:
                    break
                params.update({"pageNumber": j["pageNumber"] + 1})
            return content
        else:
            r = f(
                f"{self.url}/{path}",
                params=params,
                json=json,
                headers=headers,
                auth=self.auth,
            )
            j = r.json()
            if r.status_code == 201:
                return j
            if r.status_code != 200:
                msg = f"Response code {r.status_code} while requesting {self.url}/{path}. Body was {json}."
                if "errorMessage" in j:
                    msg += f" Error message from API: {j['errorMessage']}"
                else:
                    msg += f" Raw error message from API: {j}"
                raise RuntimeError(msg)
            return j

    def acctNumber(self, site, cab):
        params = {
            "detail": "true",
            "ibxs": site,
        }
        ibxData = self._request("v1/orders/smarthands/locations", params=params)
        for cab in ibxData["locations"][0]["cages"]:
            if cab.get("cage", None) == aCab:
                accountNum = cab["accounts"][0]["number"]
                return accountNum

    def createSmrtHand(self, data):
        response = self._request("v1/orders/smarthands/other", method="post", json=data)
        if response.get("OrderNumber"):
            order_number = response.get("OrderNumber")
            return order_number
        else:
            print(f"Error creating order, check customer Portal and create Smarthands")


class Netbox:
    # Initialize Attributes
    def __init__(self, host, intf):
        self.host = host
        self.intf = intf

    def local_intf(self):
        return self.intf

    def nb_get_device_neighbor_ipv4(self):
        """
        Pull IPv4 neighbor based on upstream interface.
        Store output in a dictionary data structure.
        """
        host_intf = nb.dcim.interfaces.get(device=self.host, name=self.intf)
        neig_host = host_intf.connected_endpoints[0].device.display
        neig_int = host_intf.connected_endpoints[0].display
        neig_ipv4 = nb.ipam.ip_addresses.get(device=neig_host, interface=neig_int, family=4)
        sliced_ipv4 = neig_ipv4.address[0:-3]
        return sliced_ipv4

    def nb_get_device_neighbor_ipv6(self):
        """
        Pull IPv6 neighbor based on upstream interface.
        Store output in a dictionary data structure.
        """
        host_intf = nb.dcim.interfaces.get(device=self.host, name=self.intf)
        neig_host = host_intf.connected_endpoints[0].device.display
        neig_int = host_intf.connected_endpoints[0].display
        neig_ipv6 = nb.ipam.ip_addresses.get(device=neig_host, interface=neig_int, family=6)
        sliced_ipv6 = neig_ipv6.address[0:-4]
        return sliced_ipv6

    def nb_get_device_neighbor_endpoint(self):
        """
        Pull downstream hostname:interface
        """
        host_intf = nb.dcim.interfaces.get(device=self.host, name=self.intf)
        neig_host = host_intf.connected_endpoints[0].device.display
        neig_int = host_intf.connected_endpoints[0].display
        dwnstrm_dict = {neig_host: neig_int}
        return dwnstrm_dict

    def nb_get_device_neighbor_intf(self):
        """
        Pull interface, return is str
        """
        host_intf = nb.dcim.interfaces.get(device=self.host, name=self.intf)
        return host_intf.connected_endpoints[0].display

    def host_get_info(self):
        info = {}
        dev = nb.dcim.devices.get(name=self.host)
        info["rack"] = dev.rack.display
        info["ru"] = str(dev.position)
        info["dev_type"] = dev.device_type.display
        info["sn"] = dev.serial
        info["cabinet"] = dev.location.display
        info["fac_id"] = dev.rack.facility_id
        return info

    def host_get_site(self):
        """
        Returns the site code of the device
        """
        device = nb.dcim.devices.get(name=self.host)
        return device.site.display

    def host_get_platform(self):
        """
        Returns the platform of the device
        """
        device = nb.dcim.devices.get(name=self.host)
        return device.platform.slug

    def host_get_role(self):
        """
        Returns the device role
        """
        device = nb.dcim.devices.get(name=self.host)
        return device.device_role.slug


class NewPortDescription:
    # Initialize jira and intf attributes.
    def __init__(self, jira, api, switch, intf):
        self.jira = jira
        self.switch = switch
        self.intf = intf
        self.api = api

    def update_port_desc(self, update):
        """
        Update port desc 'BB' to 'NETOPS-xxxx' or 'NETOPS-xxxx' to 'BB'
        """
        conn = dev_connect(self.switch)
        cmds = ["show interfaces " + str(self.intf) + " description"]
        output = conn.enable(cmds[0])
        desc = output[0]["result"]["interfaceDescriptions"][self.intf]["description"]
        if update == "drain":
            netops = desc.replace("BB", str(self.jira))
        elif update == "normalize":
            netops = desc.replace(str(self.jira), "BB")

        self.api.set_description(str(self.intf), netops)


class Jira:
    url = "https://packet.atlassian.net"

    def conn(self):
        """
        Open a connection to the Jira API
        """
        url = self.url
        user = os.getenv("JIRA_USER")
        token = os.getenv("JIRA_TOKEN")
        connect = JIRA(basic_auth=(user, token), server=url)
        return connect

    def update(self, data, ticket):
        """
        Update a Jira with a comment
        """
        connection = self.conn()
        connection.add_comment(ticket, data)

    def create(self, data):
        """
        Create a new Jira
        """
        connection = self.conn()
        issue = connection.create_issue(fields=data)
        return issue

    def link(self, no_jira, dco_jira):
        """
        Link the DCOPS and NETOPS jira
        """
        connection = self.conn()
        reason = "is blocked by"
        link = connection.create_issue_link(reason, inwardIssue=no_jira, outwardIssue=dco_jira)


class GNMI:
    def __init__(self, switch):
        self.switch = switch

    def get(self, path, datatype):
        """
        Input datatype options state, config, and opertational
        """
        switch = (self.switch, 6030)
        with gNMIclient(
            target=switch,
            username="admin",
            password=os.getenv("NOKIA_PW"),
            skip_verify=True,
        ) as gc:
            result = gc.get(path=[path], datatype=datatype)
            return result

    def setGroupConfigDiff(self, update):
        switch = (self.switch, 6030)
        with gNMIclient(
            target=switch,
            username="admin",
            password=os.getenv("NOKIA_PW"),
            skip_verify=True,
            show_diff="get",
        ) as gc:
            result = gc.set(update=update)
            return result

    def setConfigDiff(self, path, change):
        switch = (self.switch, 6030)
        with gNMIclient(
            target=switch,
            username="admin",
            password=os.getenv("NOKIA_PW"),
            skip_verify=True,
            show_diff="get",
        ) as gc:
            result = gc.set(update=[(path, change)])
            return result

    def setConfig(self, path, change):
        switch = (self.switch, 6030)
        with gNMIclient(
            target=switch,
            username="admin",
            password=os.getenv("NOKIA_PW"),
            skip_verify=True,
        ) as gc:
            result = gc.set(update=[(path, change)])
            return result

    def delConfig(self, path):
        switch = (self.switch, 6030)
        with gNMIclient(
            target=switch,
            username="admin",
            password=os.getenv("NOKIA_PW"),
            skip_verify=True,
        ) as gc:
            result = gc.set(delete=path)
            return result

    def gnmi_get_desc(self, intf):
        path = f"interface[name={intf}]"
        gnmiIntf = self.get(path, "state")
        intf_details = gnmiIntf["notification"][0]["update"][0]["val"]["description"]
        return intf_details

    def gnmi_drain_diff_intf(self, intf, desc, jira):
        before = desc
        after = desc.replace("BB", jira)
        diff = f"""A:{self.switch}# diff
      interface {intf}
-         description "{before}"
+         description "{after}"
              """
        print(diff)
        return diff

    def gnmi_norm_diff_intf(self, intf, desc, jira):
        before = desc
        after = desc.replace(jira, "BB")
        diff = f"""A:{self.switch}# diff
      interface {intf}
-         description "{before}"
+         description "{after}"
              """
        print(diff)
        return diff

    def gnmi_diff_deny(self, ip4, ip6):
        diff = f"""A:{self.switch}# diff
      network-instance default 
          protocols 
              bgp 
                  neighbor {ip4} 
+                     export-policy DENY
+                     import-policy DENY
                  neighbor {ip6} 
+                     export-policy DENY
+                     import-policy DENY  
-- * candidate shared default --[  ]--
        """
        print(diff)
        return diff

    def gnmi_diff_nodeny(self, ip4, ip6):
        diff = f"""A:{self.switch}# diff
      network-instance default 
          protocols 
              bgp 
                  neighbor {ip4} 
-                     export-policy DENY
-                     import-policy DENY
                  neighbor {ip6} 
-                     export-policy DENY
-                     import-policy DENY  
-- * candidate shared default --[  ]--
        """
        print(diff)
        return diff

    def gnmi_drain_peer(self, peer4, peer6):
        """
        Add neighbor {{peer}} route-map DENY in/out.
        """
        updates = []
        path_prefix_v4 = f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={peer4}]"
        exp4 = (path_prefix_v4, {"export-policy": "DENY"})
        imp4 = (path_prefix_v4, {"import-policy": "DENY"})
        path_prefix_v6 = f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={peer6}]"
        exp6 = (path_prefix_v6, {"export-policy": "DENY"})
        imp6 = (path_prefix_v6, {"import-policy": "DENY"})
        updates.append(exp4)
        updates.append(imp4)
        updates.append(exp6)
        updates.append(imp6)
        self.setGroupConfigDiff(updates)

    def gnmi_norm_peer(self, peer4, peer6):
        """
        Remove neighbor {{peer}} route-map DENY in/out.
        """
        updates = []
        updates.append(f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={peer4}]/import-policy")
        updates.append(f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={peer4}]/export-policy")
        updates.append(f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={peer6}]/import-policy")
        updates.append(f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={peer6}]/export-policy")
        self.delConfig(updates)

    def gnmi_drain_intf_desc(self, jira, intf):
        results = {}
        path = f"interface[name={intf}]"
        intf_details = self.gnmi_get_desc(intf)
        description = intf_details.replace("BB", jira)
        change = {"description": description}
        change_results = self.setConfigDiff(path, change)
        if isinstance(change_results, tuple):
            results["before"] = change_results[1][0][2]
            results["after"] = change_results[1][1][2]
        else:
            results["before"] = intf_details
            results["after"] = f"No Change on {self.switch}::{intf}"
        return results

    def gnmi_norm_intf_desc(self, jira, intf):
        results = {}
        path = f"interface[name={intf}]"
        intf_details = self.gnmi_get_desc(intf)
        description = intf_details.replace(jira, "BB")
        change = {"description": description}
        change_results = self.setConfigDiff(path, change)
        if isinstance(change_results, tuple):
            results["before"] = change_results[1][0][2]
            results["after"] = change_results[1][1][2]
        else:
            results["before"] = intf_details
            results["after"] = f"No Change on {self.switch}::{intf}"
        return results

    def gnmi_intf_data(self, intf):
        intf_data = {}
        intf_data["interval"] = 1.0
        intf_data["intf"] = intf
        intf_data["host"] = self.switch

        crc_err_path = f"interface[name={intf}]/ethernet/statistics/in-crc-error-frames"
        crc_err = self.get(crc_err_path, "state")
        intf_data["fcs_err"] = crc_err["notification"][0]["update"][0]["val"]

        totalrx_err_path = f"interface[name={intf}]/statistics/in-error-packets"
        totalrx_err = self.get(totalrx_err_path, "state")
        intf_data["totalrx_err"] = totalrx_err["notification"][0]["update"][0]["val"]

        totaltx_err_path = f"interface[name={intf}]/statistics/out-error-packets"
        totaltx_err = self.get(totaltx_err_path, "state")
        intf_data["totaltx_err"] = totaltx_err["notification"][0]["update"][0]["val"]

        count_clr_path = f"interface[name={intf}]/statistics/last-clear"
        count_clr = self.get(count_clr_path, "state")
        if count_clr["notification"][0].get("update", None):
            intf_data["count_clear"] = count_clr["notification"][0]["update"][0]["val"]
        else:
            intf_data["count_clear"] = "Never Cleared"

        flap_path = f"interface[name={intf}]/last-change"
        flap = self.get(flap_path, "state")
        intf_data["flap"] = flap["notification"][0]["update"][0]["val"]

        in_rate_path = f"interface[name={intf}]/traffic-rate/in-bps"
        in_rate = self.get(in_rate_path, "state")
        intf_data["in_rate"] = in_rate["notification"][0]["update"][0]["val"]

        out_rate_path = f"interface[name={intf}]/traffic-rate/out-bps"
        out_rate = self.get(out_rate_path, "state")
        intf_data["out_rate"] = out_rate["notification"][0]["update"][0]["val"]

        status_path = f"interface[name={intf}]/oper-state"
        status = self.get(status_path, "state")
        intf_data["status"] = status["notification"][0]["update"][0]["val"]

        protocol_path = f"interface[name={intf}]/subinterface[index=0]/oper-state"
        protocol = self.get(protocol_path, "state")
        intf_data["protocol"] = protocol["notification"][0]["update"][0]["val"]

        optic_type_path = f"interface[name={intf}]/transceiver/vendor-part-number"
        optic_type = self.get(optic_type_path, "state")
        intf_data["optic_type"] = optic_type["notification"][0]["update"][0]["val"]
        if "cwdm" in optic_type["notification"][0]["update"][0]["val"].lower():
            intf_data["fec_corr"] = "Not Supported"
            intf_data["fec_corr_time"] = "Not Supported"
            intf_data["fec_uncorr"] = "Not Supported"
            intf_data["fec_uncorr_time"] = "Not Supported"

        optic_sn_path = f"interface[name={intf}]/transceiver/serial-number"
        optic_sn = self.get(optic_sn_path, "state")
        intf_data["optic_sn"] = optic_sn["notification"][0]["update"][0]["val"]

        optic_temp_path = f"interface[name={intf}]/transceiver/temperature"
        optic_temp = self.get(optic_temp_path, "state")
        intf_data["optic_temp"] = f"{optic_temp['notification'][0]['update'][0]['val']['latest-value']}C"

        optic_voltage_path = f"interface[name={intf}]/transceiver/voltage"
        optic_voltage = self.get(optic_voltage_path, "state")
        intf_data["optic_voltage"] = f"{optic_voltage['notification'][0]['update'][0]['val']['latest-value']}V"

        # Mapping Arista Dictionary Keys with Nokia Dictionary Keys
        ch_detail = ["input-power", "output-power", "laser-bias-current"]
        ch_a_detail = ["optic_rx_ch", "optic_tx_ch", "tx_bias_"]
        for n_det, a_det in zip(ch_detail, ch_a_detail):
            for ch in ["1", "2", "3", "4"]:
                unit = "dBm"
                if a_det == "tx_bias_":
                    unit = "mA"
                key = f"{a_det}{ch}"
                param_path = f"interface[name={intf}]/transceiver/channel[index={ch}]/{n_det}/latest-value"
                param_results = self.get(param_path, "state")
                intf_data[key] = f"{param_results['notification'][0]['update'][0]['val']}{unit}"

        return intf_data

    def gnmi_intf_rate(self, intf):
        rate_data = {}
        rate_data["intf"] = intf
        rate_data["interval"] = 1.0

        in_rate_path = f"interface[name={intf}]/traffic-rate/in-bps"
        in_rate = self.get(in_rate_path, "state")
        rate_data["in_rate"] = bit_to_mbit(in_rate["notification"][0]["update"][0]["val"])

        out_rate_path = f"interface[name={intf}]/traffic-rate/out-bps"
        out_rate = self.get(out_rate_path, "state")
        rate_data["out_rate"] = bit_to_mbit(out_rate["notification"][0]["update"][0]["val"])

        return rate_data


def init_arguments():
    parser = argparse.ArgumentParser(
        description="Create an eapi.conf file for Arista switches, which drains/normalizes a link-in-question."
    )
    parser.add_argument(
        "-c",
        help="Create the eapi.conf file in your home directory.",
        action="store_true",
    )
    parser.add_argument("-u", help="Hostname of the upstream switch (SSPs and/or DSRs)")
    parser.add_argument("-d", help="Hostname of the downstream switch (DSRs and/or ESRs)")
    parser.add_argument("-j", help="Jira NETOPS ticket number (NETOPS-XXXX).")
    parser.add_argument(
        "--drain",
        default=None,
        help="Drain traffic for a link-in-question",
        action="store_true",
    )
    parser.add_argument(
        "--normalize",
        default=None,
        help="Normalize traffic for a link-in-question",
        action="store_true",
    )
    parser.add_argument(
        "--jira",
        default=None,
        help="Post note to Jira ticket",
        action="store_true",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-o",
        "--onsite",
        default=None,
        help="Create an Onsite Jira for DCOPS",
        action="store_true",
    )
    group.add_argument(
        "-s",
        "--smarthands",
        default=None,
        help="Create a Smart Hands Request for the IBX team",
        action="store_true",
    )
    arguments = parser.parse_args()
    return arguments


def init_ecx():
    """
    Initialize ECX
    """
    key = os.getenv("EQUINIX_CONSUMER_KEY")
    secret = os.getenv("EQUINIX_CONSUMER_SECRET")
    return ECX(ECX_URL, key, secret)


def check_eapi_conf_file():
    """
    Check if ~/.eapi.conf file already exists.
    Delete the eapi.conf file
    """
    eapi_conf_path = Path.home() / ".eapi.conf"

    if eapi_conf_path.exists():
        eapi_conf_path.unlink()


def check_jira_configuration(args):
    """
    Returns True when JIRA_TOKEN and JIRA_USER environment variables are set
    """
    if args.jira:
        for var in [
            "JIRA_USER",
            "JIRA_TOKEN",
        ]:
            if not os.getenv(var):
                print(f"ERROR: Environment variable {var} is not set")
                sys.exit()
        return True
    else:
        return False


def check_ECP_configuration(args):
    """
    Check for EQUINIX_CONSUMER_KEY and EQUINIX_CONSUMER_SECRET environment variables if args.smarthands is True
    """
    if args.smarthands:
        for var in [
            "EQUINIX_CONSUMER_KEY",
            "EQUINIX_CONSUMER_SECRET",
        ]:
            if not os.getenv(var):
                print(f"ERROR: Environment variable {var} is not set")
                sys.exit()


def check_env():
    """
    Script checks for Environment Variables properly set
    """
    missingVars = []
    for var in ["NB_API_KEY", "ARISTA_PW", "NOKIA_PW"]:
        if not os.getenv(var):
            missingVars.append(f"ERROR: Environment variable {var} is not set")

    if missingVars:
        for line in missingVars:
            print(line)
        sys.exit()


def intended_interface(upstrm_dev, dwnstrm_dev):
    """
    This function checks if there are multiple links between the uplink and downlink
    If multiple links found then user input is needed
    This function will verify that the downstream and upstream arguments match what is in Netbox
    """
    upstrm_hostname = upstrm_dev
    dwnstrm_hostname = dwnstrm_dev
    interfaces = nb.dcim.interfaces.filter(device=upstrm_hostname, connected="true")
    upstrm_intf_ls = [
        intf.display
        for intf in interfaces
        if intf.connected_endpoints_type == "dcim.interface"
        and intf.connected_endpoints[0].device.display == dwnstrm_hostname
    ]
    if len(upstrm_intf_ls) >= 2:
        selections = []
        for i in range(len(upstrm_intf_ls)):
            print(f"Interface Name: {upstrm_intf_ls[i]}::Interface number: {str(i)} ")
            selections.append(str(i))
        results = True
        while results:
            options = [int(option) for option in selections]
            user_input = input(f"Type the interface number that needs to be drained {options}:\n")
            if str(user_input) in selections:
                results = False
            else:
                results = True
        upstrm_intf = upstrm_intf_ls[int(user_input)]
    elif len(upstrm_intf_ls) == 1:
        upstrm_intf = upstrm_intf_ls[0]
    else:
        sys.exit(f"{upstrm_hostname} and {dwnstrm_hostname} not connected in Netbox, correct this first and then retry")

    return upstrm_intf


def append_multiple_lines(file_name, host, pass_word):
    """
    Append hostnames and credentials in the file.
    """
    lines_to_append = [
        f"[connection:{host}.packet.net]\n",
        f"host: {host}{DOMAIN}\n",
        "username: admin\n",
        f"password: {pass_word}\n",
        f"transport: https\n",
    ]
    with open(file_name, "a") as file_object:
        for line in lines_to_append:
            file_object.write(line)


# Nokia Playbook
def gnmi_commit():
    """
    User can commit, abort, or cancel the config session.
    """
    pending_config = True
    commit = True
    while pending_config:
        resp = input("Type 'yes' to commit, 'no' to abort and 'cancel' to exit: ").strip()
        if resp.lower() == "yes":
            pending_config = False
        elif resp.lower() == "no":
            print("Configure session Aborted.")
            pending_config = False
            commit = False
        elif resp.lower() == "cancel":
            print("Config session aborted.\nScript terminated.")
            sys.exit()
        else:
            print("\nInvalid input!")

    return commit


def gnmi_upstream_drain_playbook(host, nb_host, jira):
    """
    This is the Drain Playbook that will complete on an Upstream Peer
    that is also a Nokia switch
    """
    diff = []
    print(f"\nConnecting to {host}...")
    neighbor_v4 = nb_host.nb_get_device_neighbor_ipv4()
    neighbor_v6 = nb_host.nb_get_device_neighbor_ipv6()
    intf = nb_host.local_intf()
    gnmiHost = GNMI(host)
    intf_desc = gnmiHost.gnmi_get_desc(intf)
    print("This is what you're about to commit:\n")
    print("#" * 70)
    diff.append(gnmiHost.gnmi_drain_diff_intf(intf, intf_desc, jira))
    diff.append(gnmiHost.gnmi_diff_deny(neighbor_v4, neighbor_v6))
    print("#" * 70)
    commit_results = gnmi_commit()
    if commit_results == True:
        intf_data = gnmiHost.gnmi_intf_data(intf)
        gnmiHost.gnmi_drain_intf_desc(jira, intf)
        gnmiHost.gnmi_drain_peer(neighbor_v4, neighbor_v6)
        uplink_diff = diff
    else:
        intf_data = None
        uplink_diff = f"\nNo Changes were made on {host}\n"

    return uplink_diff, intf_data


def gnmi_downstream_drain_playbook(host, nb_host, jira):
    """
    This is the Drain Playbook that will complete on a Downstream Peer
    that is also a Nokia switch
    """
    diff = []
    print(f"Connecting to {host}...")
    intf = nb_host.local_intf()
    gnmiHost = GNMI(host)
    intf_desc = gnmiHost.gnmi_get_desc(intf)
    print("This is what you're about to commit:\n")
    print("#" * 70)
    diff.append(gnmiHost.gnmi_drain_diff_intf(intf, intf_desc, jira))
    print("#" * 70)
    commit_results = gnmi_commit()
    if commit_results == True:
        gnmiHost.gnmi_drain_intf_desc(jira, intf)
        intf_data = gnmiHost.gnmi_intf_data(intf)
        uplink_diff = diff
    else:
        intf_data = None
        uplink_diff = f"\nNo Changes were made on {host}\n"

    return uplink_diff, intf_data


def gnmi_upstream_norm_playbook(host, nb_host, jira):
    """
    This is the Normalize Playbook that will complete on an Upstream Peer
    that is also a Nokia switch
    """
    diff = []
    print(f"\nConnecting to {host}...")
    neighbor_v4 = nb_host.nb_get_device_neighbor_ipv4()
    neighbor_v6 = nb_host.nb_get_device_neighbor_ipv6()
    intf = nb_host.local_intf()
    gnmiHost = GNMI(host)
    intf_desc = gnmiHost.gnmi_get_desc(intf)
    print("This is what you're about to commit:\n")
    print("#" * 70)
    diff.append(gnmiHost.gnmi_norm_diff_intf(intf, intf_desc, jira))
    diff.append(gnmiHost.gnmi_diff_nodeny(neighbor_v4, neighbor_v6))
    print("#" * 70)
    commit_results = gnmi_commit()
    if commit_results == True:
        gnmiHost.gnmi_norm_peer(neighbor_v4, neighbor_v6)
        gnmiHost.gnmi_norm_intf_desc(jira, intf)
        intf_data = gnmiHost.gnmi_intf_data(intf)
        uplink_diff = diff
    else:
        intf_data = None
        uplink_diff = f"\nNo Changes were made on {host}\n"

    return uplink_diff, intf_data


def gnmi_downstream_norm_playbook(host, nb_host, jira):
    """
    This is the Normalize Playbook that will complete on a Downstream Peer
    that is also a Nokia switch
    """
    diff = []
    print(f"Connecting to {host}...")
    intf = nb_host.local_intf()
    gnmiHost = GNMI(host)
    intf_desc = gnmiHost.gnmi_get_desc(intf)
    print("This is what you're about to commit:\n")
    print("#" * 70)
    diff.append(gnmiHost.gnmi_norm_diff_intf(intf, intf_desc, jira))
    print("#" * 70)
    commit_results = gnmi_commit()
    if commit_results == True:
        gnmiHost.gnmi_norm_intf_desc(jira, intf)
        intf_data = gnmiHost.gnmi_intf_data(intf)
        uplink_diff = diff
    else:
        intf_data = None
        uplink_diff = f"\nNo Changes were made on {host}\n"

    return uplink_diff, intf_data


def gnmi_get_bgp_info(host, neighv4, neighv6):
    bgp_prefixes = []
    pathv4 = f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={neighv4}]"
    pathv6 = f"network-instance[name=default]/protocols/bgp/neighbor[peer-address={neighv6}]"
    gnmiHost = GNMI(host)
    v4_op_data = gnmiHost.get(pathv4, "operational")
    results = v4_op_data["notification"][0]["update"][0]["val"]
    peergroupv4 = results["peer-group"]
    bgp_statev4 = results["session-state"].capitalize()
    v4_bgp_pref = [
        results["afi-safi"][i]["active-routes"]
        for i in range(len(results["afi-safi"]))
        if "ipv4-unicast" in results["afi-safi"][i]["afi-safi-name"]
    ]
    if v4_bgp_pref:
        bgp_prefixes.append(v4_bgp_pref[0])
    else:
        bgp_prefixes.append("None")
    v6_op_data = gnmiHost.get(pathv6, "operational")
    results = v6_op_data["notification"][0]["update"][0]["val"]
    peergroupv6 = results["peer-group"]
    bgp_statev6 = results["session-state"].capitalize()
    v6_bgp_pref = [
        results["afi-safi"][i]["active-routes"]
        for i in range(len(results["afi-safi"]))
        if "ipv6-unicast" in results["afi-safi"][i]["afi-safi-name"]
    ]
    if v6_bgp_pref:
        bgp_prefixes.append(v6_bgp_pref[0])
    else:
        bgp_prefixes.append("None")

    bgp_info = (peergroupv4, bgp_statev4, peergroupv6, bgp_statev6)
    return bgp_prefixes, bgp_info


def gnmi_handle_intf_stats(host, intf):
    USER_RESP = True
    while USER_RESP:
        gnmiHost = GNMI(host)
        intf_data = gnmiHost.gnmi_intf_rate(intf)
        print_intf_stats(intf_data)
        response = input("\nType 'y' to refresh intf stats and 'n' to abort: ")
        if response.lower() == "n":
            USER_RESP = False


# Arista eapi and Playbook
def dev_connect(host):
    """
    Connection to a device.
    """
    try:
        dev = pyeapi.connect_to(host + DOMAIN)
        return dev
    except AttributeError as e:
        print("#" * 30)
        print(f"Error {e} file encountered\neAPI config file for {host} missing\nre-run script with '-c' option")
        print("#" * 30)
        sys.exit()


def eapi_drain_peer(neigh, bgp, conn):
    """
    Add neighbor {{peer-ipv4}} route-map DENY in/out.
    """
    bgp.neighbors.set_route_map_in(neigh, "DENY")
    bgp.neighbors.set_route_map_out(neigh, "DENY")


def eapi_normalize_peer(neigh, bgp, conn, host=""):
    """
    Re-create the neighbor and description.
    """
    bgp.neighbors.delete(neigh)
    bgp.neighbors.create(neigh)
    bgp.neighbors.set_description(neigh, str(host))


def eapi_no_shut_peergroup(neigh, bgp, peergroup=""):
    """
    Remove the 'shutdown' statement.
    Define the neighbor to correct peer-group.
    """
    bgp.neighbors.set_shutdown(neigh, "")
    bgp.neighbors.ispeergroup(peergroup)
    bgp.neighbors.set_peer_group(neigh, peergroup)


def eapi_get_bgp_peergroup(host, neighv4, neighv6):
    """
    Get the downstream bgp peer-group and state for v4/v6.
    """
    conn = dev_connect(host)
    cmds = [f"show bgp neighbors {str(neighv4)}", f"show bgp neighbors {str(neighv6)}"]
    output_v4 = conn.enable(cmds[0])
    peer_listv4 = output_v4[0]["result"]["vrfs"]["default"]["peerList"]
    peergroupv4 = peer_listv4[0]["peerGroupName"]
    bgp_statev4 = peer_listv4[0]["state"]
    output_v6 = conn.enable(cmds[1])
    peer_listv6 = output_v6[0]["result"]["vrfs"]["default"]["peerList"]
    peergroupv6 = peer_listv6[0]["peerGroupName"]
    bgp_statev6 = peer_listv6[0]["state"]
    return peergroupv4, bgp_statev4, peergroupv6, bgp_statev6


def eapi_get_bgp_pref_accptd(host, neighv4, neighv6):
    """
    Get the number of prefixes(v4/v6) accepted by the upstream switch.
    """
    conn = dev_connect(host)
    output = []
    cmds = ["show ip bgp summary", "show ipv6 bgp summary"]
    output_v4 = conn.enable(cmds[0])
    prefix_v4 = output_v4[0]["result"]["vrfs"]["default"]["peers"][neighv4]["prefixAccepted"]
    output_v6 = conn.enable(cmds[1])
    prefix_v6 = output_v6[0]["result"]["vrfs"]["default"]["peers"][neighv6]["prefixAccepted"]
    output.append(prefix_v4)
    output.append(prefix_v6)
    return output


def eapi_upstream_drain_playbook(upstrm_hostname, netbox_upstrm, jira):
    """
    This is the Drain Playbook that will complete on an Upstream Peer
    that is also an Arista switch
    """
    print(f"\nConnecting to {upstrm_hostname}...")
    upstrm_conn = dev_connect(upstrm_hostname)
    neighbor_v4 = netbox_upstrm.nb_get_device_neighbor_ipv4()
    neighbor_v6 = netbox_upstrm.nb_get_device_neighbor_ipv6()
    bgp = upstrm_conn.api("bgp")
    interfaces = upstrm_conn.api("interfaces")
    upstrm_conn.configure_session()
    eapi_drain_peer(neighbor_v4, bgp, upstrm_conn)
    eapi_drain_peer(neighbor_v6, bgp, upstrm_conn)
    intf_desc = NewPortDescription(jira, interfaces, upstrm_hostname, netbox_upstrm.intf)
    intf_desc.update_port_desc("drain")
    print(f"\nUPSTREAM SWITCH: {upstrm_hostname}")
    uplink_diff = config_resp(upstrm_conn)
    return uplink_diff


def eapi_downstream_drain_playbook(dwnstrm_hostname, netbox_dwnstrm, jira):
    """
    This is the Drain Playbook that will complete on a Downstream Peer
    that is also an Arista switch
    """
    print(f"Connecting to {dwnstrm_hostname}...")
    dwnstrm_conn = dev_connect(dwnstrm_hostname)
    interfaces = dwnstrm_conn.api("interfaces")
    dwnstrm_conn.configure_session()
    intf_desc = NewPortDescription(jira, interfaces, dwnstrm_hostname, netbox_dwnstrm.intf)
    intf_desc.update_port_desc("drain")
    print(f"\nDOWNSTREAM SWITCH: {dwnstrm_hostname}")
    downlink_diff = config_resp(dwnstrm_conn)

    return downlink_diff


def eapi_upstream_normalize_playbook(upstrm_hostname, netbox_upstrm, jira):
    """
    This is the Normalize Playbook that will complete on an Upstream Peer
    that is also an Arista switch
    """
    print(f"\nConnecting to {upstrm_hostname}...")
    upstrm_conn = dev_connect(upstrm_hostname)
    neighbor_v4 = netbox_upstrm.nb_get_device_neighbor_ipv4()
    neighbor_v6 = netbox_upstrm.nb_get_device_neighbor_ipv6()
    dwnstrm_hostname = next(iter(netbox_upstrm.nb_get_device_neighbor_endpoint()))
    bgp = upstrm_conn.api("bgp")
    interfaces = upstrm_conn.api("interfaces")
    upstrm_conn.configure_session()
    bgp_info = eapi_get_bgp_peergroup(upstrm_hostname, neighbor_v4, neighbor_v6)

    eapi_normalize_peer(neighbor_v4, bgp, upstrm_conn, dwnstrm_hostname)
    eapi_no_shut_peergroup(neighbor_v4, bgp, peergroup=bgp_info[0])

    eapi_normalize_peer(neighbor_v6, bgp, upstrm_conn, dwnstrm_hostname)
    eapi_no_shut_peergroup(neighbor_v6, bgp, peergroup=bgp_info[2])

    intf_desc = NewPortDescription(jira, interfaces, upstrm_hostname, netbox_upstrm.intf)
    intf_desc.update_port_desc("normalize")
    print(f"\nUPSTREAM SWITCH: {upstrm_hostname}")
    uplink_diff = config_resp(upstrm_conn)

    return uplink_diff


def eapi_downstream_normalize_playbook(dwnstrm_hostname, netbox_dwnstrm, jira):
    """
    This is the Normalize Playbook that will complete on a Downstream Peer
    that is also an Arista switch
    """
    print(f"Connecting to {dwnstrm_hostname}...")
    dwnstrm_conn = dev_connect(dwnstrm_hostname)
    interfaces = dwnstrm_conn.api("interfaces")
    dwnstrm_conn.configure_session()
    intf_desc = NewPortDescription(jira, interfaces, dwnstrm_hostname, netbox_dwnstrm.intf)
    intf_desc.update_port_desc("normalize")
    print(f"\nDOWNSTREAM SWITCH: {dwnstrm_hostname}")
    downlink_diff = config_resp(dwnstrm_conn)

    return downlink_diff


def eapi_clear_counters(host, intf):
    """
    Clear Interface Counters
    """
    conn = dev_connect(host)
    cmd = f"clear counters {intf}"
    output = conn.enable(cmd)


def eapi_get_intf_stats(host, intf):
    """
    Get intf input/ouput byte rate stats.
    30-sec update interval.
    """
    intf_data = {}
    conn = dev_connect(host)
    cmd = [
        f"show interfaces {intf}",
        f"show interfaces {intf} phy detail",
        f"show interfaces {intf} transceiver dom",
    ]
    output = conn.enable(cmd[0])
    phy_output = conn.enable(cmd[1])
    optic_output = conn.enable(cmd[2])
    intf_stats = output[0]["result"]["interfaces"][intf]
    intf_phy_stats = phy_output[0]["result"]["interfacePhyStatuses"][intf]
    intf_optic_stats = optic_output[0]["result"]["interfaces"][intf]
    fec_stats = phy_output[0]["result"]["interfacePhyStatuses"][intf]["phyStatuses"]
    in_bit = intf_stats["interfaceStatistics"]["inBitsRate"]
    out_bit = intf_stats["interfaceStatistics"]["outBitsRate"]
    new_in_bit = bit_to_mbit(in_bit)
    new_out_bit = bit_to_mbit(out_bit)
    flap = intf_stats["lastStatusChangeTimestamp"]
    count_clr = intf_stats["interfaceCounters"].get("lastClear", None)
    intf_data["host"] = host
    intf_data["intf"] = intf
    intf_data["optic_sn"] = intf_phy_stats["transceiver"]["vendorSn"]
    # Loop for rxPower and txPower
    for param in ["rxPower", "txPower"]:
        unit = intf_optic_stats["parameters"][param]["unit"]
        for ch in ["1", "2", "3", "4"]:
            key = f"optic_{param.replace('Power','')}_ch{ch}"
            value = str(round(intf_optic_stats["parameters"][param]["channels"][ch], 3)) + unit
            intf_data[key] = value
    # Loop for txBias
    unit = intf_optic_stats["parameters"]["txBias"]["unit"]
    for ch in ["1", "2", "3", "4"]:
        key = f"tx_bias_{ch}"
        value = str(intf_optic_stats["parameters"]["txBias"]["channels"][ch]) + unit
        intf_data[key] = value
    intf_data["optic_type"] = intf_phy_stats["transceiver"]["mediaType"]["value"]
    unit = intf_optic_stats["parameters"]["temperature"]["unit"]
    intf_data["optic_temp"] = str(round(intf_optic_stats["parameters"]["temperature"]["channels"]["-"], 2)) + unit
    unit = intf_optic_stats["parameters"]["voltage"]["unit"]
    intf_data["optic_voltage"] = str(round(intf_optic_stats["parameters"]["voltage"]["channels"]["-"], 3)) + unit
    intf_data["in_rate"] = new_in_bit
    intf_data["out_rate"] = new_out_bit
    intf_data["interval"] = intf_stats["interfaceStatistics"]["updateInterval"]
    intf_data["fcs_err"] = str(intf_stats["interfaceCounters"]["inputErrorsDetail"]["fcsErrors"])
    intf_data["totalrx_err"] = str(intf_stats["interfaceCounters"]["totalInErrors"])
    intf_data["totaltx_err"] = str(intf_stats["interfaceCounters"]["totalOutErrors"])
    intf_data["status"] = intf_stats["interfaceStatus"]
    intf_data["protocol"] = intf_stats["lineProtocolStatus"]
    if count_clr:
        intf_data["count_clear"] = datetime.datetime.fromtimestamp(count_clr).strftime("%c")
    else:
        intf_data["count_clear"] = "Never Cleared"
    intf_data["flap"] = datetime.datetime.fromtimestamp(flap).strftime("%c")
    if "cwdm" in intf_data["optic_type"].lower():
        intf_data["fec_corr"] = fec_stats[0]["fec"]["correctedCodewords"]["changes"]
        intf_data["fec_corr_time"] = datetime.datetime.fromtimestamp(
            fec_stats[0]["fec"]["correctedCodewords"]["lastChange"]
        ).strftime("%c")
        intf_data["fec_uncorr"] = fec_stats[0]["fec"]["uncorrectedCodewords"]["changes"]
        intf_data["fec_uncorr_time"] = datetime.datetime.fromtimestamp(
            fec_stats[0]["fec"]["uncorrectedCodewords"]["lastChange"]
        ).strftime("%c")
    return intf_data


def eapi_check_pending_conf(host):
    """
    Check pending config session(s) and flush them out.
    """
    conn = dev_connect(host)
    cmds = ["show configuration sessions", "no configure session "]
    output = conn.enable(cmds[0])
    pend_sess = output[0]["result"]["sessions"]
    print(f"\nChecking {host} for any pending config sessions:")
    if len(pend_sess.keys()) == 0:
        print(f"RESULT: No pending config sessions found on {host}.")
    if len(pend_sess.keys()) > 0:
        count = len(pend_sess.keys())
        print(f"RESULT: {count} pending config session(s) found on {host}.")
        for session in pend_sess.keys():
            print(f"removing session: {session}")
            output = conn.enable(cmds[1] + session)


def handle_intf_stats(upstrm_hostname, upstrm_intf):
    USER_RESP = True
    while USER_RESP:
        intf_data = eapi_get_intf_stats(upstrm_hostname, upstrm_intf)
        print_intf_stats(intf_data)
        response = input("\nType 'y' to refresh intf stats and 'n' to abort: ")
        if response.lower() == "n":
            USER_RESP = False


def print_intf_stats(intf_data):
    """
    Displays Interface speed rate
    """
    print(f"\nInterface {intf_data['intf']} stats:\n")
    print(f"Input rate      : {intf_data['in_rate']}")
    print(f"Output rate     : {intf_data['out_rate']}")
    print(f"Update interval : {intf_data['interval']} secs")


def display_bgp_results(bgp_info, v4, v6, bgp_prefixes):
    """
    Displays BGP prefixes learned and advertised
    """
    print(f"\nIPv4 Peer IP         : {v4}")
    print(f"IPv4 BGP Status      : {bgp_info[1]}")
    print(f"IPv4 Peer group      : {bgp_info[0]}")
    print(f"\nIPv6 Peer IP         : {v6}")
    print(f"IPv6 BGP Status      : {bgp_info[3]}")
    print(f"IPv6 Peer group      : {bgp_info[2]}")
    print("\nPrefix count:")
    print(f"IPv4 Prefix Accepted : {bgp_prefixes[0]}")
    print(f"IPv6 Prefix Accepted : {bgp_prefixes[1]}")


def bit_to_mbit(bits):
    """
    Conversion tool used to convert bits to Mbits.
    Return is formatted speed rounded upto the nearest 100th
    """
    data_in_bits = int(bits)
    megabits = round(data_in_bits / 1048576, 2)
    formatted_speed = f"{megabits} mbits/s" if megabits > 1 else f"{round(data_in_bits,2)} bits/s"
    return formatted_speed


def config_resp(conn):
    """
    User can commit, abort, or cancel the config session.
    """
    diff_results = conn.diff()
    print("This is what you're about to commit:\n")
    print("#" * 70)
    print(diff_results)
    print("#" * 70)

    pending_config = True
    while pending_config:
        resp = input("Type 'yes' to commit, 'no' to abort and 'cancel' to exit: ").strip()
        if resp.lower() == "yes":
            conn.commit()
            print("Committed.")
            return diff_results
        elif resp.lower() == "no":
            conn.abort()
            message = "Configure session Aborted. Config was not commited"
            print(message)
            return message
        elif resp.lower() == "cancel":
            conn.abort()
            print("Config session aborted.\nScript terminated.")
            sys.exit()
        elif resp.lower():
            print("\nInvalid input!")


def create_jira_note(
    bgp_info,
    netbox_upstrm,
    netbox_dwnstrm,
    prfx,
    up_data,
    down_data,
    up_diff,
    down_diff,
):
    """
    This function builds the note used in the NETOPS Jira
    """
    output_data = []
    a_info = netbox_upstrm.host_get_info()
    z_info = netbox_dwnstrm.host_get_info()
    output_data.append("{code:PlainText}")
    output_data.append(f"IPv4 Peer IP: {netbox_upstrm.nb_get_device_neighbor_ipv4()}")
    output_data.append(f"IPv4 BGP Status: {bgp_info[1]}")
    output_data.append(f"IPv4 Peer group: {bgp_info[0]}")
    output_data.append(f"IPv4 Accepted: {prfx[0]}")
    output_data.append(f"IPv6 Peer IP: {netbox_upstrm.nb_get_device_neighbor_ipv6()}")
    output_data.append(f"IPv6 BGP Status: {bgp_info[3]}")
    output_data.append(f"IPv6 Peer group: {bgp_info[2]}")
    output_data.append(f"IPv6 Accepted: {prfx[1]}")
    output_data.append(f"{up_diff}")
    output_data.append(f"{down_diff}")
    output_data.append("{code}")
    output_data.append(f"||*Interface Stats*||*{up_data['host']}*||*{down_data['host']}*||")
    output_data.append(f"|Port|{up_data['intf']}|{down_data['intf']}|")
    output_data.append(f"|Status|{up_data['status']}|{down_data['status']}|")
    output_data.append(f"|Line Protocol|{up_data['protocol']}|{down_data['protocol']}|")
    output_data.append(f"|Last Flap|{up_data['flap']}|{down_data['flap']}|")
    output_data.append(f"|Rx FCS Errors|{up_data['fcs_err']}|{down_data['fcs_err']}|")
    output_data.append(f"|Total Rx Errors|{up_data['totalrx_err']}|{down_data['totalrx_err']}|")
    output_data.append(f"|Total Tx Errors|{up_data['totaltx_err']}|{down_data['totaltx_err']}|")
    output_data.append(f"|Counters Cleared|{up_data['count_clear']}|{down_data['count_clear']}|")
    output_data.append("\n")
    output_data.append(f"||*Hardware Data*||*{up_data['host']}*||*{down_data['host']}*||")
    output_data.append(f"|Rack|{a_info['rack']}|{z_info['rack']}|")
    output_data.append(f"|RU|{a_info['ru']}|{z_info['ru']}|")
    output_data.append(f"|SN|{a_info['sn']}|{z_info['sn']}|")
    output_data.append(f"|Type|{a_info['dev_type']}|{z_info['dev_type']}|")
    output_data.append("\n")
    output_data.append(f"||*Optics Data*||*{up_data['host']}*||*{down_data['host']}*||")
    output_data.append(f"|Optic SN|{up_data['optic_sn']}|{down_data['optic_sn']}|")
    output_data.append(f"|Optic Type|{up_data['optic_type']}|{down_data['optic_type']}|")
    output_data.append(f"|Optic Temp|{up_data['optic_temp']}|{down_data['optic_temp']}|")
    output_data.append(f"|Optic Voltage|{up_data['optic_voltage']}|{down_data['optic_voltage']}|")
    if "cwdm" in up_data["optic_type"].lower():
        output_data.append(f"|FEC Corrected|{up_data['fec_corr']}|{down_data['fec_corr']}|")
        output_data.append(f"|FEC Corrected Occurence|{up_data['fec_corr_time']}|{down_data['fec_corr_time']}|")
        output_data.append(f"|FEC Uncorrected|{up_data['fec_uncorr']}|{down_data['fec_uncorr']}|")
        output_data.append(f"|FEC Uncorrected Occurence|{up_data['fec_uncorr_time']}|{down_data['fec_uncorr_time']}|")
    else:
        pass
    output_data.append("|{color:#ff5630}Receive Channels{color}| | |")
    output_data.append(f"|Rx Channel 1 Lvl|{up_data['optic_rx_ch1']}|{down_data['optic_rx_ch1']}|")
    output_data.append(f"|Rx Channel 2 Lvl|{up_data['optic_rx_ch2']}|{down_data['optic_rx_ch2']}|")
    output_data.append(f"|Rx Channel 3 Lvl|{up_data['optic_rx_ch3']}|{down_data['optic_rx_ch3']}|")
    output_data.append(f"|Rx Channel 4 Lvl|{up_data['optic_rx_ch4']}|{down_data['optic_rx_ch4']}|")
    output_data.append("|{color:#ff5630}Transmit Channels{color}| | |")
    output_data.append(f"|Tx Channel 1 Lvl|{up_data['optic_tx_ch1']}|{down_data['optic_tx_ch1']}|")
    output_data.append(f"|Tx Channel 2 Lvl|{up_data['optic_tx_ch2']}|{down_data['optic_tx_ch2']}|")
    output_data.append(f"|Tx Channel 3 Lvl|{up_data['optic_tx_ch3']}|{down_data['optic_tx_ch3']}|")
    output_data.append(f"|Tx Channel 4 Lvl|{up_data['optic_tx_ch4']}|{down_data['optic_tx_ch4']}|")
    output_data.append("|{color:#ff5630}txBias Current{color}| | |")
    output_data.append(f"|Tx Bias Current 1|{up_data['tx_bias_1']}|{down_data['tx_bias_1']}|")
    output_data.append(f"|Tx Bias Current 2|{up_data['tx_bias_2']}|{down_data['tx_bias_2']}|")
    output_data.append(f"|Tx Bias Current 3|{up_data['tx_bias_3']}|{down_data['tx_bias_3']}|")
    output_data.append(f"|Tx Bias Current 4|{up_data['tx_bias_4']}|{down_data['tx_bias_4']}|")
    output = "\n".join(output_data)
    return output


def create_dcops_note(bgp_info, nei4, nei6, prfx, up_data, down_data, up_diff, down_diff, a_info, z_info):
    """
    This builds the comment that is placed in the Onsite Jira
    """
    output_data = []
    output_data.append(f"||*Interface Stats*||*{up_data['host']}*||*{down_data['host']}*||")
    output_data.append(f"|Port|{up_data['intf']}|{down_data['intf']}|")
    output_data.append(f"|Status|{up_data['status']}|{down_data['status']}|")
    output_data.append(f"|Line Protocol|{up_data['protocol']}|{down_data['protocol']}|")
    output_data.append(f"|Last Flap|{up_data['flap']}|{down_data['flap']}|")
    output_data.append(f"|Rx FCS Errors|{up_data['fcs_err']}|{down_data['fcs_err']}|")
    output_data.append(f"|Total Rx Errors|{up_data['totalrx_err']}|{down_data['totalrx_err']}|")
    output_data.append(f"|Total Tx Errors|{up_data['totaltx_err']}|{down_data['totaltx_err']}|")
    output_data.append(f"|Counters Cleared|{up_data['count_clear']}|{down_data['count_clear']}|")
    output_data.append("\n")
    output_data.append(f"||*Hardware Data*||*{up_data['host']}*||*{down_data['host']}*||")
    output_data.append(f"|Rack|{a_info['rack']}|{z_info['rack']}|")
    output_data.append(f"|RU|{a_info['ru']}|{z_info['ru']}|")
    output_data.append(f"|SN|{a_info['sn']}|{z_info['sn']}|")
    output_data.append(f"|Type|{a_info['dev_type']}|{z_info['dev_type']}|")
    output_data.append("\n")
    output_data.append(f"||*Optics Data*||*{up_data['host']}*||*{down_data['host']}*||")
    output_data.append(f"|Optic SN|{up_data['optic_sn']}|{down_data['optic_sn']}|")
    output_data.append(f"|Optic Type|{up_data['optic_type']}|{down_data['optic_type']}|")
    output_data.append(f"|Optic Temp|{up_data['optic_temp']}|{down_data['optic_temp']}|")
    output_data.append(f"|Optic Voltage|{up_data['optic_voltage']}|{down_data['optic_voltage']}|")
    if "cwdm" in up_data["optic_type"].lower():
        output_data.append(f"|FEC Corrected|{up_data['fec_corr']}|{down_data['fec_corr']}|")
        output_data.append(f"|FEC Corrected Occurence|{up_data['fec_corr_time']}|{down_data['fec_corr_time']}|")
        output_data.append(f"|FEC Uncorrected|{up_data['fec_uncorr']}|{down_data['fec_uncorr']}|")
        output_data.append(f"|FEC Uncorrected Occurence|{up_data['fec_uncorr_time']}|{down_data['fec_uncorr_time']}|")
    else:
        pass
    output_data.append("|{color:#ff5630}Receive Channels{color}| | |")
    output_data.append(f"|Rx Channel 1 Lvl|{up_data['optic_rx_ch1']}|{down_data['optic_rx_ch1']}|")
    output_data.append(f"|Rx Channel 2 Lvl|{up_data['optic_rx_ch2']}|{down_data['optic_rx_ch2']}|")
    output_data.append(f"|Rx Channel 3 Lvl|{up_data['optic_rx_ch3']}|{down_data['optic_rx_ch3']}|")
    output_data.append(f"|Rx Channel 4 Lvl|{up_data['optic_rx_ch4']}|{down_data['optic_rx_ch4']}|")
    output_data.append("|{color:#ff5630}Transmit Channels{color}| | |")
    output_data.append(f"|Tx Channel 1 Lvl|{up_data['optic_tx_ch1']}|{down_data['optic_tx_ch1']}|")
    output_data.append(f"|Tx Channel 2 Lvl|{up_data['optic_tx_ch2']}|{down_data['optic_tx_ch2']}|")
    output_data.append(f"|Tx Channel 3 Lvl|{up_data['optic_tx_ch3']}|{down_data['optic_tx_ch3']}|")
    output_data.append(f"|Tx Channel 4 Lvl|{up_data['optic_tx_ch4']}|{down_data['optic_tx_ch4']}|")
    output_data.append("|{color:#ff5630}txBias Current{color}| | |")
    output_data.append(f"|Tx Bias Current 1|{up_data['tx_bias_1']}|{down_data['tx_bias_1']}|")
    output_data.append(f"|Tx Bias Current 2|{up_data['tx_bias_2']}|{down_data['tx_bias_2']}|")
    output_data.append(f"|Tx Bias Current 3|{up_data['tx_bias_3']}|{down_data['tx_bias_3']}|")
    output_data.append(f"|Tx Bias Current 4|{up_data['tx_bias_4']}|{down_data['tx_bias_4']}|")
    output = "\n".join(output_data)
    return output


def create_onsite_desc(user_note, up_data, down_data, a_info, z_info, site_code):
    """
    This is the Note that will used to create the Onsite Jira
    """
    subject = f"{site_code} | Network Request ({up_data['host']}::{up_data['intf']}<>{down_data['host']}::{down_data['intf']})"
    rack_data = []
    rack_data.append("{code:PlainText}")
    rack_data.append(f"{up_data['host']}")
    rack_data.append(f"Rack: {a_info['rack']}")
    rack_data.append(f"RU: {a_info['ru']}")
    rack_data.append(f"SN: {a_info['sn']}")
    rack_data.append(f"Type: {a_info['dev_type']}")
    rack_data.append(f"Interface: {up_data['intf']}")
    rack_data.append(f"{down_data['host']}")
    rack_data.append(f"Rack: {z_info['rack']}")
    rack_data.append(f"RU: {z_info['ru']}")
    rack_data.append(f"SN: {z_info['sn']}")
    rack_data.append(f"Type: {z_info['dev_type']}")
    rack_data.append(f"Interface: {down_data['intf']}")
    rack_data.append("{code}")
    rack_info = "\n".join(rack_data)
    sn_data = []
    sn_data.append("{code:PlainText}")
    sn_data.append(f"A-Side\n{up_data['host']}")
    sn_data.append(f"SN: {a_info['sn']}")
    sn_data.append(f"Type: {a_info['dev_type']}")
    sn_data.append(f"Z-Side\n{down_data['host']}")
    sn_data.append(f"SN: {z_info['sn']}")
    sn_data.append(f"Type: {z_info['dev_type']}")
    sn_data.append("{code}")
    sn_info = "\n".join(sn_data)
    simpleSN = f"A-Side: {a_info['sn']} | Z-Side {z_info['sn']}"
    output_data = []
    output_data.append("||Required Information||Answer||")
    output_data.append("|IBX | " + site_code + " |")
    output_data.append("|Device Host Name/Port#/Etc |" + rack_info + "|")
    output_data.append("|Customer Impacted? | No")
    output_data.append("|Serial|" + sn_info + "|")
    output_data.append(
        "|Authorized to begin work?  | Yes you can begin work. Give quick note in network-ops channel when work begins"
    )
    output_data.append("|Task Needed| " + user_note + "|")
    output = "\n".join(output_data)
    return subject, output, simpleSN, rack_info


def create_onsite_instructions(note):
    """
    Take user input and build instructions list, return this value as a string
    """
    contents = []
    contents.append(note)
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents.append(line)
    instructions = "\n".join(contents)
    return instructions


def get_user_input(args):
    """
    Function that is used to create instructions for DCOPS Jira
    """
    if args.smarthands:
        user_note = input("Enter instructions for IBX Smarthands. Ctrl-D or Ctrl-Z ( windows ) to save note: \n")
    elif args.onsite:
        user_note = input("Enter instructions for DCOPS. Ctrl-D or Ctrl-Z ( windows ) to save note: \n")
    if len(user_note) == 0:
        instructions = user_note
    else:
        instructions = create_onsite_instructions(user_note)
    print("Instructions submitted")
    return instructions


def create_smarthands_data(jira, allInstructions, site_code, accountNum, aCab):
    sh_data = {
        "ibxLocation": {
            "ibx": site_code,
            "cages": [{"cage": aCab, "accountNumber": accountNum}],
        },
        "customerReferenceNumber": jira,
        "serviceDetails": {"scopeOfWork": allInstructions},
        "schedule": {"scheduleType": "STANDARD"},
        "contacts": [
            {
                "contactType": "ORDERING",
                "name": "Metal NOC",
                "email": "Metal-noc@equinix.com",
            },
            {
                "contactType": "NOTIFICATION",
                "name": "Metal NOC",
                "email": "Metal-noc@equinix.com",
            },
            {
                "contactType": "TECHNICAL",
                "name": "Metal NOC",
                "email": "Metal-noc@equinix.com",
                "workPhonePrefToCall": "ANYTIME",
                "workPhone": "5555555555",
            },
        ],
    }
    return sh_data


def prettyInstructions(instructions, rack_info):
    newRackInfo = rack_info.replace("{code:PlainText}", "").replace("{code}", "")
    newRackInfoList = newRackInfo.strip().split("\n")
    newRackInfoList.insert(0, "A-Side:")
    newRackInfoList.insert(7, "Z-Side:")
    newRackInfo = "\n".join(newRackInfoList)
    allInstructions = instructions + "\n" + newRackInfo
    return allInstructions


def qualified(args, up_dev, dwn_dev):
    up_plat = up_dev.host_get_platform()
    dwn_plat = dwn_dev.host_get_platform()
    hosts = {host.host: host.host_get_platform() for host in [up_dev, dwn_dev]}

    if "juniper-junos" in hosts.values():
        print("#" * 30)
        print(f"Script cannot be ran on a Juniper device\nPerform drain manually")
        for k, v in hosts.items():
            if "juniper-junos" == v:
                print(f"{k} is set to Juniper in Netbox")
        print("#" * 30)
        sys.exit()

    elif "arista-eos" in hosts.values():
        print("#" * 30)
        print(f"The following hosts are Arista {hosts.keys()}\nChecking for config file...")
        missing_conf = []
        found_conf = []
        for k, v in hosts.items():
            if "arista-eos" == v:
                print("#" * 30)
                fqdn = k + DOMAIN
                if not pyeapi.config_for(fqdn):
                    if args.c:
                        missing_conf.append(k)
                    else:
                        print(f"{k} is missing config file\nRun script with '-c' flag to create eapi.conf file")
                        print("#" * 30)
                        sys.exit()
                else:
                    found_conf.append(k)

        if args.c and len(missing_conf) > 0:
            check_eapi_conf_file()
            for host in hosts.keys():
                fqdn = host
                pass_wd = os.environ["ARISTA_PW"]
                FILE_NAME = str(Path.home()) + "/.eapi.conf"
                append_multiple_lines(FILE_NAME, fqdn, pass_wd)
                print("#" * 30)
                print(f"config file for {host} has been created.")
                print("#" * 30)
            sys.exit()

        if found_conf:
            print("#" * 30)
            print("Found config file for the following Arista switches:")
            print("#" * 30)
            for entry in found_conf:
                print(f"{entry}")
            print("#" * 30)

    upRole = up_dev.host_get_role()
    downRole = dwn_dev.host_get_role()
    ssp_dsr_pair = {}
    ssp_dsr_pair["upstream"] = "super-spine"
    ssp_dsr_pair["downstream"] = "spine-switch"

    dsr_esr_pair = {}
    dsr_esr_pair["upstream"] = "spine-switch"
    dsr_esr_pair["downstream"] = "tor-switch"

    noPass = []
    for pairs in [ssp_dsr_pair, dsr_esr_pair]:
        if pairs["upstream"] == up_dev.host_get_role() and pairs["downstream"] == dwn_dev.host_get_role():
            print("#" * 30)
            print(f"{up_dev.host} matches role {pairs['upstream']}")
            print(f"{dwn_dev.host} matches role {pairs['downstream']}")
            print("#" * 30)
        else:
            noPass.append(pairs)

    if len(noPass) > 1:
        print("#" * 30)
        print(
            f"Verify that host '-u' is a Spine Switch or a Super Spine Switch\nVerify that host '-d' is a Spine Switch or a Tor Switch"
        )
        print("#" * 30)
        sys.exit()

    return up_plat, dwn_plat


if __name__ == "__main__":
    # Need line below to remove all GNMI terminal output
    logging.basicConfig(level=logging.CRITICAL)
    # Initialize CLI arguments
    check_env()
    nb = pynetbox.api(url=NB_URL, token=os.environ["NB_API_KEY"])
    args = init_arguments()
    upstrm_hostname = args.u
    dwnstrm_hostname = args.d
    jira_post = check_jira_configuration(args)
    check_ECP_configuration(args)
    jira = args.j
    upstrm_intf = intended_interface(upstrm_hostname, dwnstrm_hostname)
    netbox_upstrm = Netbox(args.u, upstrm_intf)
    netbox_dwnstrm_dict = netbox_upstrm.nb_get_device_neighbor_endpoint()
    dwnstrm_hostname = next(iter(netbox_dwnstrm_dict))
    dwnstrm_intf = netbox_dwnstrm_dict[dwnstrm_hostname]
    netbox_dwnstrm = Netbox(dwnstrm_hostname, dwnstrm_intf)
    up_plat, dwn_plat = qualified(args, netbox_upstrm, netbox_dwnstrm)
    upstream_info = netbox_upstrm.host_get_info()
    downstream_info = netbox_dwnstrm.host_get_info()
    neighbor_v4 = netbox_upstrm.nb_get_device_neighbor_ipv4()
    neighbor_v6 = netbox_upstrm.nb_get_device_neighbor_ipv6()
    if args.drain:
        if "arista-eos" in up_plat:
            uplink_diff = eapi_upstream_drain_playbook(upstrm_hostname, netbox_upstrm, jira)
            eapi_check_pending_conf(upstrm_hostname)
            eapi_clear_counters(upstrm_hostname, upstrm_intf)
            uplink_data = eapi_get_intf_stats(upstrm_hostname, upstrm_intf)

        elif "sr-linux" in up_plat:
            uplink_diff, uplink_data = gnmi_upstream_drain_playbook(upstrm_hostname, netbox_upstrm, jira)
            print(uplink_diff)

        if "arista-eos" in dwn_plat:
            downlink_diff = eapi_downstream_drain_playbook(dwnstrm_hostname, netbox_dwnstrm, jira)
            eapi_check_pending_conf(dwnstrm_hostname)
            eapi_clear_counters(dwnstrm_hostname, dwnstrm_intf)
            downlink_data = eapi_get_intf_stats(dwnstrm_hostname, dwnstrm_intf)

        elif "sr-linux" in dwn_plat:
            downlink_diff, downlink_data = gnmi_downstream_drain_playbook(dwnstrm_hostname, netbox_dwnstrm, jira)
            print(downlink_diff)

        print(f"\nUPSTREAM switch - {upstrm_hostname} BGP neighbor information:")
        if "arista-eos" in up_plat:
            bgp_prefixes = eapi_get_bgp_pref_accptd(upstrm_hostname, neighbor_v4, neighbor_v6)
            bgp_info = eapi_get_bgp_peergroup(upstrm_hostname, neighbor_v4, neighbor_v6)
            display_bgp_results(bgp_info, neighbor_v4, neighbor_v6, bgp_prefixes)
            handle_intf_stats(upstrm_hostname, upstrm_intf)

        elif "sr-linux" in up_plat:
            bgp_prefixes, bgp_info = gnmi_get_bgp_info(upstrm_hostname, neighbor_v4, neighbor_v6)
            display_bgp_results(bgp_info, neighbor_v4, neighbor_v6, bgp_prefixes)
            gnmi_handle_intf_stats(upstrm_hostname, upstrm_intf)

        if jira_post:
            jira_note = create_jira_note(
                bgp_info,
                netbox_upstrm,
                netbox_dwnstrm,
                bgp_prefixes,
                uplink_data,
                downlink_data,
                uplink_diff,
                downlink_diff,
            )
            dcops_note = create_dcops_note(
                bgp_info,
                neighbor_v4,
                neighbor_v6,
                bgp_prefixes,
                uplink_data,
                downlink_data,
                uplink_diff,
                downlink_diff,
                upstream_info,
                downstream_info,
            )
            jc = Jira()
            jc.update(jira_note, jira)
            print(f"Notes posted to {jira}")
            if args.onsite:
                site_code = netbox_upstrm.host_get_site()
                instructions = get_user_input(args)
                summary, description, simpleSN, rack_info = create_onsite_desc(
                    instructions,
                    uplink_data,
                    downlink_data,
                    upstream_info,
                    downstream_info,
                    site_code,
                )
                issue_dict = {
                    "project": {"key": "ONSITE"},
                    "summary": summary,
                    "description": description,
                    "components": [{"name": "Network Request"}],
                    "issuetype": {"name": "Task"},
                    "priority": {"name": "Medium"},
                    "customfield_10644": [{"value": site_code}],  # IBX Field
                    "customfield_10639": simpleSN,  # Serial Number Field
                    "customfield_10713": [{"value": "No"}],  # Customer Impact Field
                    "customfield_10918": {"value": "Yes"},  # Authorized to Work
                    "customfield_10938": f"A: {upstrm_hostname} | Z: {dwnstrm_hostname}",  # Host Name Field
                }
                onsite = jc.create(issue_dict)
                jc.update(dcops_note, onsite.key)
                jc.link(jira, onsite.key)
                message = f"Created {onsite.key}"
                jc.update(message, jira)
                print(message)
                print("Script Completed")
            elif args.smarthands:
                instructions = get_user_input(args)
                site_code = netbox_upstrm.host_get_site()
                summary, description, simpleSN, rack_info = create_onsite_desc(
                    instructions,
                    uplink_data,
                    downlink_data,
                    upstream_info,
                    downstream_info,
                    site_code,
                )
                ecx = init_ecx()
                aCab = upstream_info["cabinet"]
                allInstructions = prettyInstructions(instructions, rack_info)
                accountNum = ecx.acctNumber(site_code, aCab)
                smarthandsData = create_smarthands_data(jira, allInstructions, site_code, accountNum, aCab)
                # import pdb;pdb.set_trace()
                smarthandsTicket = ecx.createSmrtHand(smarthandsData)
                message = f"Created {smarthandsTicket} for IBX Smarthands support"
                print(message)
                jc.update(message, jira)
                print("Script Completed")

    if args.normalize:
        if "arista-eos" in up_plat:
            uplink_diff = eapi_upstream_normalize_playbook(upstrm_hostname, netbox_upstrm, jira)
            eapi_check_pending_conf(upstrm_hostname)
            eapi_clear_counters(upstrm_hostname, upstrm_intf)
            uplink_data = eapi_get_intf_stats(upstrm_hostname, upstrm_intf)

        elif "sr-linux" in up_plat:
            uplink_diff, uplink_data = gnmi_upstream_norm_playbook(upstrm_hostname, netbox_upstrm, jira)
            print(uplink_diff)

        if "arista-eos" in dwn_plat:
            downlink_diff = eapi_downstream_normalize_playbook(dwnstrm_hostname, netbox_dwnstrm, jira)
            eapi_check_pending_conf(dwnstrm_hostname)
            eapi_clear_counters(dwnstrm_hostname, dwnstrm_intf)
            downlink_data = eapi_get_intf_stats(dwnstrm_hostname, dwnstrm_intf)

        elif "sr-linux" in dwn_plat:
            downlink_diff, downlink_data = gnmi_downstream_norm_playbook(dwnstrm_hostname, netbox_dwnstrm, jira)
            print(downlink_diff)

        print(f"\nUPSTREAM switch - {upstrm_hostname}:")
        if "arista-eos" in up_plat:
            bgp_prefixes = eapi_get_bgp_pref_accptd(upstrm_hostname, neighbor_v4, neighbor_v6)
            bgp_info = eapi_get_bgp_peergroup(upstrm_hostname, neighbor_v4, neighbor_v6)
            display_bgp_results(bgp_info, neighbor_v4, neighbor_v6, bgp_prefixes)
            handle_intf_stats(upstrm_hostname, upstrm_intf)

        elif "sr-linux" in up_plat:
            bgp_prefixes, bgp_info = gnmi_get_bgp_info(upstrm_hostname, neighbor_v4, neighbor_v6)
            display_bgp_results(bgp_info, neighbor_v4, neighbor_v6, bgp_prefixes)
            gnmi_handle_intf_stats(upstrm_hostname, upstrm_intf)

        if jira_post:
            jira_note = create_jira_note(
                bgp_info,
                netbox_upstrm,
                netbox_dwnstrm,
                bgp_prefixes,
                uplink_data,
                downlink_data,
                uplink_diff,
                downlink_diff,
            )
            jc = Jira()
            jc.update(jira_note, jira)
            print(f"Notes posted to {jira}")
