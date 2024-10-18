aristaStatus
=====================================
This tool was created to track status of grouping of Arista switches during ansible upgrade.  The inventory file should contain hostnames that map to loopback0 addresses.  The tool will fetch and print status of: reachability to loopback0, reachability to mgmt (N/A msw), uplink bgp peers, maintenance mode, and mlag. Status changes for devices is logged to file in same directory. Inventory test case and log files included here.

See detailed wiki for more details and examples
https://equinixjira.atlassian.net/wiki/spaces/OP/pages/145714056424/NETOPS-GUIDE+Arista+Upgrade+Status


Runtime Details
-----------------------------
```
- An inventory file containing a list of devices must be passed as a cli argument.
- On the first run you must use -e option to build .eapi.conf
- Status is printed to the screen and then the loop sleeps for 15sec.  Collecting status time varies by number of hosts polled, latency, etc. 
```

Command line argument options
-----------------------------
```
usage: aristaStatus.py [-h] -i INVENTORY [-e]

optional arguments:
  -h, --help            show this help message and exit
  -i INVENTORY, --inventory INVENTORY
                        Name of the inventory file
  -e, --makeEapi        Build .eapi.conf file

```

Example usage
-------------
```
(ansible-env) slindsey@network-utils01-sv15:~$ python3 aristaStatus.py -i inventory.arista.testCase.txt -e

 - Arista Admin password:
Created .eapi.conf
Now restart Script without eapi option
(ansible-env) slindsey@network-utils01-sv15:~$ python3 aristaStatus.py -i inventory.arista.testCase.txt

Screen will clear on loop.  Sample status below

Tue 20 Jun 2023 07:29:02 PM UTC
Switch                  lo0/mgmt        PeerState       Maintenance     Mlag
-------------------     -------         ---------       -----------     ----
csr1.sy4                Up / Up         2/2             NoMaint
ssp1.sy4                Up / Up         2/2             Disabled
dsr1.rk01.p01.sy4       Up / Up         4/4             NoMaint
dsr1.rk01.p01.sy5       Up / Up         4/4             Disabled
esr1a.rk13.p01.sy4      Up / Up         4/4             NoMaint         Active
esr1b.rk13.p01.sy4      Up / Up         4/4             NoMaint         Active
esr1a.rk13.p01.sy5      Up / Up         8/8             Disabled        Active
esr1b.rk13.p01.sy5      Up / Up         8/8             Disabled        Active
msw1.rk13.p01.sy4       Up              2/2
msw1.rk13.p01.sy5       Up              2/2

```
