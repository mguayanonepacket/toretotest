deviceStatus
=====================================
This tool was created to track status of grouping of Arista and Nokia switches during the upgrade.  The inventory file should contain hostnames that map to loopback0 addresses.  The tool will fetch and print status of: reachability to loopback0, reachability to mgmt (N/A msw), uplink bgp peers, control node bgp peers, maintenance mode, and mlag. Status changes for devices is logged to file in same directory. Inventory test case and log files included here.



Runtime Details
-----------------------------
```
- An inventory file containing a list of devices must be passed as a cli argument.
- Export variables for GNMI user and password must be provided.
- Status is printed to the screen and then the loop sleeps for 20sec.  Collecting status time varies by number of hosts polled, latency, etc. 
```

Requirements
------------
Netopslib Library must be installed in your virtual environment to use this script. To install the library in your existing virtual environment run the following command: 

```python
pip install git+https://github.com/packethost/NetopsLib.git
# or
pip install git+https://github.com/packethost/NetopsLib.git --upgrade
```

Export variables
----------------
```
export NB_URL=https://netbox.packet.net/  -->Netbox URL
export NB_API_KEY="XXXXXX"  -->Your netbox token
export MONITORING_PW='XXXXXXX' -->Password for the monitoring user. You can find it in 1PASS
```

Command line argument options
-----------------------------
```
usage: deviceStatus.py [-h] -i INVENTORY

optional arguments:
  -h, --help            show this help message and exit
  -i INVENTORY, --inventory INVENTORY
                        Name of the inventory file

```

Example
-------
```
export NB_URL=https://netbox.packet.net/
export NB_API_KEY="XXXXXX"
export MONITORING_PW='XXXXXXX'
cd Packet-Gits/NetworkOperations/Operations/Maintenances/deviceStatus/
~/Packet-Gits/NetworkOperations/Operations/Maintenances/deviceStatus$ python3 deviceStatus.py -i inventory.arista.testCase.txt
```

Screen will clear on loop.  Sample status below
```
Ctrl + C to end script
Wed 28 Aug 2024 01:24:04 PM UTC
Switch                  lo0/mgmt        PeerState       CN-CR           Maintenance     Mlag            SvrPortState    Firmware
-------------------     --------        ---------       -----           -----------     ----            ------------    --------
dsr1.rk01.p01.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
dsr1.rk01.p02.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
dsr2.rk02.p01.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
dsr2.rk02.p02.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
dsr3.rk01.p01.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
dsr3.rk01.p02.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
dsr4.rk02.p01.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
dsr4.rk02.p02.da6       Up / Up         8/8             -               NoMaint                         -               EOS: 4.30.5M    
esr1a.rk03.p01.da6      Up / Up         12/12           10/10           NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk04.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk05.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk06.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk07.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk08.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk09.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk10.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M      
esr1a.rk11.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M      
esr1a.rk12.p01.da6      Up / Up         12/12           -               NoMaint         Active          -               EOS: 4.30.5M    
esr1a.rk13.p01.da6      Up / Up         15/15           -               NoMaint         -               16/20           SRL: v23.10.4-89-g68bbba5a50
esr1a.rk14.p01.da6      Up / Up         15/15           -               NoMaint         -               14/21           SRL: v23.10.4-89-g68bbba5a50  
esr1a.rk16.p01.da6      Up / Up         15/15           -               NoMaint         -               10/13           SRL: v23.10.4-89-g68bbba5a50  
esr1a.rk17.p01.da6      Up / Up         15/15           -               NoMaint         -               5/12            SRL: v23.10.4-89-g68bbba5a50
esr1a.rk18.p01.da6      Up / Up         15/15           -               NoMaint         -               9/16            SRL: v23.10.4-89-g68bbba5a50 
esr1a.rk19.p01.da6      Up / Up         15/15           -               NoMaint         -               8/14            SRL: v23.10.4-89-g68bbba5a50
esr1a.rk20.p01.da6      Up / Up         15/15           -               NoMaint         -               7/9             SRL: v23.10.4-89-g68bbba5a50
esr1a.rk21.p01.da6      Up / Up         15/15           -               NoMaint         -               7/14            SRL: v23.10.4-89-g68bbba5a50
esr1a.rk26.p01.da6      Up / Up         15/15           -               NoMaint         -               23/23           SRL: v23.10.4-89-g68bbba5a50
esr1a.rk27.p01.da6      Up / Up         15/15           -               NoMaint         -               23/23           SRL: v23.10.4-89-g68bbba5a50
```
