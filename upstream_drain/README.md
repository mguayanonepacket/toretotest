# Upstream Switch Drain tool

The aim of this tool is to drain and/or normalize a link that is unstable/flapping, errors, or hard down.
It uses pyeapi to interact with Arista switches, pygnmi to interfact with the Nokia switches, and pynetbox to get necessary information from Netbox.

**NOTE:** This tool is stable and uses the new syntax convention starting from 

This script can log a note in the Jira case and also if needed it will create an ONSITE jira for DCOPS.

## Getting started

1. Go to the directory.

```
cd ~/Packet-Gits/NetworkOperations/Operations/Issues/upstream_drain
```
2. Activate the Gold virtual environment.

```
$ source path/to/venv/bin/activate
```
3. Export the environment variables needed.

```
# This should be your Netbox API key. 
$ export NB_API_KEY='XXXXXXXXXXXXXXXXXXXXXXX'

# Can be found in 1Pass.
$ export ARISTA_PW='XXXXXXXXXXXXXXXXXXXXXXX'
$ export NOKIA_PW='XXXXXXXXXXXXXXXXXXXXXXX'

# This is your Jira login email address
$ export JIRA_USER='xxxxx@equinix.com'

# This is your Jira API token, same token as the site postcheck script
$ export JIRA_TOKEN='XXXXXXXXXXXXX'
```

## Usage

After setting up the environment, you can now run the script.

Instructions are in the wiki:
https://equinixjira.atlassian.net/wiki/spaces/OP/pages/145959004106/NETOPS-SOP+Drain+Interfaces+with+Errors+DRAFT


If either the upstream switch or the downstream switch is an Arista, or if both are Arista switches, you should initially execute the script with the -c option. Subsequently, rerun the script to carry out the drain or normalize operations.

```
$ python3 upstream_drain.py -u dsr2.rk02.p01.se4 -d esr1b.rk07.p01.se4 -c
##############################
config file has been created.
##############################
```
```
usage: upstream_drain.py [-h] [-c] [-u U] [-d D] [-j J] [--drain] [--normalize] [--jira] [--onsite]

Create an eapi.conf file for Arista switches, which drains/normalizes a link-in-question.

optional arguments:
  -h, --help   show this help message and exit
  -c           Create the eapi.conf file in your home directory.
  -u U         Hostname of the upstream switch (SSPs and/or DSRs)
  -d D         Hostname of the downstream switch (DSRs and/or ESRs)
  -j J         Jira NETOPS ticket number (NETOPS-XXXX).
  --drain      Drain traffic for a link-in-question
  --normalize  Normalize traffic for a link-in-question
  --jira       Post note to Jira ticket
  --onsite     Create an Onsite Jira for DCOPS
```
#### Drain traffic
```
Drain the link Only:
$ python3 upstream_drain.py -u dsr1.rk01.p01.se4 -d esr1a.rk03.p01.se4 -j NETOPS-1111 --drain

Drain the link and log a note on the NETOPS Jira:
$ python3 upstream_drain.py -u dsr1.rk01.p01.se4 -d esr1a.rk03.p01.se4 -j NETOPS-1111 --drain --jira

Drain the link, log a note on the NETOPS Jira, and create an ONSITE Jira for DCOPS:
$ python3 upstream_drain.py -u dsr1.rk01.p01.se4 -d esr1a.rk03.p01.se4 -j NETOPS-1111 --drain --jira --onsite

```

#### Normalize traffic
```
Normalize link Only:
$ python3 upstream_drain.py -u dsr1.rk01.p01.se4 -d esr1a.rk03.p01.se4 -j NETOPS-1111 --normalize

Normalize link and add notes to Jira:
$ python3 upstream_drain.py -u dsr1.rk01.p01.se4 -d esr1a.rk03.p01.se4 -j NETOPS-1111 --normalize --jira

```

## Output

#### Sample output when draining the link.

**NOTE:** User input should be the same format as shown below

**eAPI only accepts complete interface name.**

```
$ python3 upstream_drain.py -u dsr2.rk02.p01.se4 -d esr1b.rk07.p01.se4 -j NETOPS-1111 --drain

dsr2.rk02.p01.se4 matches role spine-switch


esr1b.rk07.p01.se4 matches role tor-switch


Connecting to dsr2.rk02.p01.se4...

This is what you're about to commit:

######################################################################
--- system:/running-config
+++ session:/5452ffbc-165d-48de-aaca-3c61a8c5c933-session-config
@@ -484,7 +484,7 @@
    no switchport
 !
 interface Ethernet3/14/1
-   description BB: esr1b.rk07.p01.se4:Ethernet50/1 [local wire]
+   description NETOPS-1111: esr1b.rk07.p01.se4:Ethernet50/1 [local wire]
    mtu 9214
    speed forced 100gfull
    no switchport
@@ -1527,6 +1527,8 @@
    neighbor 10.253.128.127 description esr1a.rk07.p01.se4
    neighbor 10.253.128.135 peer group ESR
    neighbor 10.253.128.135 description esr1b.rk07.p01.se4
+   neighbor 10.253.128.135 route-map DENY in
+   neighbor 10.253.128.135 route-map DENY out
    neighbor fc00:db:0:1::1c peer group V6-BSR
    neighbor fc00:db:0:1::1c description bbr1.se4
    neighbor fc00:db:0:1::1e peer group V6-BSR
@@ -1551,6 +1553,8 @@
    neighbor fc00:db:0:1::7f description esr1a.rk07.p01.se4
    neighbor fc00:db:0:1::87 peer group V6-ESR
    neighbor fc00:db:0:1::87 description esr1b.rk07.p01.se4
+   neighbor fc00:db:0:1::87 route-map DENY in
+   neighbor fc00:db:0:1::87 route-map DENY out
    redistribute connected route-map REDIST-CONNECTED
    redistribute static route-map REDIST-STATIC
    !

######################################################################
Type 'yes' to commit, 'no' to abort and 'cancel' to exit: yes
Committed.

DOWNSTREAM SWITCH: esr1b.rk07.p01.se4
This is what you're about to commit:

######################################################################
--- system:/running-config
+++ session:/77b99c9b-34ef-45e6-a4ca-ce26fab4800b-session-config
@@ -389,7 +389,7 @@
    sflow enable
 !
 interface Ethernet50/1
-   description BB: dsr2.rk02.p01.se4:Ethernet3/14/1 [local wire]
+   description NETOPS-1111: dsr2.rk02.p01.se4:Ethernet3/14/1 [local wire]
    mtu 9214
    speed forced 100gfull
    no switchport


######################################################################
Type 'yes' to commit, 'no' to abort and 'cancel' to exit: yes
Committed.

Checking dsr2.rk02.p01.se4 for any pending config sessions:
RESULT: No pending config sessions found on dsr2.rk02.p01.se4.

Checking esr1b.rk07.p01.se4 for any pending config sessions:
RESULT: No pending config sessions found on esr1b.rk07.p01.se4.

UPSTREAM switch - dsr2.rk02.p01.se4 BGP neighbor information:

IPv4 Peer IP         : 10.253.128.135
IPv4 BGP Status      : Established
IPv4 Peer group      : ESR

IPv6 Peer IP         : fc00:db:0:1::87
IPv6 BGP Status      : Established
IPv6 Peer group      : V6-ESR

Prefix count:
IPv4 Prefix Accepted : 0
IPv6 Prefix Accepted : 0

Interface Ethernet3/14/1 stats:

Input rate      : 887.8070692337301 bits/s
Output rate     : 1252.0951279266908 bits/s
Update interval : 30.0 secs

Do you want to continue? Type 'y' to refresh intf stats and 'n' to abort: y

Interface Ethernet3/14/1 stats:

Input rate      : 820.2265441344313 bits/s
Output rate     : 915.4637718708587 bits/s
Update interval : 30.0 secs

Do you want to continue? Type 'y' to refresh intf stats and 'n' to abort: n

Compiling data, wait 30 seconds
Notes posted to NETOPS-1111
Write a note to DCOPS: {example: dsr2.rk02.p01.se4 et5/14/1 has low receive light. Please clean all fibers along the path.}

```



#### Sample Output when normalizing the link.

```
$ python3 upstream_drain.py -u dsr2.rk02.p01.se4 -d esr1b.rk07.p01.se4 -j NETOPS-1111 --normalize

dsr2.rk02.p01.se4 matches role spine-switch


esr1b.rk07.p01.se4 matches role tor-switch


Connecting to dsr2.rk02.p01.se4...

######################################################################
--- system:/running-config
+++ session:/a5f2cd6d-5581-412d-9517-2aaa2adadadd-session-config
@@ -484,7 +484,7 @@
    no switchport
 !
 interface Ethernet3/14/1
-   description NETOPS-1111: esr1b.rk07.p01.se4:Ethernet50/1 [local wire]
+   description BB: esr1b.rk07.p01.se4:Ethernet50/1 [local wire]
    mtu 9214
    speed forced 100gfull
    no switchport
@@ -1527,8 +1527,6 @@
    neighbor 10.253.128.127 description esr1a.rk07.p01.se4
    neighbor 10.253.128.135 peer group ESR
    neighbor 10.253.128.135 description esr1b.rk07.p01.se4
-   neighbor 10.253.128.135 route-map DENY in
-   neighbor 10.253.128.135 route-map DENY out
    neighbor fc00:db:0:1::1c peer group V6-BSR
    neighbor fc00:db:0:1::1c description bbr1.se4
    neighbor fc00:db:0:1::1e peer group V6-BSR
@@ -1553,8 +1551,6 @@
    neighbor fc00:db:0:1::7f description esr1a.rk07.p01.se4
    neighbor fc00:db:0:1::87 peer group V6-ESR
    neighbor fc00:db:0:1::87 description esr1b.rk07.p01.se4
-   neighbor fc00:db:0:1::87 route-map DENY in
-   neighbor fc00:db:0:1::87 route-map DENY out
    redistribute connected route-map REDIST-CONNECTED
    redistribute static route-map REDIST-STATIC
    !

######################################################################
Type 'yes' to commit, 'no' to abort and 'cancel' to exit: yes
Committed.

DOWNSTREAM SWITCH: esr1b.rk07.p01.se4
This is what you're about to commit:

######################################################################
--- system:/running-config
+++ session:/9b16162f-e6bb-4b01-abe1-a5ee2928f189-session-config
@@ -389,7 +389,7 @@
    sflow enable
 !
 interface Ethernet50/1
-   description NETOPS-1111: dsr2.rk02.p01.se4:Ethernet3/14/1 [local wire]
+   description BB: dsr2.rk02.p01.se4:Ethernet3/14/1 [local wire]
    mtu 9214
    speed forced 100gfull
    no switchport


######################################################################
Type 'yes' to commit, 'no' to abort and 'cancel' to exit: yes
Committed.

Checking dsr2.rk02.p01.se4 for any pending config sessions:
PENDING-CONF TEST PASSED: No pending config sessions found on dsr2.rk02.p01.se4.

Checking esr1b.rk07.p01.se4 for any pending config sessions:
PENDING-CONF TEST PASSED: No pending config sessions found on esr1b.rk07.p01.se4.

UPSTREAM switch - dsr2.rk02.p01.se4 BGP neighbor information:

IPv4 Peer IP         : 10.253.128.135
IPv4 BGP Status      : Established
IPv4 Peer group      : ESR

IPv6 Peer IP         : fc00:db:0:1::87
IPv6 BGP Status      : Established
IPv6 Peer group      : V6-ESR

Prefix count:
IPv4 Prefix Accepted : 6
IPv6 Prefix Accepted : 1

Interface Ethernet3/14/1 stats:

Input rate      : 916.6999906424534 bits/s
Output rate     : 1632.3158943403937 bits/s
Update interval : 30.0 secs

Do you want to continue? Type 'y' to refresh intf stats and 'n' to abort: y

Interface Ethernet3/14/1 stats:

Input rate      : 889.0665951844077 bits/s
Output rate     : 1515.3536141919224 bits/s
Update interval : 30.0 secs

Do you want to continue? Type 'y' to refresh intf stats and 'n' to abort: n
```
## User Response

### Config change response.

'yes' = committing the configuration in its current config session.

'no' = aborting the configuration in its current config session.

'cancel' = aborting the configuration in its current config session and terminating the entire script.

### Interface statistics response.

'y' = to refresh interface statistics.

'n' = to abort the script.

### Script Validations:

* It will validate the devices if they are active in status and has a role for **Super Spine Switch**, **Spine Switch**, and **TOR Switch** for SSPs, DSRs, and ESRs respectively.
* It will gather all interface lower level detail and add to Jira as a note
