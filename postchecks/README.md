This script runs the post-checks for new IBX build-outs and ready racks. It runs the 15 tests described below for Juniper, Nokia, Arista, OpenGear and ServerTech devices.

Environment variable requirements
---------------------------------

```
export NB_URL=https://netbox.packet.net/
export NB_API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
export RSA_KEY_NAME="<NAME OF THE KEY>"   # Optional, this RSA key has to be stored in the directory .ssh in your home directory. Defaults to ~/.ssh/id_rsa
export ARISTA_PW="XXXXXXXXXXXX"	   #Arista ADMIN password. It can be found in 1PASS						
export JIRA_USER='USERNAME'   #Username used to log into Jira
export JIRA_TOKEN='XXXXXXXXXXXXX'	 #Jira toke to be able to use the API - It can be created on 'Account settings' > 'Security'
export MONITORING_PW="XXXXXXXXXXXX"	   #monitoring user password for the metro. It can be found in 1PASS
export OPEN_PASS="XXXX"         #Opengear password from 1Pass
export PDU_PASS="XXXX"         #Servertech password from 1Pass, make sure you use right password for the site.

```

Module install requirements
---------------------------

```
python3 -m venv <GS Venv name>
source <GS Venv name>/bin/activate
pip3 install -r requirements.txt  (file that can be found in the NetworkOperations repository)
```

RSA format key for Juniper Devices - Requirement
------------------------------------------------

```
PyEZ only supports ssh keys in RSA format. To access the Juniper devices we use a OPENSSH format key, so we need to create a new private ssh key in RSA format using our current OPENSSH key and pass the name as an export variable as mentioned above. 
Follow the next steps to create a new ssh key in RSA format from your current OPENSSH key:

1. Create a copy of you current private OPENSSH key:
cp ./ssh/id_rsa ./ssh/new_rsa.key

2. Convert your current new openssh key into RSA format with the following command:
ssh-keygen -p -m PEM -f new_rsa.key

Example:

jcarbonell@network-utils01-dc13:~/.ssh$ ssh-keygen -p -m PEM -f new_rsa.key
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.

jcarbonell@network-utils01-dc13:~/.ssh$ cat new_rsa.key
-----BEGIN RSA PRIVATE KEY-----

(Omitted by brevity)

3. Create export variable with the name of the new key when running the script:
export RSA_KEY_NAME="new_rsa.key"

```

Command line argument options
-----------------------------

```
usage: postchecks.py [-h] [-c] [-r RACKS] -s SITE [-p POD] -u USER

Explanation of options
----------------------
-c option to generate the Arista Config file. It is required for the first run to avoid EAPI connection errors.
-u username used for Juniper devices. This argument is optional. By default it uses the linux username from the NetUtils ssh session.
-s site name. This argument is mandatory.
-p pod number. If not defined, both pods will be done. This argument is optional.
-r single rack or rack range. If defined, only the devices of those racks will be checked along with neighboring devices. This argument is optional.
-d single device. This argument is optional
```

Usage examples
--------------

```
Step 1: python3 postchecks.py -u jcarbonell -s tr2 -c    #You always need to run the script with the option -c first to create the EAPI config file
Step 2: python3 postchecks.py -u jcarbonell -s tr2       #After Step 1 is complete, You can run the script to run the post-checks

or to run the script against a pod (ex. DC13 POD02)

Step 1: python3 postchecks.py -u jcarbonell -s dc13 -p 2 -c
Step 2: python3 postchecks.py -u jcarbonell -s dc13 -p 2

or to run the script for a couple of ready racks

Step 1: python3 postchecks.py -u jcarbonell -s dc13 -p 2 -r rk05-06 -c
Step 2: python3 postchecks.py -u jcarbonell -s dc13 -p 2 -r rk05-06

or to run the script for a single rack

Step 1: python3 postchecks.py -u jcarbonell -s sl1 -r core1 -c
Step 2: python3 postchecks.py -u jcarbonell -s sl1 -r core1

If you have Juniper and Nokia devices only, you can skip the step 1.
```

Tests run by the script for Opengear devices
--------------------------------------------

* Test 1: Check RANCID tag in Netbox:
* Test 2: Check Device Model against Netbox:
* Test 3: Check Primary IPv4 against Netbox:
* Test 4: Check device Serial against Netbox:
* Test 5: Check Host Name against Netbox:
* Test 6: Check device Firmware against Netbox:
* Test 7: Check Console port labels against Netbox:
* Test 8: Check devices connected to Console ports against Netbox:

Tests run by the script for ServerTech devices
----------------------------------------------

* Test 1: Check RANCID tag in Netbox:
* Test 2: Check the Firmware against Netbox:
* Test 3: Check device Serial against Netbox:
* Test 4: Check device Model against Netbox:
* Test 5: Check MAC against Netbox:
* Test 6: Check primary IPv4 against Netbox:
* Test 7: Check Status of Power Outlets:

Tests run by the script for Rest of devices
-------------------------------------------

* Test 1: checks if the firmware versions are the same as the Gold Standard versions
* Test 2: checks device serial match the Netbox serial for the device
* Test 3: checks the Netbox interfaces and neighbors of the device matches the information of lldp of the device
* Test 4: checks all the device configured interfaces shown in Netbox are in UP state
* Test 5: checks link light levels are between 4 dbm and -4 dbm
* Test 6: checks logs for flapping interfaces
* Test 7: checks device environment (for PSUs down and temperature issues)
* Test 8: checks bgp (IPv4, IPv6 and evpn) neighbor status
* Test 9: pings flood on all the device interfaces shown in Netbox for IPv4 and check interface errors. It also clears the counters
* Test 10: checks that Arista devices have all the aliases configured
* Test 11: checks that the loopback2 ip addresses of esrA and esrB in the same rack match both in Netbox and configured on the devices
* Test 12: checks sflow on transit/pni/ix conections and jumbo MTU value
* Test 13: check NH for the default route on vrf PACKET INTERNAL to be the ip of the BBR
* Test 14: check rancid tag for the devices
* Test 15: check that packetbot user is configured on Nokia devices.If Arista or Juniper devices, it will be skipped.
* Test 16: check on /etc/hosts in both network-utils (dc13 and sv15) for an entry for each of the devices

Script results
--------------

* If all the tests are successful, you will get the following message at the end of the script execution (no report will be generated):

```
Post-checks completed successfully for {device hostname}

Output Example:

Post-checks completed successfully for bbr1.pa4

```

* If any of the tests fail, you will get the following message at the end of the script execution (a report in the REPORTS folder with the errors found will be generated):

```
Post-checks failed for {device hostname} - Check the report in REPORT folder for details

Output Example:

Post-checks failed for esr1b.rk15.p01.pa4 - Check the report in REPORT folder for details

```

* Successful tests won't generate any screen output or report
* If you want to see a summary of the issues found on the device and a brief description, you have two options:

1. Check the MS Sxcel spreadsheet called 'Post-checks.xlsx' created in the folder from where you are running the script.
2. Check thet text files generated in the REPORTS folder by running the following command:

```
cat REPORTS/* | grep ISSUE

Output Example:

ISSUE FOUND: Test 1 failed for csr2.pa4 - The device csr2.pa4 is not in Gold Standard firmware version: 
ISSUE DETAIL: The device csr2.pa4 is not in Gold Standard firmware version. Its current firmware version is: 4.24.5M - The Gold Standard Version is 4.26.4M

```

* If you don't see the word '[END]' at the end of the execution of the script, there must have been an exception and the script may have not completed all the tests on all the devices. Re-run it again or reach out to the developer to debug the issue further.

```
Output Example of a correct script execution end:

Post-checks completed successfully for msr2.rk02.p01.pa4
Post-checks completed successfully for msr3.rk03.p01.pa4
Post-checks failed for fw1.pa4 - Check the report in REPORT folder for details
Post-checks failed for mrr1.pa4 - Check the report in REPORT folder for details
Post-checks failed for mrr2.pa4 - Check the report in REPORT folder for details

[END]

...

```
