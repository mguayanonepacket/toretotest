This tool gets the pre/post checks for Nokia, Arista and Juniper devices and generates diff files (either in txt or html format, but by default only the HTML diff file is created) to facilitate the pre and post checks.
Usage:

STEP 0: Complete the following files before running the script:

a) Add the device you want to get the pre/post-checks to the File 'inventory.txt'. If you want to use a different file use the option -i {PATH TOP THE INVENTORY FILE}

Add the hostname or IP addresses of the devices you want to get the pre/post-checks in the following format
{hostname}


Example:

jcarbonell@jcarbonell-Latitude-7400:~/PACKET$ cat inventory.txt 
esr1.c03.ewr1
bsr1.ewr1
dsr1.fra2 
esr1b.rk49.dfw2
esr1a.rk49.dfw2



b) Commands for the pre/post checks

You only need to complete the command files of the device type you need the pre/post-checks

b.1) Complete the following file for Juniper devices: 'checks-commands-juniper.txt' (Only if you need pre/post checks for Juniper devices)

Add the commands you want to perform. Don't use command abbreviations otherwise, they will fail. Regex expressions are supported.
Getting the full internet routing tables (with 'show route all' command for example) will fail because of a timeout (netmiko limitation).

Example:

jcarbonell@jcarbonell-Latitude-7400:~/PACKET$ cat checks-commands-juniper.txt
show chassis environment | no-more
show interfaces descriptions| match down | no-more
show route all | count
show bgp neighbor | match "^Peer:|Description:|Active prefixes:|Received prefixes:|Accepted prefixes:|Suppressed due to damping:|Advertised prefixes:|Table" | no-more



b.2) Complete the following file for Arista devices: 'checks-commands-arista.txt' (Only if you need pre/post checks for Arista devices)

Add the commands you want to perform. Don't use command abbreviations otherwise, they will fail. Regex expressions are supported.

Example:

jcarbonell@jcarbonell-Latitude-7400:~/PACKET$ cat checks-commands-arista.txt 
show ip bgp summary
show ip interface brief
show interfaces status | i down
show ip route


b.3) If you need to have a particular list of commands you want to run for a specific device, you can add one file with the following name cmd-{HOSTNAME}.txt and the script will use the commands
 included in that file for the device with that hostname. If no file with the name format exists, the script will use the commands listed in the files mentioned in b.1) and b.2)
 
 Example

jcarbonell@jcarbonell-Latitude-7400:~/PACKET/pychecks$ cat cmd-esr1b.rk49.dfw2.txt 
show interfaces status
show ip route

 

STEP 1: Execute the script to get the prechecks with the option '-p' (lowercase):

Ex.

python3 pre_post_checks.py -p 

This will create some temporary files in a directory called 'pyTMP' and the pre-checks files with the regular command output with the following name {yyyymmdd-hhmmss}-pre-{hostname}.txt in the 'OUTPUT' folder 



STEP 2: There are two possibilities:

a) Intermediate checks: Execute the script to get the postchecks with the option '-c' along with 'number of intermediate check'. This option won't delete the temporary files inside pyTMP folder so you will be able
to run the multiple intermediate checks (this will compare the outputs got during the pre-checks with the output got in the specific intermediate number you are running):

Ex.
python3 pre_post_checks.py -c 1

This will create the regular command outputs (with this name {yyyymmdd-hhmmss}-intermediate-{number}-{hostname}.txt) and diff files (with this name {yyyymmdd-hhmmss}-diff-intermediate-{number}-{hostname}.txt) in the 'OUTPUT' folder.
You can run the intermediate options as many times as you want. But to avoid the script to override the previous intermediate outputs increment the 'number of intermediate check' param.
It will also create a folder name HTML that contains the diff file in a user friendly way. This is the recommended option to compare pre and intermediate versions.

b) Final post-checks: Execute the script to get the postchecks with the option '-P' (upper case):


Ex.
python3 pre_post_checks.py -P 

This will create the files in the 'OUTPUT' folder with the regular command output for the devices (with this name {yyyymmdd-hhmmss}-post-{hostname}.txt) and the diff files (with this name {yyyymmdd-hhmmss}-diff-{hostname}.txt) with the differences found 
You can run this option once because it will delete all the temporary files and no comparison will be possible without running the pre-checks again.
This option creates a diff file in the HTML file with the same name but with a user friendly way as in the intermediate option.



** NOTE: Other arguments allowed **

*  '-pd <number>': Optional argument. If present, out of all the devices listed in the inventory file, it will get pre/post checks for the devices that match that pod number.
Ex:
python3 pre_post_checks.py -c 1 -pd 1

*  '-a': Optional argument. If present, out of all the devices listed in the inventory file, it will get pre/post checks for esr1a, dsr1/3, ssp1/3, bbr1, csr1.
Ex:
python3 pre_post_checks.py -c 1 -a

*  '-b': Optional argument. If present, out of all the devices listed in the inventory file, it will get pre/post checks for esr1b, dsr2/4, ssp2/4, bbr2, csr2, msws.
Ex:
python3 pre_post_checks.py -c 1 -b

* '-d <hostname>': Optional argument. If present, if the device is listed in the inventory file, it will get pre/post checks for that particular device.
Ex:
python3 pre_post_checks.py -c 1 -d esr1.rk05.p01.fr2

* '-r <RACK LIST>': Optional argument. If present, if there are devices belonging to that rack in the inventory file, it will get pre/post checks for devices in that particular rack.
Ex:
python3 pre_post_checks.py -c 1 -r rk03-5,rk11

* '-s <SITE>': Optional argument. If present,  out of all the devices listed in the inventory file, it will get pre/post checks for the devices that belong to that site.
Ex:
python3 pre_post_checks.py -c 1 -s la4

* '-i <INVENTORY FILE>': Optional argument. By default the script is going to read the inventory file called inventory.txt in the pre_post_check_script folder. If present it will read that new inventory file passed as an argument
Ex:
python3 pre_post_checks.py -c 1 -i NewInventoryFile.txt

You can combine the different arguments to get the devices you want. If there's no match in the inventory file, the script will display an error and exit.

* '-no-html': Optional argument.By default, only HTML diff file is created. If used, it disables the HTML diff file generation saving time.
Ex:
python3 pre_post_checks.py -c 1 -no-html

* '-txt': Optional argument. By default only the HTML diff file is created. With this argument, you can also create a TXT diff file along with the HTML diff file.
Ex:
python3 pre_post_checks.py -c 1 -txt 
