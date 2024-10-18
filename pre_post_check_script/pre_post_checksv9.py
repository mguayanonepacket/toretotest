# Jose Carbonell
# v1.1

import sys
import time
from pathlib import Path
import os.path
import shutil
import os
import re
from concurrent.futures import ThreadPoolExecutor
import subprocess
import difflib
from netmiko import ConnectHandler
import argparse
import pynetbox
import paramiko
import threading
import multiprocessing


class LimitedRecursionHtmlDiff(difflib.HtmlDiff):
    def __init__(self, recursion_limit=None, *args, **kwargs):
        self.recursion_limit = recursion_limit
        super().__init__(*args, **kwargs)
        
    def _format_range_unified(self, from_line, to_line):
        if self.recursion_limit is not None and self.recursion_limit <= 0:
            # If recursion limit reached, output a placeholder message
            return '<span class="placeholder">...</span>'
        
        if self.recursion_limit is not None:
            # Decrement recursion limit for nested calls
            self.recursion_limit -= 1
        
        return super()._format_range_unified(from_line, to_line)
        
            
def establishConnection(host, username):
    
  
    # Replace this with the actual path to your private key file
    private_key_path = str(Path.home())+'/.ssh/id_rsa'
    

    # Create an SSH client
    ssh_client = paramiko.SSHClient()

    # Set the policy to automatically add the server's host key (this is insecure and should be done carefully in production)
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Load the private key
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)

        # Connect to the device
        ssh_client.connect(hostname=host, username=username, pkey=private_key, timeout=10)
        
        return ssh_client

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials and private key.")
    except paramiko.SSHException as e:
        print(f"SSH error: {e}")
    except Exception as e:
        print(f"Error: {e}")


def getArguments():
    # Function that gets the arguments and depending of the options returns the variablos required to execute the different options. Ir return the username used for JUniper devices, site name,
    # pod, rack range and a variable onlyCreateFile that is used when the script only needs to generate the EAPI config file.

    # Construct an argument parser
    all_args = argparse.ArgumentParser()

    # Add arguments to the parser
    all_args.add_argument(
        "-p",
        "--Prechecks",
        required=False,
        action="store",
        const="NoValue",
        nargs="?",
        help="Get the pre-checks (ex. -p)",
    )
    all_args.add_argument(
        "-u",
        "--User",
        default=os.getenv("USER"),
        help="Introduce the username for Juniper devices (ex. -u myuser)",
    )
    all_args.add_argument(
        "-P",
        "--Postchecks",
        required=False,
        action="store",
        const="NoValue",
        nargs="?",
        help="Get the post-checks (ex. -p)",
    )
    all_args.add_argument(
        "-c",
        "--CurrentStateComparison",
        required=False,
        type=int,
        help="Get the intermediate checks (ex. -c 1)",
    )
    all_args.add_argument(
        "-i",
        "--inventory",
        default="inventory.txt",
        required=False,
        help="Path to inventory file (ex, -i ~/inventory.txt)",
    )
    all_args.add_argument(
        "-s",
        "--Sites",
        default="",
        required=False,
        help="List of sites comma separated (ex, -s dc10,dc13)",
    )
    all_args.add_argument(
        "-a",
        "--AsideDevices",
        action="store",
        const="NoValue",
        nargs="?",
        required=False,
        help="Only include Aside devices: esr1a, dsr1/3, csr1, ssp1/3, bbr1, bsr1, msr1/3, mdr1/3  (ex, -a)",
    )
    all_args.add_argument(
        "-b",
        "--BsideDevices",
        action="store",
        const="NoValue",
        nargs="?",
        required=False,
        help="Only include Aside devices: esr1b, dsr2/4, csr2, ssp2/4, bbr2, bsr1, msws, msr2/4, mdr2/4, fw1 (ex, -b)",
    )
    all_args.add_argument(
        "-pd",
        "--Pods",
        default="",
        required=False,
        help="List of sites comma separated (ex, -s 1,2,3)",
    )
    all_args.add_argument(
        "-r",
        "--Racks",
        default="",
        required=False,
        help="List of sites comma separated (ex, -r rk01-2,rk13)",
    )
    all_args.add_argument(
        "-d",
        "--Devices",
        default="",
        required=False,
        help="List of devices comma separated (ex, -d esr1a.rk01.p01.ny5,esr1b,rk02.p01.ny7)",
    )
    args = vars(all_args.parse_args())

    username = args["User"].lower()
    intermediateRun = ""
    sites=[]
    devs=[]
    pods=[]
    racks=[]
    devices=[]

    # Get the hostname of the device we want to run post-checks on
    if args["Prechecks"]:
        option = "pre"
    if args["Postchecks"]:
        option = "post"
    if args["CurrentStateComparison"]:
        option = "CurrentStateComparison"
        intermediateRun = str(args["CurrentStateComparison"])
    if args["Sites"]:
        sites=str(args["Sites"]).split(',')
    if args["Pods"]:
        pods=str(args["Pods"]).split(',')
    if args["Racks"]:
        racks=getRackList(str(args["Racks"]).split(','))
    if args["Devices"]:
        devices=str(args["Devices"]).split(',')
    if args["AsideDevices"]:
        devs=["esr1a","dsr1", "dsr3", "csr1", "ssp1","ssp3", "bbr1", "bsr1", "msr1", "msr3", "mdr1", "mdr3", "mrr1"]
    if args["BsideDevices"]:
        devs=["esr1b","dsr2", "dsr4", "csr2", "ssp2","ssp4", "bbr2", "bsr2", "msr2", "msr4", "mdr2", "mdr4", "mrr2", "msw1", "msw2", "fw1"]

    return option, username, intermediateRun, args, sites, devs, pods, racks, devices


def getDeviceOutput(host, command):
    # Gets the output of the command passed as an argument and returns the output of the command
    #ssh_command = ['ssh', '-o', 'UserKnownHostsFile=/dev/null','-o','StrictHostKeyChecking=no','-T', host, command]
    ssh_command = ['ssh','-T', host, command]
    try:
        process = subprocess.Popen(
            ssh_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        output = ""
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output += line
        return output
    except subprocess.CalledProcessError as e:
        print(
            f"\nWARNING: Connection to the device {host} failed while trying to get the output of the command {command}."
        )
        print("Check the command and try again later.\n")
        return 


def genHTMLDiffFile(file_pre, file_post, command, host, deviceType, intermediateArg):
    invalidChars = '<>:"/\|?*^ '
    for char in invalidChars:
        commandName = command.replace(char, "")
    # Generate html diff files
    if not os.path.exists("HTML"):
        try:
            os.mkdir("HTML")
        except:
            print("The HTML directory already exists")
            pass
            
    if intermediateArg:
        intermediateDir="TMP-intermediate-"+ intermediateArg + "-diffs"
        if not os.path.exists("HTML/"+str(intermediateDir)):
            try:
                os.mkdir("HTML/"+str(intermediateDir))
            except:
                print(f"The HTML/{intermediateDir} directory already exists")
                pass
            
        output_file = (
            "HTML/"+ intermediateDir + "/"+commandName+"-"+host + "-pre-intermediate-" + intermediateArg + "-diff.html"
        )
    else:
        if not os.path.exists("HTML/TMP-POST"):
            try:
                os.mkdir("HTML/TMP-POST")
            except:
                print("The HTML/TMP-POST directory already exists")
                pass
            
        output_file = "HTML/TMP-POST/"+commandName+"-" + host + "-pre-post-diff.html"

    with open(file_pre) as f1, open(file_post) as f2:
        file_1 = f1.readlines()
        file_2 = f2.readlines()

    if output_file:
        if deviceType == "arista_eos":
            html_diff = LimitedRecursionHtmlDiff(recursion_limit=15)
            delta = html_diff.make_file(
                fromlines=file_1,
                tolines=file_2,
                fromdesc="PRE",
                todesc="POST",
                context=True,
                numlines=0,
            )
        elif deviceType == "juniper_junos" or deviceType == "sr_linux":
            html_diff = LimitedRecursionHtmlDiff(recursion_limit=15)
            delta = html_diff.make_file(
                fromlines=file_1,
                tolines=file_2,
                fromdesc="PRE",
                todesc="POST",
                context=False,
            )

        with open(output_file, "a+") as f:
            f.write(
                "\n<html><head><title>"
                + str(host)
                + '</title></head><body></br><table style="border:1px solid black;border-collapse:collapse;"><td bgcolor="#99CCFF"><b># '
                + str(command)
                + " #</b></td></br></body></html>"
            )
            f.write(delta)
            f.write("\n\n")


def genTXTDiffFile(file_pre, file_post, command, host, intermediateArg):
    
    invalidChars = '<>:"/\|?*^ '
    for char in invalidChars:
        commandName = command.replace(char, "")
        
    if intermediateArg:
        intermediateDir="TMP-intermediate-"+ intermediateArg + "-diffs"
        if not os.path.exists("OUTPUT/"+str(intermediateDir)):
            try:
                os.mkdir("OUTPUT/"+str(intermediateDir))
            except:
                print(f"The OUTPUT/{intermediateDir} directory already exists")
                pass

        output_file = (
            "OUTPUT/"+ intermediateDir + "/"+commandName+"-" + host + "-pre-intermediate-" + intermediateArg + "-diff.txt"
        )
    else:
        if not os.path.exists("OUTPUT/TMP-POST/"):
            try:
                os.mkdir("OUTPUT/TMP-POST/")
            except:
                print(f"The OUTPUT/TMP-POST/ directory already exists")
                pass
            
        output_file = "OUTPUT/TMP-POST/"+commandName+"-"  + host + "-pre-post-diff.txt"

    with open(file_pre) as f1, open(file_post) as f2:
        file_1 = f1.readlines()
        file_2 = f2.readlines()
    diff = difflib.Differ(charjunk=lambda x: x in [",", ".", "-", "'"])
    if output_file:
        with open(output_file, "a+") as f:
            f.write("\n<" + str(host) + ">" + str(command) + "")
            for line in diff.compare(file_1, file_2):
                f.write(line)
            f.write("\n")


def childPreChecks(host, deviceType, username, option, intermediateArg):
    print("Thread created for", host)
    if not os.path.exists("OUTPUT"):
        try:
            os.mkdir("OUTPUT")
        except:
            print(f"The OUTPUT directory already exists")
            pass
        
    if not os.path.exists("OUTPUT/PRE/"):
        try:
            os.mkdir("OUTPUT/PRE/")
        except:
            print(f"The OUTPUT/PRE/ directory already exists")
            pass
        
    timestr = time.strftime("%Y%m%d-%H%M%S")
    f = open("OUTPUT/PRE/" + timestr + "-pre-" + host + ".txt", "w+")
    if os.path.exists("cmd-" + host + ".txt") == True:
        commandFileName = "cmd-" + host + ".txt"

    else:

        if deviceType == "arista_eos":
            commandFileName = "checks-commands-arista.txt"

        elif deviceType == "juniper_junos":
            commandFileName = "checks-commands-juniper.txt"

        elif deviceType == "sr_linux":
            commandFileName = "checks-commands-nokia.txt"
            
    connection=establishConnection(host,username)
    buf_size=66536
    with open(commandFileName) as file:  # GET COMMANDS AND OUTPUTS
        for command in file:
            command = command.strip()
            filename = command
            invalidChars = '<>:"/\|?*^ '

            for char in invalidChars:
                filename = filename.replace(char, "")

            f.write("<" + host + "> " + command + "\n\n")
            
            try:
                stdin, stdout, stderr = connection.exec_command(command, bufsize=buf_size)
                output = stdout.read(buf_size).decode()

            except:
                print(
                    "\nWARNING: The command '"
                    + command
                    + "' failed for the device "
                    + host
                    + ". Check the command syntax or run it manually on the device\n"
                )
                f.write(
                    "\nWARNING: The command '"
                    + command
                    + "' failed for the device "
                    + host
                    + ". Check the command syntax or run it manually on the device\n\n"
                )
                continue


            f.write(str(output).replace("<.*>", ""))
            f.write("\n\n")
            with open("pyTMP/" + filename + "-pre-" + host + ".txt", "w") as tmpf:
                tmpf.write(str(output).replace("<.*>", ""))
                tmpf.write("\n\n")

    f.close()
    return "Pre-checks completed successfully for " + host

def worker(option, intermediateArg, host, command, deviceType):
    connection=establishConnection(host,username)
    buf_size=66536
    invalidChars = '<>:"/\|?*^ '
    for char in invalidChars:
        filename = command.replace(char, "")
    if not os.path.exists("OUTPUT"):
        try:
            os.mkdir("OUTPUT")
        except:
            print("The OUTPUT directory already exists")
            pass
            
    if option == "CurrentStateComparison":
        intermediateDir="TMP-intermediate-"+ intermediateArg + "-diffs"
        if not os.path.exists("OUTPUT/"+str(intermediateDir)):
            try:
                os.mkdir("OUTPUT/"+str(intermediateDir))
            except:
                print(f"The OUTPUT/{intermediateDir} directory already exists")
                pass
            
        filenameTMP = "OUTPUT/"+ intermediateDir + "/"+ filename + "-intermediate-" + intermediateArg+ "-" + host + ".txt"
    else:
        if not os.path.exists("OUTPUT/TMP-POST-/"):
            try:
                os.mkdir("OUTPUT/TMP-POST/")
            except:
                print(f"The OUTPUT/TMP-POST/ directory already exists")
                pass
            
        filenameTMP = "OUTPUT/TMP-POST/" + filename + "-post-" + host + ".txt"
   
    f = open(filenameTMP,"w+" )
    f.write("<" + host + "> " + command + "\n")

    try:

        stdin, stdout, stderr = connection.exec_command(command, bufsize=buf_size)
        output = stdout.read(buf_size).decode()

    except Exception as e:
        print(f"Error connecting to {host}: {str(e)}")
        print(
            "\nWARNING: The command '"
            + command
            + "' failed for the device "
            + host
            + ". Check the command syntax or run it manually on the device\n"
        )
        f.write(
            "\nWARNING: The command '"
            + command
            + "' failed for the device "
            + host
            + ". Check the command syntax or run it manually on the device\n\n"
        )
        return

    tmpFilenamePre = "pyTMP/" + filename + "-pre-" + host + ".txt"
    if option == "CurrentStateComparison":
        tmpFilenamePost = (
            "pyTMP/"
            + filename
            + "-int-"
            + intermediateArg
            + "-"
            + host
            + ".txt"
        )
    elif option == "post":
        tmpFilenamePost = "pyTMP/" + filename + "-post-" + host + ".txt"

    tmpf = open(tmpFilenamePost, "w")
    f.write(str(output).replace("<.*>", ""))
    tmpf.write(str(output).replace("<.*>", ""))
    tmpf.write("\n\n")
    tmpf.close()
    genHTMLDiffFile(
        tmpFilenamePre,
        tmpFilenamePost,
        command,
        host,
        deviceType,
        intermediateArg,
    )
    genTXTDiffFile(
       tmpFilenamePre, tmpFilenamePost, command, host, intermediateArg
    )
    #Removing tmp files if not intermediate option
    if not option=="CurrentStateComparison":
        r=os.remove(tmpFilenamePre)
    r = os.remove(tmpFilenamePost)
    connection.close()
    f.close()
    #print("# Diffs completed for "+host + "- Command: "+command)
    return 

def combineTXTFiles(host,intermediateArg):
    #print("Combining text files for "+host)
    if not os.path.exists("OUTPUT"):
        try:
            os.mkdir("OUTPUT")
        except:
            print("The OUTPUT directory already exists")
            pass
    timestr = time.strftime("%Y%m%d-%H%M%S")
    if option == "CurrentStateComparison":
        intermediateDir="intermediate-"+ intermediateArg + "-diffs"
        if not os.path.exists("OUTPUT/"+str(intermediateDir)):
            try:
                os.mkdir("OUTPUT/"+str(intermediateDir))
            except:
                print("The OUTPUT directory already exists")
                pass
            
        output_file = "OUTPUT/"+ intermediateDir + "/"+ timestr + "-intermediate-" + intermediateArg+ "-" + host + ".txt"

        try:
            cmd = [
                "sh",  # Run the command through a shell
                "-c",  # Use a shell command
                f'cat OUTPUT/TMP-{intermediateDir}/*{host}*.txt >> {output_file}'
            ]
            subprocess.run(cmd, check=True, shell=False)
            #print(f"Successfully combined text files for {host}!")

        except subprocess.CalledProcessError as e:
            print(f"TXT Diff - Error occurred: {e} for {host}")
        
    else:
        if not os.path.exists("OUTPUT/POST/"):
            try:
                os.mkdir("OUTPUT/POST/")
            except:
                print("The OUTPUT/POST directory already exists")
                pass
            
        output_file = "OUTPUT/POST/" + timestr + "-post-" + host + ".txt"

        try:
            cmd = [
                "sh",  # Run the command through a shell
                "-c",  # Use a shell command
                f'cat OUTPUT/TMP-POST/*{host}*.txt >> {output_file}'
            ]
            subprocess.run(cmd, check=True, shell=False)
            #print(f"Successfully combined text files for {host}!")

        except subprocess.CalledProcessError as e:
            print(f"TXT Diff - Error occurred: {e} for {host}")
    
                
def combineHTMLFiles(host,intermediateArg):
    #print("Combining HTML files for "+host)
        # Generate htl diff files
    if not os.path.exists("HTML"):
        try:
            os.mkdir("HTML")
        except:
            print("The HTML directory already exists")
            pass
        
    if intermediateArg:
        intermediateDir="intermediate-"+ intermediateArg + "-diffs"
        if not os.path.exists("HTML/"+str(intermediateDir)):
            try:
                os.mkdir("HTML/"+str(intermediateDir))
            except:
                print(f"The HTML/{intermediateDir} directory already exists")
                pass
            
        output_file = (
            "HTML/"+ intermediateDir + "/"+ host + "-pre-intermediate-" + intermediateArg + "-diff.html"
        )
        try:
            cmd = [
                "sh",  # Run the command through a shell
                "-c",  # Use a shell command
                f'cat HTML/TMP-{intermediateDir}/*{host}-pre-intermediate-{intermediateArg}*.html >> {output_file}'
            ]
            subprocess.run(cmd, check=True, shell=False)
            #print(f"Successfully combined HTML files for {host}!")

        except subprocess.CalledProcessError as e:
            print(f"HTML Diff- Error occurred: {e} for {host}")
            
    else:
        if os.path.exists("HTML/POST") == False:
            try:
                os.mkdir("HTML/POST")
            except:
                print("The HTML/POST directory already exists")
                pass
        output_file = "HTML/POST/" + host + "-pre-post-diff.html"
        try:
            cmd = [
                "sh",  # Run the command through a shell
                "-c",  # Use a shell command
                f'cat HTML/TMP-POST/*{host}-pre-post-*.html >> {output_file}'
            ]
            subprocess.run(cmd, check=True, shell=False)
            #print(f"Successfully combined HTML files for {host}!")

        except subprocess.CalledProcessError as e:
            print(f"HTML Diff- Error occurred: {e} for {host}")
        
    
                
def childPostChecks(host, deviceType, username, option, intermediateArg):

    print("Thread created for", host)
    
    if os.path.exists("cmd-" + host + ".txt") == True:
        commandFileName = "cmd-" + host + ".txt"

    else:

        if deviceType == "arista_eos":
            commandFileName = "checks-commands-arista.txt"

        elif deviceType == "juniper_junos":
            commandFileName = "checks-commands-juniper.txt"

        elif deviceType == "sr_linux":
            commandFileName = "checks-commands-nokia.txt"


    threads = []
    with open(
        commandFileName
    ) as file:  # GET COMMANDS AND OUPUTS AND COMPARE THEM WITH THE PREVIOUSLY STORED IN THE TEMP DIRECTORY
        for command in file:
            command = command.strip()
            thread = threading.Thread(target=worker, args=(option, intermediateArg,host, command, deviceType))
            thread.start()
            threads.append(thread)
            
       # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
    #combineTXTFiles(host,intermediateArg)
    combineHTMLFiles(host,intermediateArg)

    return "Post-checks completed successfully for " + host



def get_platform(host):
    nb = init_nb()
    dev = nb.dcim.devices.get(name=host)
    platform = dev.platform.slug.replace("-", "_")
    return platform


def init_nb():
    nb_url = os.getenv("NB_URL")
    nb_api = os.getenv("NB_API_KEY")
    if not all([nb_url, nb_api]):
        raise ValueError("NB_URL and NB_API_KEY must all be set in the local env")
    nb = pynetbox.api(url=nb_url, token=nb_api)
    return nb

def getRackList(rackListProvided):
    rackList=[]
    coreRack=False
    for item in rackListProvided:
        if item.find('core') != -1:
                    
                rackRange=item.strip("core").split("-")
                coreRack=True
                    
        else:	
                rackRange=item.strip("rk").split("-")
        if len(rackRange)==1:  #Only one rack is passed as an argument
            if coreRack:
                rackList.append("core"+str(rackRange[0]).zfill(1))        
            else:
                rackList.append("rk"+str(rackRange[0]).zfill(2))
            
        else:                  #Rack range passed as an argument
            
            tmpRackList=list(range(int(rackRange[0]), int(rackRange[1])+1))
            if coreRack:
                for i in range(0, len(tmpRackList)):
                    rackList.append("core"+str(tmpRackList[i]).zfill(1))
            else:
                for i in range(0, len(tmpRackList)):
                    rackList.append("rk"+str(tmpRackList[i]).zfill(2))
    

    return rackList


def filterHosts(sites, devs, pods, host, hosts4Threads, racks, devices, process_index):
    skipDevice=False                
    if sites:
        for site in sites:
            if site not in host:
                skipDevice=True
            else:
                skipDevice=False
                break

    if pods and not skipDevice:
        for pod in pods:            
            if "p"+pod.zfill(2) not in host:
                skipDevice=True
            else:
                skipDevice=False
                break

    if devs and not skipDevice:
        if host.split(".")[0] not in devs:
            skipDevice=True

    if racks and not skipDevice:
        for rack in racks: 
            if rack not in host:
                skipDevice=True
            else:
                skipDevice=False
                break
    
    if devices and not skipDevice:
        for device in devices:  
            if device not in host:
                skipDevice=True
            else:
                skipDevice=False
                break
                
    
    if not skipDevice:
        hosts4Threads[process_index].append(host)
    
    return hosts4Threads

def remove_subdirectories_matching_regex(root_dir, regex_pattern):
    for dirpath, dirnames, filenames in os.walk(root_dir, topdown=False):
        for dirname in dirnames:
            if re.match(regex_pattern, dirname):
                dir_to_remove = os.path.join(dirpath, dirname)
                shutil.rmtree(dir_to_remove)
                print(f"Removed directory: {dir_to_remove}")
                
def createThreads(hosts4Threads,username,option,intermediateRun, result_queue):
    with ThreadPoolExecutor(
    max_workers=20
    ) as executor:  # CREATE THREADS FOR EACH DEVICE
        futures = []
        for host in hosts4Threads:
            deviceType = get_platform(host.split(".packet.net")[0])
            futures.append(
            
                executor.submit(
                    childPostChecks if option!='pre' else childPreChecks,
                    host=host,
                    deviceType=deviceType,
                    username=username,
                    option=option,
                    intermediateArg=intermediateRun,
                )
            )
    
        for future in futures:
            print(future.result())
            result=future.result()
            result_queue.put(result)
        
    
if __name__ == "__main__":

    # Get arguments
    option, username, intermediateRun, args, sites, devs, pods, racks, devices = getArguments()
    
    if option == "pre":
        numProcesses=4
        hosts4Threads=[[] for _ in range(numProcesses)]
        if not os.path.exists("pyTMP"):
            try:
                os.mkdir("pyTMP")
            except:
                print("The pyTMP directory already exists")
                pass
           
        if not os.path.exists("OUTPUT"):
            try:
                os.mkdir("OUTPUT")
            except:
                print("The OUTPUT directory already exists")
                pass
            
        with open(args["inventory"]) as file:
            i=0
            for host in file:
                if host.strip():
                    host = host.strip().replace(".mgmt.", ".")
                    process_index = i % numProcesses
                    hosts4Threads=filterHosts(sites, devs, pods, host, hosts4Threads, racks, devices, process_index)
                    i+=1

            if not hosts4Threads:
                print("No devices match the parameters criteria")
                sys.exit()
                        
                
        processes = []
        result_queue = multiprocessing.Queue()

    
        for process_num, devices_list in enumerate(hosts4Threads):
            process = multiprocessing.Process(target=createThreads, args=(devices_list,username,option,intermediateRun, result_queue))
            processes.append(process)
            process.start()

        # Wait for all processes to complete
        for process in processes:
            process.join()

        # Collect results from the queue
        results = []
        while not result_queue.empty():
            results.append(result_queue.get())

        # Print the results
        #for hostname, result in results:
        #    print(f"{result}")

        print("All processes have finished")

        print("\n[END]\n")

    elif option == "post" or option == "CurrentStateComparison":
        numProcesses=4
        # Initialize empty lists for each process
        hosts4Threads=[[] for _ in range(numProcesses)]
        if os.path.exists("pyTMP") == False:
            print("\nPlease perform prechecks first by using the 'pre' keyword\n")
            exit(0)
        if option == "post":
            check=''
            while check != 'y' and check != 'n':
                msg='# The \'post\' option will delete all temp files.No additional comparations will be possible afterwards. Are you sure? (y/n)'
                check = input(msg+'.'*(85-len(msg))+': ').lower()
            if check=='n':
                sys.exit("Script aborted by the user.")
                
        with open(args["inventory"]) as file:
            i=0
            for host in file:
                if host.strip():
                    host = host.strip().replace(".mgmt.", ".")
                    process_index = i % numProcesses
                    hosts4Threads=filterHosts(sites, devs, pods, host, hosts4Threads, racks, devices, process_index)
                    i+=1

                if not hosts4Threads:
                    print("No devices match the parameters criteria")
                    sys.exit()
                        
        
        processes = []
        result_queue = multiprocessing.Queue()

    
        for process_num, devices_list in enumerate(hosts4Threads):
            process = multiprocessing.Process(target=createThreads, args=(devices_list,username,option,intermediateRun, result_queue))
            processes.append(process)
            process.start()

        # Wait for all processes to complete
        for process in processes:
            process.join()

        # Collect results from the queue
        results = []
        while not result_queue.empty():
            results.append(result_queue.get())

        # Print the results
        #for result in results:
        #    print(f"{result}")

        print("All processes have finished")
                        

        # REMOVE TEMP FILES
        print("# Cleaning up temp files....")
        remove_subdirectories_matching_regex('OUTPUT', 'TMP-*')
        remove_subdirectories_matching_regex('HTML', 'TMP-*')
        if not option == "CurrentStateComparison":

            if not os.listdir(
                "pyTMP"
            ):  # if directory is empty, remove it (temp files deleted above)
                shutil.rmtree("pyTMP")

        print("\n[END]\n")
