# Jose Carbonell
# v1.0

import sys
import time
from pathlib import Path
import os.path
import shutil
import os, fnmatch
import re
from concurrent.futures import ThreadPoolExecutor
import subprocess
import difflib
from netmiko import ConnectHandler
import argparse
import pynetbox


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

    args = vars(all_args.parse_args())

    username = args["User"].lower()
    intermediateRun = ""

    # Get the hostname of the device we want to run post-checks on
    if args["Prechecks"]:
        option = "pre"
    elif args["Postchecks"]:
        option = "post"
    elif args["CurrentStateComparison"]:
        option = "CurrentStateComparison"
        intermediateRun = str(args["CurrentStateComparison"])

    return option, username, intermediateRun, args


def createConnection(deviceType, host, username):

    params = {}
    if deviceType == "arista_eos":  # ARISTA DEVICES
        params = {
            "device_type": "arista_eos",
            "username": username,
            "use_keys": True,
            "host": host,
            "port": 22,
            "global_delay_factor": 2,
        }
    elif deviceType == "juniper_junos":  # JUNIPER DEVICES
        params = {
            "device_type": "juniper",
            "username": username,
            "host": host,
            "port": 22,
            "use_keys": True,
            "global_delay_factor": 2,
        }

    if params:
        try:
            net_connect = ConnectHandler(**params)
            return net_connect

        except:
            print(
                "\nWARNING: Connection to the device "
                + host
                + " failed. Check username or ssh key or try again later\n"
            )
            sys.exit("Error creating the connection for the host " + host)


def getDeviceOutput(host, command):
    # Gets the output of the command passed as an argument and returns the output of the command
    ssh_command = ["ssh", "-T", host, command]
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
        return ""


def genHTMLDiffFile(file_pre, file_post, command, host, deviceType, intermediateArg):
    # Generate htl diff files
    if os.path.exists("HTML") == False:
        os.mkdir("HTML")

    if intermediateArg:
        output_file = "HTML/" + host + "-pre-intermediate-" + intermediateArg + "-diff.html"
    else:
        output_file = "HTML/" + host + "-pre-post-diff.html"

    with open(file_pre) as f1, open(file_post) as f2:
        file_1 = f1.readlines()
        file_2 = f2.readlines()

    if output_file:
        if deviceType == "arista_eos":
            delta = difflib.HtmlDiff().make_file(
                fromlines=file_1,
                tolines=file_2,
                fromdesc="PRE",
                todesc="POST",
                context=True,
                numlines=0,
            )
        elif deviceType == "juniper_junos" or deviceType == "sr_linux":
            delta = difflib.HtmlDiff().make_file(
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
    if intermediateArg:
        output_file = "OUTPUT/" + host + "-pre-intermediate-" + intermediateArg + "-diff.txt"
    else:
        output_file = "OUTPUT/" + host + "-pre-post-diff.txt"

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


def childPreChecks(host, deviceType, username):
    print("Thread created for", host)

    conn = createConnection(deviceType, host, username)

    timestr = time.strftime("%Y%m%d-%H%M%S")
    f = open("OUTPUT/" + timestr + "-pre-" + host + ".txt", "w+")

    if os.path.exists("cmd-" + host + ".txt") == True:
        commandFileName = "cmd-" + host + ".txt"

    else:

        if deviceType == "arista_eos":
            commandFileName = "checks-commands-arista.txt"
            conn.enable()

        elif deviceType == "juniper_junos":

            commandFileName = "checks-commands-juniper.txt"

        elif deviceType == "sr_linux":
            commandFileName = "checks-commands-nokia.txt"

    with open(commandFileName) as file:  # GET ARISTA COMMANDS AND OUTPUTS
        for command in file:
            command = command.strip()
            filename = command
            invalidChars = '<>:"/\|?*^ '

            for char in invalidChars:
                filename = filename.replace(char, "")

            f.write("<" + host + "> " + command + "\n\n")
            if deviceType == "sr_linux":
                try:
                    output = getDeviceOutput(host, command)

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
            else:
                try:
                    output = conn.send_command(command)

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

            tmpf = open("pyTMP/" + filename + "-pre-" + host + ".txt", "w")
            f.write(str(output).replace("<.*>", ""))
            f.write("\n\n")
            tmpf.write(str(output).replace("<.*>", ""))
            tmpf.write("\n\n")
            tmpf.close()

    f.close()
    return "Pre-checks completed successfully for " + host


def childPostChecks(host, deviceType, username, option, intermediateArg):

    print("Thread created for", host)

    timestr = time.strftime("%Y%m%d-%H%M%S")
    if option == "CurrentStateComparison":

        f = open(
            "OUTPUT/" + timestr + "-intermediate-" + intermediateArg + "-" + host + ".txt",
            "w+",
        )

    else:

        f = open("OUTPUT/" + timestr + "-post-" + host + ".txt", "w+")

    if os.path.exists("cmd-" + host + ".txt") == True:
        commandFileName = "cmd-" + host + ".txt"

    else:

        if deviceType == "arista_eos":
            commandFileName = "checks-commands-arista.txt"

        elif deviceType == "juniper_junos":

            commandFileName = "checks-commands-juniper.txt"

        elif deviceType == "sr_linux":
            commandFileName = "checks-commands-nokia.txt"

    conn = createConnection(deviceType, host, username)

    with open(
        commandFileName
    ) as file:  # GET ARISTA COMMANDS AND OUPUTS AND COMPARE THEM WITH THE PREVIOUSLY STORED IN THE TEMP DIRECTORY
        for command in file:
            command = command.strip()
            filename = command
            invalidChars = '<>:"/\|?*^ '

            for char in invalidChars:
                filename = filename.replace(char, "")

            f.write("<" + host + "> " + command + "\n")

            if deviceType == "sr_linux":
                try:
                    output = getDeviceOutput(host, command)
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
            else:
                try:
                    output = conn.send_command(command)
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

            tmpFilenamePre = "pyTMP/" + filename + "-pre-" + host + ".txt"
            if option == "CurrentStateComparison":
                tmpFilenamePost = "pyTMP/" + filename + "-int-" + intermediateArg + "-" + host + ".txt"
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
            genTXTDiffFile(tmpFilenamePre, tmpFilenamePost, command, host, intermediateArg)
            # Removing tmp files if not intermediate option
            if not option == "CurrentStateComparison":
                r = os.remove(tmpFilenamePre)
            r = os.remove(tmpFilenamePost)

    f.close()

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


if __name__ == "__main__":

    # Get arguments
    option, username, intermediateRun, args = getArguments()
    if option == "pre":

        # username = sys.argv[2]

        if os.path.exists("pyTMP") == False:
            os.mkdir("pyTMP")

        if os.path.exists("OUTPUT") == False:
            os.mkdir("OUTPUT")

        with open(args["inventory"]) as file:

            with ThreadPoolExecutor(max_workers=25) as executor:  # CREATE THREADS FOR EACH DEVICE
                futures = []
                for host in file:
                    if host.strip():
                        host = host.strip().replace(".mgmt.", ".")
                        deviceType = get_platform(host.split(".packet.net")[0])
                        futures.append(
                            executor.submit(
                                childPreChecks,
                                host=host,
                                deviceType=deviceType,
                                username=username,
                            )
                        )

                for future in futures:
                    print(future.result())

        print("\n[END]\n")

    elif option == "post" or option == "CurrentStateComparison":
        if os.path.exists("pyTMP") == False:
            print("\nPlease perform prechecks first by using the 'pre' keyword\n")
            exit(0)

        with open(args["inventory"]) as file:
            with ThreadPoolExecutor(max_workers=25) as executor:  # CREATE THREADS FOR EACH DEVICE
                futures = []
                for host in file:
                    if host.strip():
                        host = host.strip().replace(".mgmt.", ".")
                        deviceType = get_platform(host.split(".packet.net")[0])
                        futures.append(
                            executor.submit(
                                childPostChecks,
                                host=host,
                                deviceType=deviceType,
                                username=username,
                                option=option,
                                intermediateArg=intermediateRun,
                            )
                        )

                for future in futures:
                    print(future.result())

        # REMOVE TEMP FILES
        if not option == "CurrentStateComparison":

            if not os.listdir("pyTMP"):  # if directory is empty, remove it (temp files deleted above)
                shutil.rmtree("pyTMP")

        print("\n[END]\n")
