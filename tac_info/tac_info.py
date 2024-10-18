#!/usr/bin/env python3
# juniper
from jnpr.junos.utils.config import Config
from jnpr.junos import Device
from jnpr.junos.utils.start_shell import StartShell
from pprint import pprint
from jnpr.junos.utils.fs import FS

# system utils
import sys
import os
from pathlib import Path
import time
from datetime import datetime
import subprocess
import socket
import re

# SFTP stuff
from jnpr.junos.utils.ftp import FTP
from scp import SCPClient
import paramiko
from paramiko import SFTPClient, SSHClient, SSHConfig, Transport

# threading
from concurrent.futures import ThreadPoolExecutor

# NB
import pynetbox
from pathlib import Path
from netmiko import ConnectHandler


banner = "\n" + "=" * 10 + "\n"
jnp_ftp_server = socket.gethostbyname("sftp.juniper.net")
jnp_ftp_user = "jtac"
jnp_ftp_pass = "anonymous"
arista_ftp_server = "tac-sftp.arista.com"  # use fqdn
arista_ftp_user = "equinixfer"
arista_ftp_pass = "GEI7J0(fHKZ7Hv0W&7QF"

dev_files = []
local_files = []
date = time.strftime("%Y%m%d")
dev_path = "/var/tmp/"
nb = pynetbox.api(url=os.environ["NB_URL"], token=os.environ["NB_API_KEY"])
nokia_wait_time = 15 * 60  # 15min * 60sec


def get_args():
    upload_lock = True
    if len(sys.argv) > 2:
        if sys.argv[1] == "-d":
            device = str(sys.argv[2])
        if sys.argv[3] == "-c":
            tac = str(sys.argv[4])
        if len(sys.argv) > 5:
            if sys.argv[5] == "-noupload":
                upload_lock = False

    if len(sys.argv) < 2:
        print(
            "You must use -d to set the device and -c to set the tac case number.\nIf you wan't to keep the files locally only use the '-noupload' option after the case number"
        )
        exit()
    return (device, tac, upload_lock)


def gather_info(device, tac, dev_type, dev_files):

    if dev_type == "Juniper":
        dev = Device(host=device)
        fs = FS(dev)
        file_naming = device + "_" + str(tac) + "_" + time.strftime("%Y%m%d")
        try:
            dev.open()
            print("> Connected to: " + device + "\n")
        except:
            print(":: WARNING ::\nFailed to connect to the device.\n")
        Dual_RE = dev.facts["2RE"]
        master_slot = (dev.facts["master"]).strip("")[2]
        master_re = ""
        wait = "."
        if Dual_RE == True:
            master_re = "RE" + master_slot + "-"
            if master_slot == "0":
                dev.rpc.make_directory(directory=dev_path + "re1/")
                with StartShell(dev) as ss:
                    i = 0
                    print(
                        "> Copying log folder from the other RE, this will take some time (around 1 min, depending on folder's size)..."
                    )
                    start_time = datetime.now()
                    try:
                        ss.run("rcp -rpT re1:/var/log /var/tmp/re1/", this="%", timeout=180)
                        print("\t> Copy logs from backup RE completed")
                    except:
                        print("\t:: WARNING ::\nFailed to copy logs from the other RE, please do it manually\n")
                    end_time = datetime.now()
                print("\t> Total time: {}".format(end_time - start_time))
                print("\n> Compressing logs from backup RE")
                dev.rpc.file_archive(
                    compress=True, source=dev_path + "re1/", destination=dev_path + "RE1-logs_" + file_naming + ".tgz"
                )
                if fs.ls(path=dev_path + "RE1-logs_" + file_naming + ".tgz"):
                    print("\t> Logs from BACKUP RE compression completed.\n")
                    log = dev_path + "RE1-logs_" + file_naming + ".tgz"
                    with StartShell(dev) as ss:
                        ss.run("rm -r /var/tmp/re1/")
                    dev_files.append(log)
            if master_slot == "1":
                dev.rpc.make_directory(directory=dev_path + "re0/")
                with StartShell(dev) as ss:
                    print("> Copying log folder from the other RE, this will take some time...")
                    start_time = datetime.now()
                    try:
                        ss.run("rcp -rpT re0:/var/log /var/tmp/re0/", this="%", timeout=180)
                        print("\t> Copy logs from backup RE completed")
                    except:
                        print("\t:: WARNING ::\nFailed to copy logs from the other RE, please do it manually\n")
                    end_time = datetime.now()
                print("\t> Total time: {}".format(end_time - start_time))
                print("\n> Compressing logs from backup RE")
                dev.rpc.file_archive(
                    compress=True, source=dev_path + "re0/", destination=dev_path + "RE0-logs_" + file_naming + ".tgz"
                )
                if fs.ls(path=dev_path + "RE0-logs_" + file_naming + ".tgz"):
                    print("Logs from BACKUP RE compression completed.\n\n")
                    log = dev_path + "RE1-logs_" + file_naming + ".tgz"
                    fs.rmdir(dev_path + "re0/")
                    dev_files.append(log)
        print("\n> Compressing logs on MASTER RE, please be patient...")
        try:
            dev.rpc.file_archive(
                compress=True, destination=dev_path + master_re + "logs_" + file_naming, source="/var/log/*"
            )
            print("\t> Logs compression completed.\n")
        except:
            print("\t:: WARNING ::\nFailed to compress the logs.\n")
        if fs.ls(path=dev_path + master_re + "logs_" + file_naming + ".tgz"):
            log = dev_path + master_re + "logs_" + file_naming + ".tgz"
            dev_files.append(log)

        try:
            print("\n> Generating RSI, please be patient...")
            with StartShell(dev) as ss:
                ss.run('cli -c "request support information | save /var/tmp/RSI_' + file_naming + '.txt"')
        except:
            print("\t:: WARNING ::\nFailed to generate RSI.\n")
        if fs.ls(path=dev_path + "RSI_" + file_naming + ".txt"):
            print("\t> RSI generated correctly\n\n")
            rsi = dev_path + "RSI_" + file_naming + ".txt"
            dev_files.append(rsi)
        try:
            print("\n> Checking for core-dump...")
            core_dumps = dev.rpc.get_system_core_dumps()
        except:
            print("\t:: WARNING ::\nFailed to get core-dumps.\n")
        for file_name in core_dumps.findall("..//file-information"):
            core_file = file_name.find("./file-name").text
            dev_files.append(core_file.strip("\n"))
            print("\t> Found core-dump file: " + "\t" + core_file)

    elif dev_type == "Arista":

        dev = {
            "device_type": "arista_eos",
            "host": device,
            "username": "admin",
            "password": os.environ["ADMIN_PW"],
            "global_delay_factor": 3,
        }
        host = device + ".packet.net"
        try:
            dev_conn = ConnectHandler(**dev)
            print("> Connected to: " + device + "\n")
        except:
            print(
                ":: WARNING :: Connection to the device "
                + device
                + " failed. Check username or password or try again later\n"
            )
            exit()
        commands = [
            "show tech-support | gzip > /mnt/flash/" + str(tac) + "-show-tech-" + device + "_" + date + ".log.gz",
            "show agent log | gzip > /mnt/flash/" + str(tac) + "-show-agentlog-" + device + "_" + date + ".log.gz",
            "bash sudo tar -czvf - /var/log/qt/ > /mnt/flash/"
            + str(tac)
            + "-qt-logs-"
            + device
            + "_"
            + date
            + ".tar.gz",
            "show agent qtrace | gzip >/mnt/flash/" + str(tac) + "-show-agentqt-" + device + "_" + date + ".log.gz",
            "show logging system | gzip >/mnt/flash/" + str(tac) + "-show-logsys-" + device + "_" + date + ".log.gz",
            "bash sudo tar -cvf - /mnt/flash/debug/* > /mnt/flash/" + str(tac) + "-debug-folder-" + device + "_" + date,
            "bash sudo tar -cvf - /mnt/flash/schedule/tech-support/* > /mnt/flash/"
            + str(tac)
            + "-history-tech-"
            + device
            + "_"
            + date
            + ".tar",
        ]

        for command in commands:
            try:
                print(
                    "\n> Executing command: "
                    + command
                    + "\n\t> Please be patient, some commands will take longer than others to run (between 1 and 5 min, depending on the device)"
                )
                start_time = datetime.now()
                dev_conn.send_command(command, delay_factor=4, read_timeout=600)
                end_time = datetime.now()
                print("\t> Total time: {}".format(end_time - start_time))
                dev_files.append(command.split(">")[1])
            except:
                print(
                    f'\n:: WARNING :: The command "{+command}" failed for the device {device}. Check the command syntax or run it manually on the device. Skipping this command\n'
                )
                continue

    elif dev_type == "Nokia":
        sys.exit(f"WIP - you have to do it manually for now")
        logsCompress = f"/var/tmp/{device}_{date}_{tac}.tgz"
        # compress the logs
        compressCommand = f'bash tar -czf {logsCompress} /var/log/srlinux && echo "[OK]"'
        compressStringCheck = "[OK]"
        compress = run_ssh_command(device, command, compressStringCheck)
        if compress:
            dev_files.append(logsCompress)

        # get the tech support
        tsCommand = "tech-support"
        tsStringCheck = "Tech report generated at:"
        ts = run_ssh_command(device, command, compressStringCheck)
        if ts:

            dev_files.append(logsCompress)

        # for command in commands:
        #     ssh_command = ['ssh', '-o', 'UserKnownHostsFile=/dev/null','-o','StrictHostKeyChecking=no','-T', device, command]
        #     try:
        #         print(f'\n> Executing command: {command}\n\t> Please be patient, some commands will take longer than others to run (between 1 and 5 min, depending on the device)')
        #         start_time = datetime.now()
        #         process = subprocess.Popen(
        #             ssh_command,
        #             stdout=subprocess.PIPE,
        #             stderr=subprocess.PIPE,
        #             universal_newlines=True,
        #         )
        #         output = ""
        #         while True:
        #             line = re.sub(r'\s*\|$|^\|\s*|\s\s+','',process.stdout.readline()).strip('\n')
        #             if not line:
        #                 break
        #             elif len(line) > 1:
        #                 if re.findall(r'Tech report generated at',line,re.I):
        #                     dev_files.append(line.split('at: ')[1])
        #     except:
        #         print (f'\n:: WARNING :: The command "{+command}" failed for the device {device}. Check the command syntax or run it manually on the device. Skipping this command\n')
        #         continue
        #     end_time = datetime.now()
        #     print('\t> Total time: {}'.format(end_time - start_time))

    return dev_files


def run_ssh_command(hostname, command, stringCheck):
    output = False
    ssh_newkey = "Are you sure you want to continue connecting"
    child = pexpect.spawn(f"ssh {hostname}", timeout=25)
    child.sendline(command)
    i = child.expect([ssh_newkey, pexpect.TIMEOUT, pexpect.EOF])
    if i == 0:
        child.sendline("yes")
        child.expect(pexpect.EOF)

    output = child.before.decode("utf-8").splitlines()
    for line in output:
        if line.startswith(stringCheck):
            return True
    child.close()
    return output


def download_files(device, file):
    if os.path.exists(str(Path.home()) + "/tac_files/") is False:
        os.mkdir(str(Path.home()) + "/tac_files/")
    scp_dev = device + ":" + file
    local_file = str(Path.home()) + "/tac_files/" + file.split("/")[-1]
    print("\n> Starting download for :" + file)
    try:
        subprocess.run(["scp", "-o", "StrictHostKeyChecking=no", scp_dev, local_file])
        print("\t> Downloaded file: " + file)
    except:
        print("\t:: WARNING ::\nFailed to download file: " + h)


def upload(tac, file, ftp_pass, ftp_server, ftp_user, dev_type):
    host, port = ftp_server, 22
    transport = paramiko.Transport((host, port))
    transport.connect(None, ftp_user, ftp_pass)
    sftp = paramiko.SFTPClient.from_transport(transport)
    local_file = str(Path.home()) + "/tac_files/" + file
    print("> Starting upload the file:" + local_file + " to the FTP server " + ftp_server)
    if dev_type == "Arista":
        remote_path = "/case_files/" + str(tac)
    elif dev_type == "Juniper":
        remote_path = "/pub/incoming/" + str(tac)
    remote_file = remote_path + "/" + file
    try:
        sftp.chdir(remote_path)
        print("\t> Remote path " + remote_path + " already exist.")
    except:
        print("\t> Couldn't find case " + tac + " folder on SFTP server")
        print("\t\t> Creating folder for the case")
        try:
            sftp.mkdir(remote_path)
            print("\t\t> Created new folder")
        except:
            print("\t\t:: WARNING ::\t\nFailed to create remote folder")
    try:
        sftp.put(local_file, remote_file)
        print("\t> File: " + local_file + " uploaded sucessfully\n")
    except:
        print("\t:: WARNING ::\t\nFailed to upload: " + local_file + " to " + remote_file)
    sftp.close()
    transport.close()


if __name__ == "__main__":

    device, tac, upload_lock = get_args()
    print(banner)

    nb_dev = nb.dcim.devices.filter(name=device)
    for nbdev in nb_dev:
        dev_type = str(nbdev.device_type.manufacturer.name)

    gather_info(device, tac, dev_type, dev_files)
    for file in dev_files:
        i = 0
        max = int(len(file.split("/")) - 1)
        while i <= max:
            if i == max:
                local_files.append(file.split("/")[i])
            i += 1
    print(banner)
    print(f"List of files: {local_files}")
    print(banner)
    # download files
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = []
        for file in dev_files:
            futures.append(pool.submit(download_files, device=device, file=file))

    print("\n> Download of the files to ~/tac_files/ completed.")
    print(banner)
    # upload files to SFTP
    if upload_lock:
        if dev_type == "Juniper":
            for file in local_files:
                upload(tac, file, jnp_ftp_pass, jnp_ftp_server, jnp_ftp_user, dev_type)
        if dev_type == "Arista":
            for file in local_files:
                upload(tac, file, arista_ftp_pass, arista_ftp_server, arista_ftp_user, dev_type)
    else:
        print("\t> The files will NOT be uploaded to the SFTP server, as you used the option '-noupload'")
    print(banner)
