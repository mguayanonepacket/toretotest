# Description:

This script will grab information from the target device and upload that information to the manufacturer SFTP server.

The actions to execute are:

* Juniper:

  - Compress /var/log/ folder (if the device has dual RE will also compress backup RE log folder)
  - Generate RSI file
  - Look for core-dump files

* Arista:

  - Execute this commands:
  ```
  show tech-support | gzip > /mnt/flash/436537-show-tech-$HOSTNAME-$(date +%m_%d.%H%M).log.gz
  show agent log | gzip > /mnt/flash/436537-show-agentlog-$HOSTNAME-$(date +%m_%d.%H%M).log.gz
  bash sudo tar -czvf - /var/log/qt/ > /mnt/flash/436537-qt-logs-$HOSTNAME-$(date +%m_%d.%H%M).tar.gz
  show agent qtrace | gzip >/mnt/flash/436537-show-agentqt-$HOSTNAME-$(date +%m_%d.%H%M).log.gz
  show logging system | gzip >/mnt/flash/436537-show-logsys-$HOSTNAME-$(date +%m_%d.%H%M).log.gz
  bash sudo tar -cvf - /mnt/flash/debug/* > /mnt/flash/436537-debug-folder-$HOSTNAME-$(date +%d_%m.%H%M).tar
  bash sudo tar -cvf - /mnt/flash/schedule/tech-support/* > /mnt/flash/436537-history-tech-$HOSTNAME-$(date +%m_%d.%H%M).tar
  ```

* Nokia:
  - Work in progress

* Both device types:

  - Download the files to ~/tac_files/  
  - Upload the files to SFTP server

# Requeriments:

You will need to export the NB_URL and NB_API_KEY variables.
If the target device is an Arista you'll also need to export the "ADMIN_PW" variable.

There is a list of requirements on requirements.txt that you'll need to install like this:

```
pip3 install -r requeriments.txt
```

# Command line options

````
python3 tac_info.py -d  -c  [-noupload]

    -d : Specifies the device hostname or IP address.
    -c : Specifies the TAC case number.
    -noupload: Optional flag to prevent uploading the files to the FTP server.
```

# How to execute:

Simple define the device after "-d" tag and case number after "-c" tag.

# Usage example:

```
python3 jtac_info_v1.py -d bbr1.sv3-lab -c 2022-0603-486529
```
