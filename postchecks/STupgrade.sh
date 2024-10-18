#!/bin/bash
#
# STI PRO PDU Firmware Update Script
# Copyright 2018 Server Technology
# All rights reserved
#
# Description: Updates one PRO PDU from a local firmware file, as set below
# Requirements: Curl, Perl
# Usage: bash sti-pro-fw-update_script.sh
# Version: 0.6

# A username and password for the STI device with administrator privileges
USERNAME=admn
PASSWORD=$SECRET

# IP of the device
IP_ADDRESS=$DEVICE

# Protocol to be used: http/https
PROTOCOL=https

# Path and name of the update file
UPDATE_FILE=$FILE

# Path to the logfile
LOG_FILE=/dev/stdout

if [ -f $UPDATE_FILE ]; then
	echo `date` "$UPDATE_FILE found" >> $LOG_FILE
else
	echo `date` "ERROR: failed to find $UPDATE_FILE" >> $LOG_FILE
	exit
fi

UPDATE_MJR=`xxd -p -l1 -s 0x48 $UPDATE_FILE`
if [[ $UPDATE_MJR != 08 ]]; then
	echo `date` "ERROR: invalid PRO PDU application firmware file" >> $LOG_FILE
	exit
fi
UPDATE_MJR=`echo $UPDATE_MJR | perl -n -e'/0*([0-9]*)/ && print$1'`
UPDATE_MNR=`xxd -p -l1 -s 0x49 $UPDATE_FILE`
if [[ $UPDATE_MNR == 00 ]]; then
	UPDATE_MNR=0
else
	UPDATE_MNR=`echo $UPDATE_MNR | perl -n -e'/0*([0-9]*)/ && print$1'`
fi
UPDATE_REV=`xxd -p -l1 -s 0x4A $UPDATE_FILE`
UPDATE_REV=$((0x$UPDATE_REV+0x61))
UPDATE_REV=`printf "\x$(printf %x $UPDATE_REV)"`

echo `date` "Starting firmware update for $IP_ADDRESS" >> $LOG_FILE
RESPONSE=`curl -s --connect-timeout 20 --max-time 30 -k --tlsv1.2 -u "$USERNAME:$PASSWORD" -i "$PROTOCOL://$IP_ADDRESS/system.html" 2>&1`
if [[ $RESPONSE == *"<tr class=\"tspc\"><td></td></tr>"* ]]; then
	TLS=tlsv1.2
	CURRENT_MJR=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*([0-9])[^<]*</ && print$1'`
	CURRENT_MNR=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*[0-9].([0-9])[^<]*</ && print$1'`
	CURRENT_REV=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*[0-9].[0-9]([a-zA-Z])[^<]*</ && print$1'`
	echo `date` "Logged into $IP_ADDRESS successfully" >> $LOG_FILE
	echo `date` "Current firmware for $IP_ADDRESS detected as v$CURRENT_MJR.$CURRENT_MNR$CURRENT_REV" >> $LOG_FILE
else
	RESPONSE=`curl -s --connect-timeout 20 --max-time 30 -k --tlsv1.0 -u "$USERNAME:$PASSWORD" -i "$PROTOCOL://$IP_ADDRESS/system.html" 2>&1`
	if [[ $RESPONSE == *"<tr class=\"tspc\"><td></td></tr>"* ]]; then
		TLS=tlsv1.0
		CURRENT_MJR=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*([0-9])[^<]*</ && print$1'`
		CURRENT_MNR=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*[0-9].([0-9])[^<]*</ && print$1'`
		CURRENT_REV=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*[0-9].[0-9]([a-zA-Z])[^<]*</ && print$1'`
		echo `date` "Logged into $IP_ADDRESS successfully" >> $LOG_FILE
		echo `date` "Current firmware for $IP_ADDRESS detected as v$CURRENT_MJR.$CURRENT_MNR$CURRENT_REV" >> $LOG_FILE
	else
		echo `date` "ERROR: failed to login to $IP_ADDRESS" >> $LOG_FILE
		exit
	fi
fi

if [[ $CURRENT_MJR == $UPDATE_MJR && $CURRENT_MNR == $UPDATE_MNR && $CURRENT_REV == $UPDATE_REV ]]; then
	echo `date` "The device at $IP_ADDRESS is at the target firmware version -- no update required"
	exit
fi

echo `date` "Uploading $UPDATE_FILE to $IP_ADDRESS" >> $LOG_FILE
RESPONSE=`curl -s --connect-timeout 20 --max-time 60 -k --$TLS -u "$USERNAME:$PASSWORD" -i -H "Expect:" -F "FileName=@$UPDATE_FILE" "$PROTOCOL://$IP_ADDRESS/Forms/files_1" 2>&1`
echo `date` "Upload of $UPDATE_FILE to $IP_ADDRESS finished" >> $LOG_FILE
echo `date` "Updating and rebooting the device at $IP_ADDRESS" >> $LOG_FILE
RESPONSE=`curl -s --connect-timeout 20 --max-time 30 -k --$TLS -u "$USERNAME:$PASSWORD" -i -d "FormButton=Apply" -d "RST=00000001" "$PROTOCOL://$IP_ADDRESS/Forms/restart_1"`
RESPONSE=`curl -s --connect-timeout 20 --max-time 30 -k --$TLS -u "$USERNAME:$PASSWORD" -i "$PROTOCOL://$IP_ADDRESS/restarting.html"`
RESPONSE=`curl -s --connect-timeout 20 --max-time 30 -k --$TLS -u "$USERNAME:$PASSWORD" -i "$PROTOCOL://$IP_ADDRESS/restarting.html"`

# begin wait for restart to begin
WAIT_INDEX=0
WAIT_END=20
while true; do
	RESPONSE=`curl -s --connect-timeout 20 --max-time 30 -k --$TLS -u "$USERNAME:$PASSWORD" -i "$PROTOCOL://$IP_ADDRESS/system.html" 2>&1`
	if [[ $RESPONSE != *"<tr class=\"tspc\"><td></td></tr>"* ]]; then
		break
	fi
	if (( WAIT_INDEX++ > WAIT_END )); then
		echo `date` "ERROR: The device at $IP_ADDRESS did not restart" >> $LOG_FILE
		exit
	fi
	sleep 10
done

# restart has begun; now wait for the unit to come back online
if [[ $UPDATE_REV > 'f' ]]; then 
	TLS=tlsv1.2
else
	TLS=tlsv1.0
fi
WAIT_INDEX=0
while [[ "$(curl -s --connect-timeout 20 --max-time 30 -k --$TLS -u "$USERNAME:$PASSWORD" -o /dev/null -w ''%{http_code}'' $PROTOCOL://$IP_ADDRESS/system.html)" != "200" ]];
do
	if (( WAIT_INDEX++ > WAIT_END )); then
		echo `date` "ERROR: The device at $IP_ADDRESS did not restart" >> $LOG_FILE
		exit
	fi
	sleep 10
done
RESPONSE=`curl -s --connect-timeout 20 --max-time 30 -k --$TLS -u "$USERNAME:$PASSWORD" -i "$PROTOCOL://$IP_ADDRESS/system.html" 2>&1`
if [[ $RESPONSE == *"<tr class=\"tspc\"><td></td></tr>"* ]]; then
	NEW_MJR=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*([0-9])[^<]*</ && print$1'`
	NEW_MNR=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*[0-9].([0-9])[^<]*</ && print$1'`
	NEW_REV=`echo $RESPONSE | perl -n -e'/<td><b>Firmware:<\/b><\/td><td>[^0-9]*[0-9].[0-9]([a-zA-Z])[^<]*</ && print$1'`
	echo `date` "Reboot of the device at $IP_ADDRESS is finished" >> $LOG_FILE
	echo `date` "The PRO PDU at $IP_ADDRESS went from v$CURRENT_MJR.$CURRENT_MNR$CURRENT_REV to v$NEW_MJR.$NEW_MNR$NEW_REV" >> $LOG_FILE
	if [[ $NEW_MJR == $UPDATE_MJR && $NEW_MNR == $UPDATE_MNR && $NEW_REV == $UPDATE_REV ]]; then
		echo `date` "The update of the device at $IP_ADDRESS was successful" >> $LOG_FILE
	else
		echo `date` "The update of the device at $IP_ADDRESS was unsuccessful" >> $LOG_FILE
	fi
	exit	
fi
echo `date` "ERROR: The device at $IP_ADDRESS did not update correctly" >> $LOG_FILE
