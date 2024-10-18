## Juniper BGPToolkit
===============================
BGPToolkit is a tool designed to manage BGP sessions, including draining and normalizing traffic. This script helps configure and verify BGP policies on routers.

Prerequisites
—————————-----
```
        •       Python Environment: Python 3.8 installed. 
        •       Install the required dependencies using the following command in your virtual environment: 
                pip install -r requirements.txt
```

Running the Script
—————————---------
I- Launch the Script: 

$ python3 BGPToolkit.py

II- Enter Router Details: When prompted, enter the router's hostname. (Make sure there is no space before and after the hostname otherwise you will get an error.)

III- Enter Peer ASN: Provide the ASN of the peer for which you want to manage BGP sessions.

IV- Choose an Operation: 

1 - Drain traffic: Apply graceful shutdown and drain commands to the BGP sessions.
2 - Normalize traffic: Remove graceful shutdown and drain commands, returning the BGP session to normal operation.

Please refer to the following wiki for more details:

https://equinixjira.atlassian.net/wiki/spaces/OP/pages/146132604581/NETOPS-GUIDE+Manage+BGP+Peering+for+transit+links+Review