from access import access
import requests
import re
from netmiko import ConnectHandler
import pandas as pd
import urllib3

urllib3.disable_warnings()

url = "https://id.cisco.com/oauth2/default/v1/token"


def clean(data):
    print("removing duplicates")
    data = data.drop_duplicates(subset="IP address")
    return data


def get_device_information(df):
    df["Reachability"] = None
    df["Configured restconf"] = None
    df["OS type"] = None
    df["Version"] = None
    df["PID"] = None

    version = re.compile(r"Cisco IOS Software.*,.*, Version (.*),")
    pid = re.compile(
        r"[C|c]isco\s+([A-Z]+[/-]?[A-Z0-9]{1,}[-/][A-Z0-9]{1,}).*bytes of memory"
    )

    for index, row in df.iterrows():
        ip_address = row["IP address"]

        device = {
            "device_type": "cisco_ios",
            "ip": ip_address,
            "username": "admin",
            "password": "cisco!123",
            "secret": "cisco!123",
        }

        # For Mac users:
        # ping_reply = os.system(f"ping -c 1 -W 1 {ip_address} > /dev/null 2>&1")
        # For Windows users:
        # print(f"\nTesting reachability for {ip_address}...\n")
        # ping_reply = os.system(f"ping -n 1 -w 1 {ip_address}")
        # First we test reachability

        try:
            connection = ConnectHandler(**device)
            df.at[index, "Reachability"] = "Reachable"
            print(f"Successfuly connected to {ip_address}! Getting PID and Version...")
            output = connection.send_command("show version")
            version_output = version.search(output).group(1)
            pid_output = pid.search(output).group(1)
            if "Cisco IOS-XE" in output:
                print(f"Checking for restconf in {ip_address}")
                df.at[index, "OS type"] = "IOS-XE"
                output = connection.send_command("sh run")
                if "restconf" in output:
                    df.at[index, "Configured restconf"] = "Restconf enabled"
                else:
                    try:
                        connection.send_config_set("restconf")
                        df.at[index, "Configured restconf"] = "Restconf enabled"
                    except Exception as e:
                        print(f"Failed to configure restconf on {ip_address}: {str(e)}")
                        df.at[index, "Configured restconf"] = "No Restconf"
            else:
                df.at[index, "OS type"] = "IOS"
                df.at[index, "Configured restconf"] = "Not supported"
            df.at[index, "Version"] = version_output
            df.at[index, "PID"] = pid_output
            connection.disconnect()
        except Exception as e:
            print(f"Failed to retrieve info from {ip_address}: {str(e)}")
            df.at[index, "Reachability"] = "Unreachable"
            df.at[index, "Configured restconf"] = "Unknown"
            df.at[index, "OS type"] = "Unknown"
            df.at[index, "Version"] = "Unknown"
            df.at[index, "PID"] = "Unknown"
    return df


# function to get bugs from cisco api
def get_bugs(df):
    df["Potential_bugs"] = None
    token = access()
    headers = {
        "Authorization": f"Bearer {token}",
    }

    for index, row in df.iterrows():
        # Read the column that contains the Part ID of the device
        device_id = row["PID"]
        if device_id:
            try:
                url = f"https://apix.cisco.com/bug/v3.0/bugs/products/product_id/{device_id}?page_index=1&modified_date=5"
                response = requests.get(url, headers=headers)

                # Validate the status code as 200
                if response.status_code == 200:
                    # Parse the response in json format
                    response_data = response.json()
                    # Print the response_data so you can see how to filter it to just keep the bug ID
                    # print (response_data)

                    # List comprehension in python: https://realpython.com/list-comprehension-python/
                    bug_id = [bug["bug_id"] for bug in response_data["bugs"]]
                    print(f"Potential bugs for {device_id}: {bug_id}")
                    # Update the bug_id information in the proper column/row
                    df.at[index, "Potential_bugs"] = bug_id
                else:
                    print(f"Request failed with status code {response.status_code}")
                    df.at[index, "Potential_bugs"] = "Wrong API access"
            except Exception as e:
                print(f"Failed to retrieve info from {device_id}: {str(e)}")
    return df


# function to get vulnerabilities from cisco api
def get_vulnerabilities(df):
    df["PSIRT"] = None
    token = access()
    headers = {
        "Authorization": f"Bearer {token}",
    }
    for index, row in df.iterrows():
        # Read the column that contains the Version of the device
        version = row["Version"]
        if version:
            try:
                url = f"https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version={version}"
                response = requests.get(url, headers=headers)

                # Validate the status code as 200
                if response.status_code == 200:
                    # Parse the response in json format
                    response_data = response.json()
                    # Print the response_data so you can see how to filter it to just keep the advisoryId
                    # print (response_data)

                    # List comprehension in python: https://realpython.com/list-comprehension-python/
                    advisory_id = [
                        adv["advisoryId"] for adv in response_data["advisories"]
                    ]
                    # advisory_id = [ adv['advisoryId'] for adv in response_data['advisories'] if adv['cvssBaseScore'] > 7.5 ]
                    print(f"PSIRT for {version}: {advisory_id}")
                    # Update the bug_id information in the proper column/row
                    df.at[index, "PSIRT"] = advisory_id
                else:
                    print(f"Request failed with status code {response.status_code}")
                    df.at[index, "PSIRT"] = "Wrong API access"
            except Exception as e:
                print(f"Failed to retrieve info from {version}: {str(e)}")
    return df
