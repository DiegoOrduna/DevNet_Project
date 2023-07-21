from access import access
import requests
import re
from netmiko import ConnectHandler
import pandas as pd
import urllib3
from requests.auth import HTTPBasicAuth
import json

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
    df["Severity"] = None
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
                    severity = [bug["severity"] for bug in response_data["bugs"]]
                    headline = [bug["headline"] for bug in response_data["bugs"]]

                    # print(f"Potential bugs for {device_id}: {bug_id}")
                    # print(f"Severity level bugs in {device_id}: {severity}")
                    # Update the bug_id information in the proper column/row
                    df.at[index, "Potential_bugs"] = bug_id
                    df.at[index, "Severity"] = severity
                    # df.at[index, "Headline"] = headline
                    for index in range(len(severity)):
                        sev = severity[index]
                        bug = bug_id[index]
                        head = headline[index]
                        device = device_id
                        if sev == "1":
                            print(
                                f"Detected potential catastrophic bug in {device}: {bug}"
                            )
                            print(f"With the description: {head}")
                else:
                    print(f"Request failed with status code {response.status_code}")
                    df.at[index, "Potential_bugs"] = "Wrong API access"
            except Exception as e:
                print(f"Failed to retrieve info from {device_id}: {str(e)}")

            # number = 0
            # for current_digit in severity:
            #     number = current_digit
            #     for current_bug in bug_id:
            #         if number>="2":
            #             bug=current_bug
            #             print(bug)
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
                    advisory_id2 = [
                        adv["advisoryId"]
                        for adv in response_data["advisories"]
                        if adv["cvssBaseScore"] > "8.9"
                    ]
                    Summary = [
                        adv["summary"]
                        for adv in response_data["advisories"]
                        if adv["cvssBaseScore"] > "8.9"
                    ]

                    # Update the bug_id information in the proper column/row
                    for index in range(len(advisory_id2)):
                        ad_id2 = advisory_id2[index]
                        Summ = Summary[index]
                        print(
                            f"PSIRT critical for {version}: {ad_id2}, se muestra resumen a continuacion: {Summ}"
                        )
                    df.at[index, "PSIRT"] = advisory_id
                else:
                    print(f"Request failed with status code {response.status_code}")
                    df.at[index, "PSIRT"] = "Wrong API access"
            except Exception as e:
                print(f"Failed to retrieve info from {version}: {str(e)}")
    return df


def get_memory(df):
    df["Total_proc_mem"] = ""
    df["Used_proc_mem"] = ""
    df["Free_proc_mem"] = ""

    for index, row in df.iterrows():
        ip_address = row["IP address"]

        if row["OS type"] == "IOS-XE" and row["Configured restconf"] == "No Restconf":
            print("Configuring restconf")
            device = {
                "device_type": "cisco_ios",
                "ip": ip_address,
                "username": "admin",
                "password": "cisco!123",
                "secret": "cisco!123",
            }
            try:
                connection = ConnectHandler(**device)
                output = connection.send_config_set("restconf")
                connection.exit_config_mode()
                connection.disconnect()
                df.at[index, "Configured restconf"] = "Restconf enabled"
            except Exception as e:
                print(f"Failed to retrieve info from {ip_address}: {str(e)}")
        elif (
            row["OS type"] == "IOS-XE"
            and row["Configured restconf"] == "Restconf enabled"
        ):
            device = {
                "ip": ip_address,
                "username": "admin",
                "password": "cisco!123",
            }
            headers = {
                "Accept": "application/yang-data+json",
            }

            # Check the memory with restconf
            url_mem = f"https://{ip_address}/restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics"

            response = requests.get(
                url_mem,
                headers=headers,
                verify=False,
                auth=HTTPBasicAuth(device["username"], device["password"]),
            )

            if response.status_code == 200:
                response = response.json()
                # print(response)
                # Check the response live session
                memory_statistics = response[
                    "Cisco-IOS-XE-memory-oper:memory-statistics"
                ]["memory-statistic"]
                for element in memory_statistics:
                    if element["name"] == "Processor":
                        total_memory = element["total-memory"]
                        used_memory = element["used-memory"]
                        free_memory = element["free-memory"]
                        used_percentage_memory = (
                            int(free_memory) / int(total_memory)
                        ) * 100
                        df.at[index, "Total_proc_mem"] = total_memory
                        df.at[index, "Used_proc_mem"] = used_memory
                        df.at[index, "Free_proc_mem"] = free_memory
                        # df.at[index, 'Percentage_free_mem'] = left_percentage_memory
                        if used_percentage_memory >= 90:
                            print(
                                f"El dispositivo excede el 90% de uso de memoria, lo que podria provocar lentitud en el sistema"
                            )
                # print (memory_statistics)
            else:
                print(f"Received response code: {response.status_code}")
    return df
