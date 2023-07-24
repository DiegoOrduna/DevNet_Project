import pandas as pd

from utils import (
    clean,
    get_device_information,
    get_bugs,
    get_vulnerabilities,
    get_memory,
)


def process(df, teams_api, room_id):
    print("Cleaning data...")
    df = clean(df)
    print("Getting device information...")
    df = get_device_information(df)
    print("Getting bug information...")
    df = get_bugs(df, teams_api, room_id)
    print("Getting vulns information...")
    df = get_vulnerabilities(df, teams_api, room_id)
    print("Getting memory information...")
    df = get_memory(df, teams_api, room_id)
    print(df)
    print("Saving data to csv file...")
    df.to_csv("interns_challenge_final.csv", index=False)
    print("Done!")
    return df


# process(pd.read_csv("interns_challenge_new.csv"))
