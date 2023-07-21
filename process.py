import pandas as pd

from utils import (
    clean,
    get_device_information,
    get_bugs,
    get_vulnerabilities,
    get_memory,
)

if __name__ == "__main__":
    print("Reading data from csv file...")
    df = pd.read_csv("interns_challenge.csv")
    print("Cleaning data...")
    df = clean(df)
    print("Getting device information...")
    df = get_device_information(df)
    print("Getting bug information...")
    df = get_bugs(df)
    print("Getting vulns information...")
    df = get_vulnerabilities(df)
    print("Getting memory information...")
    df = get_memory(df)
    print(df)
    print("Saving data to csv file...")
    df.to_csv("interns_challenge_final.csv", index=False)
    print("Done!")
