# this program is a bot that recieves and processes CSV files and sends them to a Webex Teams space

import io
from flask import Flask, request
from utils import create_webhook
from setup import setup
from access import access_bot
from process import process
from utils import send_message
from webexteamssdk import WebexTeamsAPI, Webhook
import pprint
import requests
import pandas as pd


WEBEX_TEAMS_ACCESS_TOKEN = access_bot()

teams_api = WebexTeamsAPI(access_token=WEBEX_TEAMS_ACCESS_TOKEN)
app = Flask(__name__)


@app.route("/messages_webhook", methods=["POST"])
def messages_webhook():
    if request.method == "POST":
        json_data = request.json
        pprint.pprint(json_data)
        room_id = json_data["data"]["roomId"]
        # check if json data has a file attached
        try:
            if (
                "files" in json_data["data"]
                and json_data["data"]["personEmail"] != "HelpMate@webex.bot"
            ):
                # We get the csv file from the message
                file = teams_api.messages.get(json_data["data"]["id"]).files[0]

                # get the file from the message using the file url and as auth header we use the access token as bearer token
                file_request = requests.get(
                    file,
                    headers={"Authorization": "Bearer " + WEBEX_TEAMS_ACCESS_TOKEN},
                )

                # get the file contents
                file_data = file_request.content.decode("utf-8")
                df = pd.read_csv(io.StringIO(file_data), sep=",")

                # process the file
                send_message(teams_api, room_id, "Analyzing CSV file, please wait...")
                df = process(df, teams_api, room_id)

                # send the processed file to the room
                teams_api.messages.create(
                    roomId=room_id,
                    text="Here is the processed CSV file",
                    files=["interns_challenge_final.csv"],
                )

                return "OK"
            else:
                if json_data["data"]["personEmail"] != "HelpMate@webex.bot":
                    # send a message to the room with the file url
                    send_message(
                        teams_api,
                        room_id,
                        "Please send a CSV file",
                    )
                return "OK"
        except:
            send_message(
                teams_api,
                room_id,
                "Please send a CSV file",
            )
            return "OK"
    return "OK"


if __name__ == "__main__":
    setup(teams_api)
    teams_api = WebexTeamsAPI(access_token=WEBEX_TEAMS_ACCESS_TOKEN)
    create_webhook(teams_api, "messages_webhook", "/messages_webhook", "messages")
    app.run(host="0.0.0.0", port=5000)
