from webexteamssdk import WebexTeamsAPI
from access import access_bot

api = WebexTeamsAPI(access_token=access_bot())
demo_room_id = None


def setup(api):
    # Find all rooms that have 'webexteamssdk Demo' in their title
    all_rooms = api.rooms.list()
    demo_rooms = [room for room in all_rooms if "HelpMate Demo" in room.title]
    print(f"Found {len(demo_rooms)} rooms with 'HelpMate Demo' in the title.")

    for room in all_rooms:
        if room.title == "HelpMate Demo":
            print(f"Found {room.title} ({room.id})")
            demo_room_id = room.id
            break

    if len(demo_rooms) == 0:
        print("Creating a new 'HelpMate Demo' room...")
        demo_room = api.rooms.create("HelpMate Demo")
        # # Add people to the new demo room
        print("Adding people to the 'Helpmate Demo' room...")
        email_addresses = [
            "aumay@cisco.com",
            "joseergo@cisco.com",
            "jantillo@cisco.com",
            "dorduna@cisco.com",
        ]
        for email in email_addresses:
            print(f"Adding {email} to the room...")
            api.memberships.create(demo_room.id, personEmail=email)
        demo_room_id = demo_room.id
    # # Delete all of the demo rooms
    # for room in demo_rooms:
    #     api.rooms.delete(room.id)

    # # Create a new demo room
    # print("Creating new 'Helpmate Demo' room...")
    # demo_room = api.rooms.create("Helpmate Demo")
    # print(demo_room.title, demo_room.id)

    # # Add people to the new demo room
    # print("Adding people to the 'Helpmate Demo' room...")
    # email_addresses = [
    #     "aumay@cisco.com",
    #     "joseergo@cisco.com",
    #     "jantillo@cisco.com",
    #     "dorduna@cisco.com",
    # ]
    # for email in email_addresses:
    #     print(f"Adding {email} to the room...")
    #     api.memberships.create(demo_room.id, personEmail=email)

    # Post a message to the new room, and upload a file
    print("Posting a message to the 'webexteamssdk Demo' room...")
    api.messages.create(
        demo_room_id,
        text=f"Welcome to the 'Helpmate Demo' room.  This is where we will be posting messages and uploading files. Please tag me and upload your CSV file to this room.",
        files=["Logo.png"],
    )


# setup(api)
