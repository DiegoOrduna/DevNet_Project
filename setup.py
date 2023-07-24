def setup(api):
    # Find all rooms that have 'webexteamssdk Demo' in their title
    all_rooms = api.rooms.list()
    print(f"All rooms: ")
    for room in all_rooms:
        print(f"{room.title} ({room.id})")

    demo_rooms = [room for room in all_rooms if "Helpmate Demo" in room.title]

    # Delete all of the demo rooms
    for room in demo_rooms:
        api.rooms.delete(room.id)

    # Create a new demo room
    print("Creating new 'Helpmate Demo' room...")
    demo_room = api.rooms.create("Helpmate Demo")
    print(demo_room.title, demo_room.id)

    # Add people to the new demo room
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

    # Post a message to the new room, and upload a file
    print("Posting a message to the 'webexteamssdk Demo' room...")
    api.messages.create(
        demo_room.id,
        text=f"Welcome to the 'Helpmate Demo' room.  This is where we will be posting messages and uploading files.",
    )
