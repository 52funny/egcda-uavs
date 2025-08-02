import socket
import numpy as np
import hashlib
import logging
import asyncio
import threading
from pypuf.simulation import XORArbiterPUF

# PUF parameters: each sub-challenge is 8 bits
n = 8
puf = XORArbiterPUF(n=n, k=1, seed=1)

def hex_string_to_ndarray(hex_string: str) -> np.ndarray:
    """
    Convert a hex string into an ndarray of shape (rows, n),
    where rows = (len(hex_string)*4) // n, and values are in {-1, +1}.
    """
    # Total bits is hex length * 4
    bit_len = len(hex_string) * 4      # 12 bytes → 96 bits
    # Binary string padded to bit_len
    binary_string = bin(int(hex_string, 16))[2:].zfill(bit_len)
    # Map '0'→-1, '1'→+1
    arr = np.array([int(b)*2 - 1 for b in binary_string], dtype=np.int8)
    rows = bit_len // n                # 96/8 = 12 rows
    return arr.reshape((rows, n))

def ndarray_to_hex_string(ndarray: np.ndarray) -> str:
    """
    Flatten a {-1,+1} ndarray into a binary string, then to hex.
    Returns uppercase hex, zero-padded to the correct length.
    """
    flat = ndarray.flatten()
    # +1→'1', -1→'0'
    binary_string = ''.join('1' if x == 1 else '0' for x in flat)
    # Hex length = bits // 4
    hex_len = len(binary_string) // 4  # 96 bits → 24 hex chars
    hexstr = hex(int(binary_string, 2))[2:].upper().zfill(hex_len)
    return hexstr

def expand_hex_string_to_ndarray(hex_string: str) -> np.ndarray:
    """
    Expand the initial 12-byte challenge into 96 total sub-challenges:
    start with shape (12,8), then hash 7 times to append 7×(12,8),
    yielding a final (96,8) matrix.
    """
    # First block
    c = hex_string_to_ndarray(hex_string)  # shape (12,8)
    m = hashlib.sha256()
    for _ in range(7):
        m.update(hex_string.encode('utf-8'))
        hex_string = m.hexdigest()
        nd = hex_string_to_ndarray(hex_string)  # also (12,8)
        c = np.concatenate((c, nd), axis=0)
    return c  # final shape (96,8)

def get_puf(hex_challenge: str) -> str:
    """
    Compute the PUF response for a given 12-byte hex challenge.
    Returns a 12-byte hex response.
    """
    c = expand_hex_string_to_ndarray(hex_challenge)  # (96,8)
    r = puf.eval(c)                                   # 96-bit response
    return ndarray_to_hex_string(r)[:24]                   # 24 hex chars

# --- TCP server: listen on port 12345 ---
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# def handle_client(conn, addr):
#     with conn:
#         conn.settimeout(10)
#         while True:
#             try:
#                 buf = recv_exact(conn, 24)
#                 if buf is None:
#                     logging.warning("Client %s closed before sending the full challenge", addr)
#                     return
#                 hex_in = buf.decode("utf-8", errors="strict").strip()
#                 logging.info("Received from %s: %r", addr, hex_in)

#                 if len(hex_in) != 24:
#                     logging.warning("Invalid length from %s: %d (expected 24)", addr, len(hex_in))
#                     return
#                 try:
#                     int(hex_in, 16)
#                 except ValueError:
#                     logging.warning("Invalid hex from %s: %r", addr, hex_in)
#                     return

#                 hex_out = get_puf(hex_in)
#                 conn.sendall(hex_out.encode("utf-8"))
#                 logging.info("Replied to %s: %s", addr, hex_out)
#             except socket.timeout:
#                 logging.warning("Timeout handling client %s", addr)
#             except (ConnectionResetError, BrokenPipeError) as e:
#                 logging.warning("Connection error with %s: %s", addr, e)
#             except Exception:
#                 logging.exception("Unexpected error with client %s", addr)


def handle_client(conn, addr):
    with conn:
        # consider removing or increasing this if you want long-idle connections
        conn.settimeout(10)
        try:
            while True:
                # read exactly 24 hex chars challenge
                buf = recv_exact(conn, 24)
                if buf is None:
                    logging.info("Client %s closed the connection", addr)
                    return

                hex_in = buf.decode("utf-8", errors="strict").strip()
                logging.info("Received from %s: %r", addr, hex_in)

                if len(hex_in) != 24:
                    logging.warning("Invalid length from %s: %d (expected 24)", addr, len(hex_in))
                    return
                try:
                    int(hex_in, 16)
                except ValueError:
                    logging.warning("Invalid hex from %s: %r", addr, hex_in)
                    return

                hex_out = get_puf(hex_in)
                conn.sendall(hex_out.encode("utf-8"))
                logging.info("Replied to %s: %s", addr, hex_out)
        except socket.timeout:
            logging.warning("Timeout handling client %s", addr)
        except (ConnectionResetError, BrokenPipeError) as e:
            logging.warning("Connection error with %s: %s", addr, e)
        except Exception:
            logging.exception("Unexpected error with client %s", addr)


def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(0xff)
    logging.info("Server listening on 0.0.0.0:12345")

    try:
        while True:
            conn, addr = server_socket.accept()
            logging.info("Accepted connection from %s", addr)
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        logging.info("Shutting down server")
    finally:
        print("Closing server socket")
        server_socket.close()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if __name__ == "__main__":
    run_server()
