import sys
import socket
from pypuf.simulation import XORArbiterPUF
import numpy as np
import hashlib


def hex_string_to_ndarray(hex_string):
    binary_string = bin(int(hex_string, 16))[2:].zfill(256)
    binary_array = np.array(
        [int(bit)*2-1 for bit in binary_string], dtype=np.int8).reshape((32, 8))
    return binary_array


def ndarray_to_hex_string(ndarray):
    # Flatten the ndarray to a 1D array
    flattened_array = ndarray.flatten()

    # Convert -1 to '0' and 1 to '1' in the flattened array
    binary_array = ['1' if x == 1 else '0' for x in flattened_array]

    # Join the binary digits into a single binary string
    binary_string = ''.join(binary_array)

    # Convert the binary string to a hex string
    hex_string = hex(int(binary_string, 2))[2:].upper()

    # Pad the hex string with leading zeros to make it 64 characters (256 bits)
    hex_string = hex_string.zfill(64)

    return hex_string


# def generate_random_hex_string():
#     num_bytes = 32  # 256 bits is equivalent to 32 bytes
#     random_bytes = secrets.token_bytes(num_bytes)
#     random_hex_string = random_bytes.hex().upper()
#     return random_hex_string


def expand_hex_string_to_ndarray(hex_string:str):
    m = hashlib.sha256()
    c = hex_string_to_ndarray(hex_string)
    for _ in range(0, 7):
        m.update(hex_string.encode('utf-8'))
        hex_string = m.hexdigest()
        nd = hex_string_to_ndarray(m.hexdigest())
        c = np.concatenate((c, nd), axis=0)
    return c


puf = XORArbiterPUF(n=8, k=1, seed=1)
def get_puf(c: str):
    c = expand_hex_string_to_ndarray(c)
    r = puf.eval(c)
    return ndarray_to_hex_string(r)


# Simple Test
# hex_str = generate_random_hex_string()
# print("c=", hex_str)
# t0 = time.time()
# c = expand_hex_string_to_ndarray(hex_str)
# t1 = time.time()
# print("time=", (t1-t0) * 1000)


# t0 = time.time()
# r = puf.eval(c)
# t1 = time.time()
# print("time=", (t1-t0) * 1000)

# print("r=", ndarray_to_hex_string(r))


# Create a socket object
server_socket = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM)

# Get hostname
host = socket.gethostname()

port = 12345

# Bind to the port
server_socket.bind((host, port))

# Set Max Connections
server_socket.listen(2)

while True:
    try:
        # Accept Connections
        stream, addr = server_socket.accept()

        print("socket addr: %s" % str(addr))

        buf = stream.recv(64)
        print("buf=", buf.decode('utf-8'))
        c = expand_hex_string_to_ndarray(buf.decode('utf-8'))
        r = puf.eval(c)
        r = ndarray_to_hex_string(r)
        stream.send(r.encode('utf-8'))
        stream.close()
    except (ValueError):
        print(addr, "ValueError")
        stream.close()
        continue
    except KeyboardInterrupt:
        print("finish")
        stream.close()
        server_socket.close()
        sys.exit()

