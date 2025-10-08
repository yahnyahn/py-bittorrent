import bencodepy
import hashlib
import json
import requests
import socket
import struct
import sys
import urllib
from typing import Any, Tuple, List, Dict


def encode_bencode(data: Any) -> bytes:
    """Encodes data using bencode."""
    return bencodepy.encode(data)


def decode_bencode(bencoded_value: bytes) -> Any:
    """Decodes bencoded data."""
    return bencodepy.decode(bencoded_value)


def send_message(sock, msg_id, payload=b''):
    """Sends a message to the peer."""
    length_prefix = struct.pack("!I", len(payload) + 1)
    message = length_prefix + struct.pack("!B", msg_id) + payload
    sock.sendall(message)


def receive_message(sock):
    """Receives a message from the peer."""
    length_prefix = sock.recv(4)
    if not length_prefix:
        return None, None
    length = struct.unpack("!I", length_prefix)[0]
    if length > 2**20:  # Limit message length to 1 MiB for safety
        raise ValueError("Message length too large")
    msg_id = struct.unpack("!B", sock.recv(1))[0]
    payload = b''
    if length > 1:
        remaining = length - 1
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                raise ConnectionError("Connection lost while receiving payload")
            payload += chunk
            remaining -= len(chunk)
    return msg_id, payload


def calculate_block_requests(piece_length, piece_index) -> List[Tuple[int, int, int]]:
    """Calculates block requests for a given piece.
    This can be used to determine the total remaining size needed to download
    """
    BLOCK_SIZE = 16 * 1024
    full_blocks = piece_length // BLOCK_SIZE
    last_block_size = piece_length % BLOCK_SIZE

    blocks = []
    for block_index in range(full_blocks):
        block_offset = block_index * BLOCK_SIZE
        blocks.append((piece_index, block_offset, BLOCK_SIZE))

    if last_block_size > 0:
        block_offset = full_blocks * BLOCK_SIZE
        blocks.append((piece_index, block_offset, last_block_size))

    return blocks


def get_tracker_response(torrent_file):
    """Gets the tracker response for a given torrent file."""
    with open(torrent_file, "rb") as f:
        data = f.read()

    parsed_data = decode_bencode(data)
    info = parsed_data[b"info"]
    info_hash = hashlib.sha1(encode_bencode(info)).digest()
    tracker_url = parsed_data[b"announce"].decode()
    file_length = info[b"length"]

    payload = {
        "info_hash": info_hash,
        "peer_id": "01234567890123456789",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": file_length,
        "compact": 1
    }

    response = requests.get(tracker_url, params=payload)
    return decode_bencode(response.content), info, info_hash


def connect_to_peer(peer_data, info_hash):
    """Connects to a peer using the given peer data and info hash."""
    ip_byte = peer_data[:4]
    port_byte = peer_data[4:]
    ip_address = '.'.join(map(str, ip_byte))
    port = struct.unpack("!H", port_byte)[0]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, port))

    protocol = struct.pack("!B19s", 19, b"BitTorrent protocol")
    reserved_bytes = b'\x00' * 8
    peer_id = b"01234567890123456789"
    handshake = protocol + reserved_bytes + info_hash + peer_id
    s.sendall(handshake)

    response = s.recv(68)
    if len(response) < 68:
        raise ConnectionError("Incomplete handshake response")
    print(f"Peer ID: {response[-20:].hex()}")

    return s


def download_piece(torrent_file, piece_index, output_file):
    """Downloads a specific piece from the torrent."""
    response_dict, info, info_hash = get_tracker_response(torrent_file)
    peers = response_dict[b"peers"]
    peer_size = 6

    peer_data = peers[:peer_size]
    s = connect_to_peer(peer_data, info_hash)
    try:
        # Wait for bitfield message
        while True:
            msg_id, payload = receive_message(s)
            if msg_id == 5:
                break

        # Send interested message
        send_message(s, 2)

        # Wait for unchoke message
        while True:
            msg_id, payload = receive_message(s)
            if msg_id == 1:
                break

        # Request blocks
        piece_data = b''
        block_size = 16 * 1024
        piece_length = info[b"piece length"]
        total_length = info[b"length"]
        piece_offset = piece_index * piece_length
        piece_length = min(piece_length, total_length - piece_offset)
        num_blocks = (piece_length + block_size - 1) // block_size

        for block_index in range(num_blocks):
            begin = block_index * block_size
            length = min(block_size, piece_length - begin)
            payload = struct.pack("!III", piece_index, begin, length)
            send_message(s, 6, payload)

        # Receive piece messages
        while len(piece_data) < piece_length:
            msg_id, payload = receive_message(s)
            if msg_id == 7:
                index, begin = struct.unpack("!II", payload[:8])
                block = payload[8:]
                piece_data += block

        # Verify integrity
        piece_hash = info[b"pieces"][piece_index * 20:(piece_index + 1) * 20]
        if hashlib.sha1(piece_data).digest() != piece_hash:
            raise ValueError("Piece hash does not match")

        # Save the piece
        with open(output_file, "wb") as f:
            f.write(piece_data)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()


def bytes_to_str(data):
    """Converts bytes to string recursively."""
    if isinstance(data, bytes):
        return data.decode('utf-8')
    elif isinstance(data, dict):
        return {bytes_to_str(key): bytes_to_str(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [bytes_to_str(element) for element in data]
    else:
        return data


def parse_torrent_file(torrent_file: str):
    """Parses a torrent file and returns the decoded data."""
    with open(torrent_file, "rb") as f:
        data = f.read()
    parsed_data = decode_bencode(data)
    return parsed_data


def download_whole_file(torrent_file: str, output_file: str):
    """Downloads the entire file from the torrent."""
    response_dict, info, info_hash = get_tracker_response(torrent_file)
    peers = response_dict[b"peers"]
    peer_size = 6

    piece_length = info[b"piece length"]
    total_length = info[b"length"]
    num_pieces = (total_length + piece_length - 1) // piece_length

    pieces_data = [None] * num_pieces

    for i in range(0, len(peers), peer_size):
        peer_data = peers[i:i+peer_size]
        try:
            s = connect_to_peer(peer_data, info_hash)
            try:
                # Wait for bitfield message
                while True:
                    msg_id, _ = receive_message(s)
                    if msg_id == 5:
                        break

                # Send interested message
                send_message(s, 2)

                # Wait for unchoke message
                while True:
                    msg_id, _ = receive_message(s)
                    if msg_id == 1:
                        break

                # Download pieces
                for piece_index in range(num_pieces):
                    if pieces_data[piece_index] is not None:
                        continue

                    piece_data = b''
                    piece_offset = piece_index * piece_length
                    piece_length = min(piece_length, total_length - piece_offset)

                    blocks = calculate_block_requests(piece_length, piece_index)

                    for piece_index, begin, length in blocks:
                        payload = struct.pack("!III", piece_index, begin, length)
                        send_message(s, 6, payload)

                    # Receive piece messages
                    while len(piece_data) < piece_length:
                        msg_id, payload = receive_message(s)
                        if msg_id == 7:
                            index, begin = struct.unpack("!II", payload[:8])
                            block = payload[8:]
                            piece_data += block

                    # Verify integrity
                    piece_hash = info[b"pieces"][piece_index * 20:(piece_index + 1) * 20]
                    if hashlib.sha1(piece_data).digest() != piece_hash:
                        raise ValueError("Piece hash does not match")

                    pieces_data[piece_index] = piece_data

            except Exception as e:
                print(f"Error: {e}")
            finally:
                s.close()
        except Exception as e:
            print(f"Failed to connect to peer: {e}")

    # Save the file
    with open(output_file, "wb") as f:
        for piece_data in pieces_data:
            if piece_data is not None:
                f.write(piece_data)
            else:
                raise ValueError("Missing piece data")

def parse_magnet_link(magnet_link: str) -> Dict[str, Any]:
    """Parses a magnet link and returns its components."""
    parsed_url = urllib.parse.urlparse(magnet_link)
    if parsed_url.scheme != 'magnet':
        raise ValueError("Invalid magnet link")

    params = urllib.parse.parse_qs(parsed_url.query)
    return {key: value[0] if len(value) == 1 else value for key, value in params.items()}

def extract_peers(peer_data: str) -> List:
    peers = []
    peer_size = 6

    for i in range(0, len(peer_data), peer_size):
        ip_bytes = peer_data[i:i+4]
        port_bytes = peer_data[i+4:i+6]
        ip = ".".join(map(str, ip_bytes))
        port = struct.unpack("!H", port_bytes)[0]
        peers.append((ip, port))
    return peers

def main():
    """Main function to handle different commands."""
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2]
        decoded_value = decode_bencode(bencoded_value)
        print(json.dumps(bytes_to_str(decoded_value), default=bytes_to_str))

    elif command == "info":
        with open(sys.argv[2], "rb") as file:
            data = file.read()

        parsed_data = decode_bencode(data)
        info = parsed_data[b"info"]
        info_bencoded = encode_bencode(info)
        info_hash = hashlib.sha1(info_bencoded).digest().hex()
        piece_length = info[b"piece length"]
        piece_hashes = info[b"pieces"].hex()

        print("Tracker URL:", parsed_data[b"announce"].decode())
        print("Length:", info.get(b"length", "N/A"))
        print("Info Hash:", info_hash)
        print("Piece Length:", piece_length)
        print("Piece Hashes:", piece_hashes)

    elif command == "peers":
        with open(sys.argv[2], "rb") as file:
            data = file.read()

        parsed_data = decode_bencode(data)
        info = parsed_data[b"info"]
        info_bencoded = encode_bencode(info)
        info_hash = hashlib.sha1(info_bencoded).digest()
        tracker_url = parsed_data[b"announce"].decode()

        # Handle single-file and multi-file torrents
        if b'length' in info:
            file_length = info[b'length']
        elif b'files' in info:
            file_length = sum(file[b'length'] for file in info[b'files'])
        else:
            raise KeyError("The key 'length' or 'files' is missing from the info dictionary")

        payload = {
            "info_hash": info_hash,
            "peer_id": "01234567890123456789",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": file_length,
            "compact": 1
        }

        response = requests.get(tracker_url, params=payload)
        response_dict = decode_bencode(response.content)
        peers = response_dict[b"peers"]
        peer_size = 6

        for i in range(0, len(peers), peer_size):
            peer_data = peers[i:i+peer_size]
            ip_byte = peer_data[:4]
            port_byte = peer_data[4:]

            ip_address = '.'.join(map(str, ip_byte))
            port = struct.unpack("!H", port_byte)[0]

            print(f"{ip_address}:{port}")

    elif command == "handshake":
        file_name = sys.argv[2]
        ip, port = sys.argv[3].split(':')

        with open(file_name, "rb") as f:
            data = f.read()

        info = decode_bencode(data)[b"info"]
        info_hash = hashlib.sha1(encode_bencode(info)).digest()
        protocol = struct.pack("!B19s", 19, b"BitTorrent protocol")
        reserved_bytes = b'\x00' * 8
        peer_id = b"01234567890123456789"

        handshake = protocol + reserved_bytes + info_hash + peer_id

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.sendall(handshake)
        print(f"Peer ID: {s.recv(68)[-20:].hex()}")

    elif command == "download_piece":
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        piece_index = int(sys.argv[5])
        download_piece(torrent_file, piece_index, output_file)

    elif command == "download":
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        download_whole_file(torrent_file, output_file)
        print(f"Downloaded {torrent_file} to {output_file}")
    
    elif command == "magnet_parse":
        magnet_link = sys.argv[2]
        magnet_dict = parse_magnet_link(magnet_link)
        tracker_url = magnet_dict.get("tr")
        info_hash = magnet_dict.get("xt")
        if isinstance(info_hash, list):
            info_hash = info_hash[0]
        info_hash = info_hash.split(":")[2]

        print(f"Tracker URL: {tracker_url}")
        print(f"Info Hash: {info_hash}")

    elif command == "magnet_handshake":
        magnet_link = sys.argv[2]
        magnet_dict = parse_magnet_link(magnet_link)
        tracker_url = magnet_dict.get("tr")
        info_hash = magnet_dict.get("xt")
        if isinstance(info_hash, list):
            info_hash = info_hash[0]
        info_hash = info_hash.split(":")[2]
        info_hash_bytes = bytes.fromhex(info_hash)
        payload = {
            'info_hash': info_hash_bytes,
            'peer_id': "01234567890123456789",
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': 999,
            "compact": 1
        }
        pstrlen = bytes([19])
        pstr = b'BitTorrent protocol'
        reserved = bytearray([0, 0, 0, 0, 0, 16, 0, 0])

        r = requests.get(tracker_url, params=payload)
        response_dict = decode_bencode(r.content)
        peer_data = response_dict[b'peers']
        peers = extract_peers(peer_data)
        ip, port = peers[0]

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))

        handshake_message = pstrlen + pstr + reserved + info_hash_bytes + b"01234567890123456789"
        s.send(handshake_message)
        response = s.recv(68)
        received_peer_id = response[-20:].hex()
        print(f"Peer ID: {received_peer_id}")
        s.close()


    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()