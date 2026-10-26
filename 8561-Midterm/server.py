import socket
import threading
import hashlib
import hmac
import json
import logging
import os

import pyotp
from scapy.all import rdpcap, IP, TCP, UDP


HOST = "127.0.0.1"
PORT = 150
USERNAME = "federico"

PASSWORD_SALT = b"FSCT8561-Sentinel"

PASSWORD_HASH = (
    "d68ce1d3e5cd364e7e23cd8716ed8ef2"
    "ab0401db4cc203ebc11f8f5c4d371a95"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PCAP_FILE = os.path.join(
    BASE_DIR,
    "FSCT8561_Operation_Sentinel_Traffic.pcap"
)

TOTP_FILE = os.path.join(
    BASE_DIR,
    "totp_secret.txt"
)

LOG_FILE = os.path.join(
    BASE_DIR,
    "security.log"
)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


def hash_password(password):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        PASSWORD_SALT,
        200000
    ).hex()


def verify_password(password):
    return hmac.compare_digest(
        hash_password(password),
        PASSWORD_HASH
    )


def load_totp_secret():
    if os.path.exists(TOTP_FILE):
        with open(TOTP_FILE, "r", encoding="utf-8") as file:
            return file.read().strip()

    secret = pyotp.random_base32()

    with open(TOTP_FILE, "w", encoding="utf-8") as file:
        file.write(secret)

    print()
    print("Running TOTP setup")
    print("Secret:", secret)
    print("Account: federico")
    print("Issuer: FSCT 8561 Midterm Server")
    print("Do not upload TOTP code to Outsiders")
    print()

    return secret


TOTP_SECRET = load_totp_secret()


def send_json(writer, payload):
    writer.write(json.dumps(payload) + "\n")
    writer.flush()


def analyze_pcap():
    try:
        packets = rdpcap(PCAP_FILE)

    except Exception as error:
        return {
            "ok": False,
            "message": f"Could not read PCAP: {error}"
        }

    tcp_count = 0
    udp_count = 0
    syn_ports = {}
    ssh_syn_count = {}

    for packet in packets:
        if TCP in packet:
            tcp_count += 1
        elif UDP in packet:
            udp_count += 1

        if IP in packet and TCP in packet:
            source_ip = packet[IP].src
            destination_port = int(packet[TCP].dport)
            flags = int(packet[TCP].flags)

            if (flags & 0x02) and not (flags & 0x10):
                syn_ports.setdefault(source_ip, set())
                syn_ports[source_ip].add(destination_port)

                if destination_port == 22:
                    ssh_syn_count[source_ip] = (
                        ssh_syn_count.get(source_ip, 0) + 1
                    )

    findings = []

    for source_ip, ports in syn_ports.items():
        if len(ports) >= 10:
            findings.append(
                f"Possible TCP port scan from "
                f"{source_ip}: SYN packets sent "
                f"to {len(ports)} distinct ports"
            )

    for source_ip, count in ssh_syn_count.items():
        if count >= 10:
            findings.append(
                f"Repeated SSH connection attempts "
                f"from {source_ip}: {count} SYN "
                f"packets to TCP/22"
            )

    if not findings:
        findings.append(
            "No configured suspicious pattern was detected"
        )

    return {
        "ok": True,
        "summary": {
            "total_packets": len(packets),
            "tcp_packets": tcp_count,
            "udp_packets": udp_count
        },
        "findings": findings
    }


def handle_client(connection, address):
    logging.info(
        "Client connected from %s",
        address
    )

    print("Client connected:", address)

    authenticated = False
    password_verified = False
    current_user = None

    try:
        reader = connection.makefile(
            "r",
            encoding="utf-8",
            newline="\n"
        )

        writer = connection.makefile(
            "w",
            encoding="utf-8",
            newline="\n"
        )

        while True:
            line = reader.readline(4096)

            if not line:
                break

            if len(line) >= 4096 and not line.endswith("\n"):
                logging.warning(
                    "Oversized request from %s",
                    address
                )

                send_json(
                    writer,
                    {
                        "ok": False,
                        "message": "Request too large"
                    }
                )

                break

            try:
                request = json.loads(line)

            except json.JSONDecodeError:
                logging.warning(
                    "Malformed JSON request from %s",
                    address
                )

                send_json(
                    writer,
                    {
                        "ok": False,
                        "message": "Malformed request"
                    }
                )

                continue

            if not isinstance(request, dict):
                send_json(
                    writer,
                    {
                        "ok": False,
                        "message": "Request must be an object"
                    }
                )

                continue

            command = request.get("command")

            if not isinstance(command, str):
                send_json(
                    writer,
                    {
                        "ok": False,
                        "message": "Missing command"
                    }
                )

                continue

            command = command.upper()

            if command == "AUTH":
                username = request.get(
                    "username",
                    ""
                )

                password = request.get(
                    "password",
                    ""
                )

                if (
                    not isinstance(username, str)
                    or not isinstance(password, str)
                ):
                    send_json(
                        writer,
                        {
                            "ok": False,
                            "message": "Invalid credentials format"
                        }
                    )

                    continue

                if (
                    username == USERNAME
                    and verify_password(password)
                ):
                    current_user = username
                    password_verified = True
                    authenticated = False

                    logging.info(
                        "Password accepted for user %s",
                        username
                    )

                    send_json(
                        writer,
                        {
                            "ok": True,
                            "message": "OTP_REQUIRED"
                        }
                    )

                else:
                    current_user = None
                    password_verified = False
                    authenticated = False

                    logging.warning(
                        "Failed password authentication from %s",
                        address
                    )

                    send_json(
                        writer,
                        {
                            "ok": False,
                            "message": "ACCESS_DENIED"
                        }
                    )

            elif command == "OTP":
                if not password_verified:
                    logging.warning(
                        "OTP attempted before password verification from %s",
                        address
                    )

                    send_json(
                        writer,
                        {
                            "ok": False,
                            "message": "Password authentication required first"
                        }
                    )

                    continue

                code = request.get(
                    "code",
                    ""
                )

                if (
                    not isinstance(code, str)
                    or not code.isdigit()
                    or len(code) != 6
                ):
                    send_json(
                        writer,
                        {
                            "ok": False,
                            "message": "OTP must be a 6-digit code"
                        }
                    )

                    continue

                if pyotp.TOTP(
                    TOTP_SECRET
                ).verify(
                    code,
                    valid_window=1
                ):
                    authenticated = True
                    password_verified = False

                    logging.info(
                        "Successful MFA login for user %s",
                        current_user
                    )

                    send_json(
                        writer,
                        {
                            "ok": True,
                            "message": "ACCESS_GRANTED"
                        }
                    )

                else:
                    password_verified = False

                    logging.warning(
                        "Failed TOTP authentication for user %s",
                        current_user
                    )

                    send_json(
                        writer,
                        {
                            "ok": False,
                            "message": "ACCESS_DENIED"
                        }
                    )

            elif command == "PCAP_ANALYZE":
                if not authenticated:
                    logging.warning(
                        "Unauthorized PCAP_ANALYZE request from %s",
                        address
                    )

                    send_json(
                        writer,
                        {
                            "ok": False,
                            "message": "Authentication required"
                        }
                    )

                    continue

                logging.info(
                    "Authorized PCAP analysis requested by %s",
                    current_user
                )

                result = analyze_pcap()

                send_json(
                    writer,
                    result
                )

            elif command == "LOGOUT":
                logging.info(
                    "Client session ended for %s",
                    current_user or address
                )

                send_json(
                    writer,
                    {
                        "ok": True,
                        "message": "GOODBYE"
                    }
                )

                break

            else:
                logging.warning(
                    "Unknown command '%s' from %s",
                    command,
                    address
                )

                send_json(
                    writer,
                    {
                        "ok": False,
                        "message": "Unknown command"
                    }
                )

    except Exception as error:
        logging.error(
            "Client handling error from %s: %s",
            address,
            error
        )

    finally:
        try:
            connection.close()
        except OSError:
            pass

        print(
            "Client disconnected:",
            address
        )


def main():
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind(
            (HOST, PORT)
        )

        server.listen(5)

        print(
            f"Server listening on {HOST}:{PORT}"
        )

        print(
            "Press Ctrl+C to stop."
        )

        try:
            while True:
                connection, address = server.accept()

                thread = threading.Thread(
                    target=handle_client,
                    args=(
                        connection,
                        address
                    ),
                    daemon=True
                )

                thread.start()

        except KeyboardInterrupt:
            print()
            print("Server stopped.")


if __name__ == "__main__":
    main()