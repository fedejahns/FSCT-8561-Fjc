import socket
import json
import getpass

import requests


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 150

HTTP_BASE_URL = "http://127.0.0.1:8765"


def send_json(sock_file, payload):
    sock_file.write(
        json.dumps(payload) + "\n"
    )
    sock_file.flush()


def receive_json(sock_file):
    line = sock_file.readline()

    if not line:
        raise ConnectionError(
            "Server disconnected"
        )

    return json.loads(line)


def login(sock_file):
    print()
    print("--- Authentication ---")

    username = input(
        "Username: "
    ).strip()

    password = getpass.getpass(
        "Password: "
    )

    send_json(
        sock_file,
        {
            "command": "AUTH",
            "username": username,
            "password": password
        }
    )

    response = receive_json(
        sock_file
    )

    print(
        "Server:",
        response.get("message")
    )

    if response.get("message") != "OTP_REQUIRED":
        return False

    code = input(
        "6-digit TOTP code: "
    ).strip()

    send_json(
        sock_file,
        {
            "command": "OTP",
            "code": code
        }
    )

    response = receive_json(
        sock_file
    )

    print(
        "Server:",
        response.get("message")
    )

    return response.get("message") == "ACCESS_GRANTED"


def port_scan():
    print()
    print(
        "==Localhost TCP Port Scanner=="
    )

    print(
        "Target restricted to 127.0.0.1"
    )

    try:
        start_port = int(
            input("Start port: ")
        )

        end_port = int(
            input("End port: ")
        )

    except ValueError:
        print(
            "Ports must be numbers."
        )

        return

    if not (
        1 <= start_port <= 65535
        and
        1 <= end_port <= 65535
    ):
        print(
            "The ports must be between 1 and 65535."
        )

        return

    if start_port > end_port:
        print(
            "Start port must be less than or equal to end port."
        )

        return

    if end_port - start_port + 1 > 150:
        print(
            "Scan no more than 150 local ports at once."
        )

        return

    print()

    for port in range(
        start_port,
        end_port + 1
    ):
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as scan_socket:

            scan_socket.settimeout(
                0.25
            )

            result = scan_socket.connect_ex(
                (
                    "127.0.0.1",
                    port
                )
            )

        if result == 0:
            state = "OPEN"
        else:
            state = "CLOSED"

        print(
            f"TCP {port}: {state}"
        )


def http_check():
    print()
    print(
        "--local HTTP security check--"
    )

    print(
        "Target:",
        HTTP_BASE_URL
    )

    paths = [
        "/",
        "/health",
        "/redirect",
        "/missing"
    ]

    try:
        responses = {}

        for path in paths:
            response = requests.get(
                HTTP_BASE_URL + path,
                timeout=5,
                allow_redirects=False
            )

            responses[path] = response

            print(
                f"{path:<10} HTTP {response.status_code}"
            )

        homepage = responses["/"]

        print()
        print("Homepage headers:")

        print(
            "Content-Type:",
            homepage.headers.get(
                "Content-Type"
            )
        )

        print(
            "Server:",
            homepage.headers.get(
                "Server"
            )
        )

        headers_to_check = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options"
        ]

        print()
        print(
            "Configuration findings:"
        )

        for header in headers_to_check:
            if header in homepage.headers:
                print(
                    f"[OK] {header} is present"
                )

            else:
                print(
                    f"[REVIEW] {header} is not present"
                )

        cookie = homepage.headers.get(
            "Set-Cookie"
        )

        if cookie:
            print(
                "[INFO] Set-Cookie header is present"
            )

            lower_cookie = cookie.lower()

            for flag in [
                "httponly",
                "secure",
                "samesite"
            ]:
                if flag not in lower_cookie:
                    print(
                        f"[REVIEW] Cookie does not include {flag}"
                    )

        print()

        print(
            "Findings found do require a manual analysis "
            "and do not prove exploitability."
        )

        print(
            "HSTS is not treated as a flaw because "
            "this supplied service uses a basic HTTP protocol."
        )

    except requests.RequestException as error:
        print(
            "HTTP connection has failed:",
            error
        )


def request_pcap_analysis(sock_file):
    send_json(
        sock_file,
        {
            "command": "PCAP_ANALYZE"
        }
    )

    response = receive_json(
        sock_file
    )

    if not response.get("ok"):
        print(
            "Server:",
            response.get("message")
        )

        return

    summary = response.get(
        "summary",
        {}
    )

    findings = response.get(
        "findings",
        []
    )

    print()
    print(
        "--- PCAP Analysis Results ---"
    )

    print(
        "Total packets:",
        summary.get(
            "total_packets"
        )
    )

    print(
        "TCP packets:",
        summary.get(
            "tcp_packets"
        )
    )

    print(
        "UDP packets:",
        summary.get(
            "udp_packets"
        )
    )

    print()
    print(
        "Suspicious-pattern findings:"
    )

    for finding in findings:
        print(
            "-",
            finding
        )


def invalid_command_test(sock_file):
    send_json(
        sock_file,
        {
            "command": "NOT_A_REAL_COMMAND"
        }
    )

    response = receive_json(
        sock_file
    )

    print(
        "Server:",
        response.get("message")
    )


def print_menu():
    print()
    print(
        "==8561Midterm - Federico=="
    )

    print(
        "1. Login with password and TOTP"
    )

    print(
        "2. Request for the PCAP analysis"
    )

    print(
        "3. Analyze localhost TCP ports"
    )

    print(
        "4. Check the local test_website.py"
    )

    print(
        "5. Send an invalid command (test)"
    )

    print(
        "0. Logout and exit"
    )


def main():
    print(
        f"Connecting to server at "
        f"{SERVER_HOST}:{SERVER_PORT}..."
    )

    try:
        with socket.create_connection(
            (
                SERVER_HOST,
                SERVER_PORT
            ),
            timeout=5
        ) as sock:

            sock.settimeout(None)

            sock_file = sock.makefile(
                "rw",
                encoding="utf-8",
                newline="\n"
            )

            print(
                "Connected."
            )

            while True:
                print_menu()

                choice = input(
                    "Select an option: "
                ).strip()

                try:
                    if choice == "1":
                        login(
                            sock_file
                        )

                    elif choice == "2":
                        request_pcap_analysis(
                            sock_file
                        )

                    elif choice == "3":
                        port_scan()

                    elif choice == "4":
                        http_check()

                    elif choice == "5":
                        invalid_command_test(
                            sock_file
                        )

                    elif choice == "0":
                        send_json(
                            sock_file,
                            {
                                "command": "LOGOUT"
                            }
                        )

                        response = receive_json(
                            sock_file
                        )

                        print(
                            "Server:",
                            response.get(
                                "message"
                            )
                        )

                        break

                    else:
                        print(
                            "Invalid menu selection."
                        )

                except (
                    ConnectionError,
                    OSError,
                    json.JSONDecodeError
                ) as error:

                    print(
                        "Server communication error:",
                        error
                    )

                    break

    except OSError as error:
        print(
            "Could not connect to the server:",
            error
        )


if __name__ == "__main__":
    main()