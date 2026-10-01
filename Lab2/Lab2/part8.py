import socket


def scan_port(target, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.5)

    result = sock.connect_ex(
        (target, port)
    )

    sock.close()

    return result == 0


target = input("Enter target host: ")

try:
    target_ip = socket.gethostbyname(target)
    print("Scanning:", target_ip)

except socket.gaierror:
    print("Invalid hostname or IP address")
    exit()


try:
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

except ValueError:
    print("Ports must be numbers")
    exit()


if start_port < 1 or start_port > 65535:
    print("Start port must be between 1 and 65535.")
    exit()

if end_port < 1 or end_port > 65535:
    print("End port must be between 1 and 65535.")
    exit()

if start_port > end_port:
    print("Start port cannot be greater than end port.")
    exit()

if end_port - start_port > 1000:
    print("Port range is too large. Maximum range is 1000 ports.")
    exit()


open_ports = []

for port in range(start_port, end_port + 1):

    if scan_port(target_ip, port):

        try:
            service = socket.getservbyport(
                port,
                "tcp"
            )

        except OSError:
            service = "unknown"

        print(
            "Port",
            port,
            "is OPEN - Likely service:",
            service
        )

        open_ports.append(port)


if open_ports:
    print("Open ports:", open_ports)

else:
    print("No open ports found in the selected range.")