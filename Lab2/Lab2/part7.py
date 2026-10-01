import socket

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


open_ports = []

for port in range(start_port, end_port + 1):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.5)

    result = sock.connect_ex(
        (target_ip, port)
    )

    sock.close()

    if result == 0:

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