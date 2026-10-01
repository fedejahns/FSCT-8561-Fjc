import socket
import nmap

target = input("Enter target host: ")

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("Invalid hostname or IP address.")
    exit()

try:
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
except ValueError:
    print("Ports must be numbers.")
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

scanner = nmap.PortScanner()

port_range = f"{start_port}-{end_port}"

try:
    scanner.scan(target_ip, port_range)
except Exception as error:
    print("Nmap scan failed:", error)
    exit()

print()
print("Target:", target_ip)
print()
print("PORT\tSTATE\tSERVICE")

if target_ip in scanner.all_hosts():

    if "tcp" in scanner[target_ip].all_protocols():

        tcp_results = scanner[target_ip]["tcp"]

        for port in sorted(tcp_results):

            state = tcp_results[port].get(
                "state",
                "unknown"
            )

            service = tcp_results[port].get(
                "name",
                "unknown"
            )

            print(
                f"{port}\t{state}\t{service}"
            )

    else:
        print("No TCP results available.")

else:
    print("Target was not returned by Nmap.")

print()
print("Scan complete.")