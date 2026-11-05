import nmap

scanner = nmap.PortScanner()

target = "127.0.0.1"
ports = "21,22,25,80,443"

scanner.scan(target, ports)

print("===== Port Scan =====")

for port in [21, 22, 25, 80, 443]:
    state = scanner[target]["tcp"][port]["state"]
    print(port, ":", state)
