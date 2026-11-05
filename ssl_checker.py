uimport ssl
import socket
from datetime import datetime

hostname = "example.com"

context = ssl.create_default_context()

try:
    with socket.create_connection((hostname, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:

            certificate = secure_sock.getpeercert()

            expiry = certificate["notAfter"]
            expiry_date = datetime.strptime(
                expiry,
                "%b %d %H:%M:%S %Y %Z"
            )

            current_date = datetime.now()

            print("\n===== SSL/TLS Check =====")
            print("Hostname:", hostname)
            print("Certificate Expiry:", expiry_date)

            if expiry_date < current_date:
                print("Status: EXPIRED")
            else:
                print("Status: VALID")

except Exception as e:
    print("SSL/TLS Error:", e)
