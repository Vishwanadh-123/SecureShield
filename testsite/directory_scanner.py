import requests

url = "http://127.0.0.1:8000"

with open("wordlist.txt") as file:
    words = file.read().splitlines()

print("===== Directory Discovery =====")

for word in words:
    target = url + "/" + word

    try:
        response = requests.get(target, timeout=5)

        if response.status_code in [200, 301, 302, 403]:
            print(f"[+] {target} -> {response.status_code}")

    except requests.RequestException:
        print("Error connecting to server")
