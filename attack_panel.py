import os
import time
import tkinter as tk
from tkinter import filedialog
from attacks_class import Attacks
def welcome_sequence():
    print("Welcome to my...")
    print_list = ["       _   _             _                                 _        []           []      ",
                  "      | | | |           | |                               | |         \  _---_  /        ",
                  "  __ _| |_| |_ __ _  ___| | _____   _ __   __ _ _ __   ___| |          \/     \/         ", 
                  " / _` | __| __/ _` |/ __| |/ / __| | '_ \ / _` | '_ \ / _ \ |           |() ()|          ",
                  "| (_| | |_| || (_| | (__|   <\__ \ | |_) | (_| | | | |  __/ |            \ + /           ", 
                  " \__,_|\__|\__\__,_|\___|_|\_\___/ | .__/ \__,_|_| |_|\___|_|           / HHH  \         ",
                  "                                   | |                                 /  \_/   \        ",  
                  "                                   |_|                               []          []      "]
               
    time.sleep(0.1)
    for line in print_list:
        time.sleep(0.1)
        print("\033[31m{}\033[0m".format(line))
    time.sleep(0.2)
    print("Created by: Ron Dahan \n")
    time.sleep(0.5)

def DOS_sequence():
    print_list = ["  _____                      _   _             _        []           []      ",
                  " |  __ \                /\  | | | |           | |         \  _---_  /        ",
                  " | |  | | ___  ___     /  \ | |_| |_ __ _  ___| |          \/     \/         ", 
                  " | |  | |/ _ \/ __|   / /\ \| __| __/ _` |/ __| |/ /        |() ()|          ",
                  " | |__| | (_) \__ \  / ____ \ |_| || (_| | (__|   <          \ + /           ", 
                  " |_____/ \___/|___/ /_/    \_\__|\__\__,_|\___|_|\_\        / HHH  \         ",
                  "                                                           /  \_/   \        ",  
                  "                                                         []          []      "]

    print("\n")     
    time.sleep(0.1)
    for line in print_list:
        time.sleep(0.1)
        print("\033[31m{}\033[0m".format(line))
    time.sleep(0.2)
    print("Created by: Ron Dahan \n")
    time.sleep(0.5)


def U2R_sequence():

    print_list = [
        "| |  | |__ \|  __ \      /\  | | | |           | |        []          []     ",
        "| |  | |  ) | |__) |    /  \ | |_| |_ __ _  ___| | __      \  _---_  /        ",
        "| |  | | / /|  _  /    / /\ \| __| __/ _` |/ __| |/ /       \/     \/         ", 
        "| |__| |/ /_| | \ \   / ____ \ |_| || (_| | (__|   <         |() ()|          ",
        " \____/|____|_|  \_\ /_/    \_\__|\__\__,_|\___|_|\_\         \ + /           ", 
        "                                                             / HHH  \         ",
        "                                                            /  \_/   \        ",  
        "                                                          []          []      "]
    print("\n")
    time.sleep(0.1)
    for line in print_list:
        time.sleep(0.1)
        print("\033[31m{}\033[0m".format(line))
    time.sleep(0.2)
    print("Created by: Ron Dahan \n")
    time.sleep(0.5)

def DosExp():
    while True:
        DOS_sequence()
        print("[1]. Start Dos Attack")
        print("[2]. What is Dos Attack")
        print("[3]. Return")
        command = input("Enter your choice: ")
        os.system('cls' if os.name == 'nt' else 'clear')
        if command == "1":
            commandYorN = input("Will you use the attack solely for its intended purposes, such as testing, research, and study? (Y/n): ")
            if commandYorN == "Y":
                attack_instance = Attacks()
                attack_instance.launch_dos_attack()
            elif commandYorN == "n":
                print("Sorry, I can't help you. :( ")
                time.sleep(2)
            else:
                print("Invalid input")
            os.system('cls' if os.name == 'nt' else 'clear')
        elif command == "2":
            print("A Denial of Service (DoS) attack is a malicious attempt to disrupt the normal functioning of a targeted server, service, or network by overwhelming it with a flood of superfluous requests. This overload prevents legitimate requests from being processed, effectively denying access to legitimate users. Variants include Distributed Denial of Service (DDoS) attacks, where the traffic comes from multiple sources, making mitigation more challenging.")
            commandReturn = input("\n\n\n[1]. Return ")
            if commandReturn == "1":
                os.system('cls' if os.name == 'nt' else 'clear')
                continue
            else:
                print("Invalid input")
            os.system('cls' if os.name == 'nt' else 'clear')
        elif command == "3":
            os.system('cls' if os.name == 'nt' else 'clear')
            return
        else:
            print("Invalid input")

def U2RExp():
    while True:
        U2R_sequence()
        print("[1]. Start U2R Attack")
        print("[2]. What is U2R Attack")
        print("[3]. Return")
        command = input("Enter your choice: ")
        os.system('cls' if os.name == 'nt' else 'clear')

        if command == "1":
            commandYorN = input("Will you use the attack solely for its intended purposes, such as testing, research, and study? (Y/n): ")
            if commandYorN.upper() == "Y":
                attack_instance = Attacks()
                attack_instance.launch_U2R_attack()
            elif commandYorN.upper() == "n":
                print("Sorry, I can't help you. :( ")
                time.sleep(2)
            else:
                print("Invalid input")
            os.system('cls' if os.name == 'nt' else 'clear')

        elif command == "2":
            print("User-to-Root (U2R) attacks have the objective of a non-privileged user acquiring root or admin-user access on a specific computer or a system on which the intruder had user-level access. Remote-to-Local (R2L) attacks involve sending packets to the victim machine.")
            commandReturn = input("\n\n\n[1]. Return ")
            if commandReturn == "1":
                os.system('cls' if os.name == 'nt' else 'clear')
                continue
            else:
                print("Invalid input")
            os.system('cls' if os.name == 'nt' else 'clear')

        elif command == "3":
            os.system('cls' if os.name == 'nt' else 'clear')
            return
        else:
            print("Invalid input")

def main():
    while True:
        welcome_sequence()
        print("[1]. Dos Attack")
        print("[2]. U2R (User to Root attack)")
        print("[3]. Exit")
        command = input("Enter your choice: ")
        os.system('cls' if os.name == 'nt' else 'clear')

        if command == "1":
            DosExp()
        elif command == "2":
            U2RExp()
        elif command == "3":
            print(""" 
                       ____               _                _ 
                      | __ ) _   _  ___  | |__  _   _  ___| |
                      |  _ \| | | |/ _ \ | '_ \| | | |/ _ \ |
                      | |_) | |_| |  __/ | |_) | |_| |  __/_|
                      |____/ \__, |\___| |_.__/ \__, |\___(_)
                             |___/              |___/         
                                                                  """)
            time.sleep(2)
            os.system('cls' if os.name == 'nt' else 'clear')
            break
        else:
            print("Invalid input")

if __name__ == '__main__':
    main()
