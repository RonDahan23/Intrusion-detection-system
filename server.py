from flask import Flask
from scapy.all import *
import time

app = Flask(__name__)

# Dictionary to map protocol numbers to names
protocol_names = {
    6: '0', #TCP
    17: '1', # UDP
    1: '2' #ICMP
}

# Dictionary to map port numbers to service names
service_names = {
    20: 'ftp_data',
    21: 'ftp_control',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
}

# Function to count the number of shell accesses
def count_shell_accesses(packet):
    try:
        num_shells = 0  # Initialize the counter for shell accesses

        # Assuming shell access is determined based on the destination port
        if IP in packet and TCP in packet and packet[TCP].dport == 22:  # Assuming port 22 (SSH) is used for shell access
            num_shells += 1

        return num_shells
    except Exception as e:
        print(f"Error counting shell accesses: {e}")
        return 0  # Return 0 if there's an error

# Function to count file creation operations in the packet payload
def packet_indicates_file_creation(packet):
    try:
        file_creation_count = 0  # Initialize file creation count
        
        # Check if payload exists
        if Raw in packet:
            # Extract payload from the packet
            payload = packet[Raw].load

            # Decode payload if it's a bytes-like object
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8')

                # Define patterns or conditions indicating file creation
                file_creation_patterns = ["create file", "new file created", "file creation"]

                # Count occurrences of file creation patterns in the payload
                for pattern in file_creation_patterns:
                    file_creation_count += payload.count(pattern)

        return file_creation_count
    except Exception as e:
        print(f"Error processing packet for file creation: {e}")
        return 0  # Return 0 if there's an error


# Function to count the number of accesses to the root
def count_root_accesses(packet):
    try:
        num_root = 0  # Initialize the counter for root accesses

        # Assuming the root access is determined based on the destination port
        if IP in packet and TCP in packet and packet[TCP].dport == 22:  # Assuming port 22 (SSH) is used for root access
            num_root += 1

        return num_root
    except Exception as e:
        print(f"Error counting root accesses: {e}")
        return 0  # Return 0 if there's an error

# Define the pattern or condition for detecting hot hints
def detect_hot_hint(packet):
    # Check if TCP layer exists and if the custom option 'hot_hint_flag' is set
    if TCP in packet and packet[TCP].options and ('hot_hint_flag', None) in packet[TCP].options:
        return True
    else:
        return False

# Function to count failed login attempts and check for "su" attempts
def count_failed_logins(packet):
    try:
        su_attempted = 0  # Initialize su_attempted variable
        # Check if payload exists
        if Raw in packet:
            # Extract payload from the packet
            payload = packet[Raw].load

            # Decode payload if it's a bytes-like object
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8')

                # Define the patterns or conditions for detecting failed and successful login attempts
                failed_login_pattern = "Failed login attempt"
                successful_login_pattern = "logged in"
                su_attempt_pattern = "su:"

                # Count the occurrences of the failed login pattern in the payload
                num_failed_logins = payload.count(failed_login_pattern)
                
                # Check for successful login
                successful_login = 1 if successful_login_pattern in payload else 0
                
                # Check for "su" attempt
                su_attempted = 1 if su_attempt_pattern in payload else 0
                
                return num_failed_logins, successful_login, su_attempted
            else:
                return 0, 0, 0  # Return 0 if payload is not a bytes-like object
        else:
            return 0, 0, 0  # Return 0 if payload does not exist
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 0, 0, 0  # Return 0 if there's an error in processing the packet

# Function to count the number of file access operations
def count_file_accesses(packet):
    try:
        num_access_files = 0  # Initialize the counter for file access operations

        # Assuming file access is determined based on the destination port
        if IP in packet and TCP in packet and packet[TCP].dport == 21:  # Assuming port 21 (FTP) is used for file access
            num_access_files += 1

        return num_access_files
    except Exception as e:
        print(f"Error counting file access operations: {e}")
        return 0  # Return 0 if there's an error


@app.route('/', methods=['GET'])
def get_packet_info():
    try:
        # Capture the time when the packet was received
        received_time = time.time()

        # Create scapy packet
        tcp_layer = TCP(flags="SF", sport=80, dport=80)
        tcp_layer.land = 0  # Assuming land is 0

        pack = Ether()/IP(flags="MF")/tcp_layer/DNS()  # Set MF flag in IP header

        # Calculate the duration
        duration = int(time.time() - received_time)

        # Initialize other variables to store extracted information
        protocol_type = None
        service = None
        flags = None
        src_bytes = None
        dst_bytes = None
        land = None
        wrong_fragment = None
        urgent_flag = None
        hot_hint_count = 0
        num_failed_logins = 0
        Logged_In = None
        root_shell = 0  # Initialize root_shell variable
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_access_files = 0

        # Extract information from the packet
        if IP in pack:
            protocol_number = pack[IP].proto
            protocol_type = protocol_names.get(protocol_number, 'Unknown')
            # Check for wrong fragments
            if pack[IP].flags & 0x01 and pack[IP].flags & 0x02:  # Check if both DF and MF flags are set
                wrong_fragment = 1
            else:
                wrong_fragment = 0
            
            # Check if source port equals destination port
            land = 1 if pack[TCP].sport == pack[TCP].dport else 0
            
            # Extract service name based on destination port
            service_port = pack[TCP].dport
            service = service_names.get(service_port, 'other')
            
            # Extract individual TCP flags
            flags = ""
            if pack[TCP].flags & 0x02:
                flags += "S"  # SYN flag
            if pack[TCP].flags & 0x04:
                flags += "F"  # FIN flag
            if pack[TCP].flags & 0x01:
                flags += "F"  # FIN flag
            if pack[TCP].flags & 0x08:
                flags += "P"  # PSH flag
            if pack[TCP].flags & 0x10:
                flags += "R"  # RST flag
            if pack[TCP].flags & 0x20:
                flags += "A"  # ACK flag
            if pack[TCP].flags & 0x40:
                flags += "U"  # URG flag
            
            # Check for urgent flag
            urgent_flag = 1 if pack[TCP].flags & 0x20 else 0

            # Check for hot hints
            if detect_hot_hint(pack):
                hot_hint_count += 1
            
            # Count failed login attempts and check for "su" attempts
            num_failed_logins, Logged_In, su_attempted = count_failed_logins(pack)
            src_bytes = len(pack[TCP].payload)
            dst_bytes = len(pack[IP].payload)
            num_root = count_root_accesses(pack)

            # Assuming system toolbox is opened through port 22 (SSH)
            if pack[TCP].dport == 22:
                root_shell = 1

            # Increment num_file_creations if packet indicates file creation operation
            if packet_indicates_file_creation(pack):
                num_file_creations += 1
            
            # Count the number of file access operations
            num_access_files = count_file_accesses(pack)

            num_shells = count_shell_accesses(pack)

        # Construct the response string
        response = f"\nDuration: {duration}\nProtocol Type: {protocol_type}\nService: {service}\nFlags: {flags}\nSource Bytes: {src_bytes}\nDestination Bytes: {dst_bytes}\nLand: {land}\nWrong Fragment: {wrong_fragment}\nUrgent Flag: {urgent_flag}\nHot Hint Count: {hot_hint_count}\nNum Failed Logins: {num_failed_logins}\nLogged in: {Logged_In}\nRoot Shell: {root_shell}\nsu_attempted: {su_attempted}\nNum Root: {num_root}\nnum_file_creations: {num_file_creations}\nnum_shells: {num_shells}\nNum Access Files: {num_access_files}\n"
        # Print the extracted information to the command prompt
        print(response)

        # Return an empty response since we are printing to cmd directly
        return ''
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 'Error processing packet'  # Return error message if there's an exception
    
if __name__ == '__main__':
    # Change the host parameter to the desired IP address
    app.run(host='172.31.37.161', port=5000, debug=True)