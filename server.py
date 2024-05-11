from flask import Flask
from scapy.all import *
import time
from collections import defaultdict

app = Flask(__name__)


# Dictionary to map protocol numbers to names
protocol_dictionary_number = {
    6: '0', #TCP
    17: '1', # UDP
    1: '2' #ICMP
}

protocol_dictionary_name = {
    6: 'TCP', 
    17: 'UDP', 
    1: 'ICMP' 
}

# Define a dictionary to store the timestamps of connections to each destination host
connection_timestamps = defaultdict(list)
service_timestamps = defaultdict(list)

# Function to count the number of shell accesses
def count_shell_accesses(packet, protocol_name):  # Pass protocol_name as an argument
    try:
        num_shells = 0  # Initialize the counter for shell accesses

        # Assuming shell access is determined based on the destination port
        if IP in packet and protocol_name in packet and packet[protocol_name].dport == 22:  # Assuming port 22 (SSH) is used for shell access
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
def count_root_accesses(packet, protocol_name):  # Pass protocol_name as an argument
    try:
        num_root = 0  # Initialize the counter for root accesses

        # Assuming the root access is determined based on the destination port
        if IP in packet and protocol_name in packet and packet[protocol_name].dport == 22:  # Assuming port 22 (SSH) is used for root access
            num_root += 1

        return num_root
    except Exception as e:
        print(f"Error counting root accesses: {e}")
        return 0  # Return 0 if there's an error

# Define the pattern or condition for detecting hot hints
def detect_hot_hint(packet, protocol_name):  # Pass protocol_name as an argument
    # Check if TCP layer exists and if the custom option 'hot_hint_flag' is set
    if protocol_name in packet and packet[protocol_name].options and ('hot_hint_flag', None) in packet[protocol_name].options:
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
        print(f"Error processing packet from count_failed_logins: {e}")
        return 0, 0, 0  # Return 0 if there's an error in processing the packet

# Function to count the number of file access operations
def count_file_accesses(packet, protocol_name):
    try:
        num_access_files = 0  # Initialize the counter for file access operations

        # Assuming file access is determined based on the destination port
        if IP in packet and protocol_name in packet and packet[protocol_name].dport == 21:  # Assuming port 21 (FTP) is used for file access
            num_access_files += 1

        return num_access_files
    except Exception as e:
        print(f"Error counting file access operations: {e}")
        return 0  # Return 0 if there's an error

def is_guest_login(packet):
    try:
        # Check if the packet contains a payload
        if Raw in packet:
            # Attempt to decode the payload
            payload = packet[Raw].load.decode('utf-8')
            
            # Define variations or patterns indicating guest login
            guest_variations = ["guest", "anonymous", "anon", "guestuser", "anonuser"]  # Add more variations as needed

            # Check if any of the variations are present in the payload
            if any(variation in payload.lower() for variation in guest_variations):
                return 1  # Indicate guest login
    except Exception as e:
        # Handle decoding errors
        print(f"Error decoding payload: {e}")
    
    return 0  # No indication of guest login

def count_connections(packet):
    try:
        destination_ip = packet[IP].dst
        destination_port = packet[IP].dport
        
        current_timestamp = time.time()
        
        # Remove timestamps older than two seconds for host connections
        connection_timestamps[destination_ip] = [ts for ts in connection_timestamps[destination_ip] if current_timestamp - ts <= 2]
        
        # Add the current timestamp for host connections
        connection_timestamps[destination_ip].append(current_timestamp)
        
        # Remove timestamps older than two seconds for service connections
        service_timestamps[destination_port] = [ts for ts in service_timestamps[destination_port] if current_timestamp - ts <= 2]
        
        # Add the current timestamp for service connections
        service_timestamps[destination_port].append(current_timestamp)

        count = len(connection_timestamps[destination_ip])
        service_count = len(service_timestamps[destination_port])
        
        return count, service_count
    except Exception as e:
        print(f"Error counting connections: {e}")
        return 0, 0

def Serror_rate_calculate(packet, count, srv_count):
    try:
        total_s_flags_by_count = 0
        total_s_flags_by_srv_count = 0
        
        if count > 0:
            if packet.haslayer(TCP):
                if packet[TCP].flags & 0x01:  # Check if FIN flag is set
                    total_s_flags_by_count += 1
                if packet[TCP].flags & 0x02:  # Check if SYN flag is set
                    total_s_flags_by_count += 1
                if packet[TCP].flags & 0x04:  # Check if RST flag is set
                    total_s_flags_by_count += 1
                if packet[TCP].flags & 0x08:  # Check if PSH flag is set
                    total_s_flags_by_count += 1

        if srv_count > 0:
            if packet.haslayer(TCP):
                if packet[TCP].flags & 0x01:  # Check if FIN flag is set
                    total_s_flags_by_srv_count += 1
                if packet[TCP].flags & 0x02:  # Check if SYN flag is set
                    total_s_flags_by_srv_count += 1
                if packet[TCP].flags & 0x04:  # Check if RST flag is set
                    total_s_flags_by_srv_count += 1
                if packet[TCP].flags & 0x08:  # Check if PSH flag is set
                    total_s_flags_by_srv_count += 1

        return (
            total_s_flags_by_count / count if count > 0 else 0,
            total_s_flags_by_srv_count / srv_count if srv_count > 0 else 0
        )
        
    except Exception as e:
        print(f"Error in Serror_rate_calculate: {e}")
        return 0, 0

def Check_REJ(packet, count, srv_count):
    try:
        check_flag_REJ_by_count = 0
        check_flag_REJ_by_srv_count = 0
        
        if count > 0:
            if packet.haslayer(TCP) and packet[TCP].flags & 0x10: 
                check_flag_REJ_by_count += 1
                
        if srv_count > 0:
            if packet.haslayer(TCP) and packet[TCP].flags & 0x10:
                check_flag_REJ_by_srv_count += 1
                
        return (
            check_flag_REJ_by_count / count if count > 0 else 0,
            check_flag_REJ_by_srv_count / srv_count if srv_count > 0 else 0
        )      
    except Exception as e:
        print(f"Error in Check_REJ: {e}")
        return 0, 0
    

def calculate_diff_srv_rate(packet_data, count):
    try:
        # Extract the service information from the packet data
        service_info = [(packet[IP].dport, packet[TCP].sport) for packet in packet_data if IP in packet and TCP in packet]
        # Count the number of connections to different services
        different_services_count = len(set(service_info))
        # Calculate Diff_srv_rate
        diff_srv_rate = (different_services_count / count)

        return diff_srv_rate
    except Exception as e:
        print("An error occurred:", e)
        return 0

def calculate_Srv_diff_host_rate(count, srv_count):
    try:
        Srv_diff_host_rate = 1 - (srv_count / count) if count > 0 else 0
        return Srv_diff_host_rate
    except Exception as e:
        print(f"Error calculating Srv_diff_host_rate: {e}")
        return 0


@app.route('/', methods=['GET'])
def get_packet_info():
    try:
        # Capture the time when the packet was received
        received_time = time.time()
        pack = Ether() / IP(flags="MF") / TCP() / UDP() / ICMP()

        duration = int(time.time() - received_time)
        protocol_type = 0
        src_bytes = 0
        dst_bytes = 0
        land = 0
        wrong_fragment = 0
        urgent_flag = 0
        hot_hint_count = 0
        num_failed_logins = 0
        Logged_In = 0
        root_shell = 0 
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_access_files = 0
        num_shells = 0
        num_outbound_cmds = 0
        host_login = 0
        guest_login = 0
        count = 0
        srv_count = 0
        Serror_rate = 0
        Srv_serror_rate = 0
        Rerror_rate = 0
        Srv_Rerror_rate = 0
        Same_srv_rate = 0
        Diff_srv_rate = 0
        protocol_name = ""  
        
        # Extract information from the packet
        if IP in pack:
            protocol_number = pack[IP].proto
            protocol_type = protocol_dictionary_number.get(protocol_number)
            protocol_name = protocol_dictionary_name.get(protocol_number)
            src_bytes = len(pack[protocol_name].payload)
            dst_bytes = len(pack[IP].payload)
            land = 1 if pack[IP].sport == pack[IP].dport else 0     # Check if source port equals destination port
            wrong_fragment = 1 if pack[IP].flags & 0x01 and pack[IP].flags & 0x02 else 0    # Check if both DF and MF flags are set
            
            if protocol_name == 'TCP' and TCP in pack:  # Check for TCP Urgent Pointer flag (URG)
                urgent_flag = 1 if pack[TCP].flags & 0x20 else 0  # Check if URG bit is set

            # Check for hot hints
            if detect_hot_hint(pack, protocol_name):  # Pass protocol_name as an argument
                hot_hint_count += 1
            
            # Count failed login attempts and check for "su" attempts
            num_failed_logins, Logged_In, su_attempted = count_failed_logins(pack)

            # Assuming system toolbox is opened through port 22 (SSH)
            root_shell = 1 if pack[protocol_name].dport == 22 else 0
                
            num_root = count_root_accesses(pack, protocol_name)  # Pass protocol_name as an argument
            
            # Increment num_file_creations if packet indicates file creation operation
            num_file_creations = packet_indicates_file_creation(pack)

            num_shells = count_shell_accesses(pack, protocol_name)  # Pass protocol_name as an argument

            # Count the number of file access operations
            num_access_files = count_file_accesses(pack, protocol_name)

            guest_login = is_guest_login(pack)

            count, srv_count = count_connections(pack)

            Serror_rate, Srv_serror_rate = Serror_rate_calculate(pack, count, srv_count)

            Rerror_rate, Srv_Rerror_rate = Check_REJ(pack, count, srv_count)

            Same_srv_rate = srv_count / count if count > 0 else 0

            Diff_srv_rate = calculate_diff_srv_rate(pack, count)
            
            Srv_diff_host_rate = calculate_Srv_diff_host_rate(count, srv_count)
            
            response = f"\nDuration: {duration}\nProtocol Type: {protocol_type}\nSource Bytes: {src_bytes}\nDestination Bytes: {dst_bytes}\nLand: {land}\nWrong Fragment: {wrong_fragment}\nUrgent Flag: {urgent_flag}\nHot Hint Count: {hot_hint_count}\nNum Failed Logins: {num_failed_logins}\nLogged in: {Logged_In}\nRoot Shell: {root_shell}\nsu_attempted: {su_attempted}\nNum Root: {num_root}\nnum_file_creations: {num_file_creations}\nnum_shells: {num_shells}\nNum Access Files: {num_access_files}\nNum Outbound Commands: {num_outbound_cmds}\nIs Host Login: {host_login}\nIs Guest Login: {guest_login}\ncount: {count}\nsrv_count: {srv_count}\nSerror_rate {Serror_rate}\nSrv_serror_rate: {Srv_serror_rate}\nRerror_rate: {Rerror_rate}\nSrv_Rerror_rate: {Srv_Rerror_rate}\nSame_srv_rate: {Same_srv_rate}\nDiff_srv_rate: {Diff_srv_rate}\nSrv_diff_host_rate: {Srv_diff_host_rate}\n\n"        # Print the extracted information to the command prompt
        print(response)

        return ''
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 'Error processing packet'  # Return error message if there's an exception

    
if __name__ == '__main__':
    # Change the host parameter to the desired IP address
    app.run(host='172.31.37.161', port=5000, debug=True)
