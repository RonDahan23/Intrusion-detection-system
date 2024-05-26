from flask import Flask
from scapy.all import *
import time
from collections import defaultdict

app = Flask(__name__)


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

def count_shell_accesses(packet, protocol_name):  
    try:
        num_shells = 0  

        if IP in packet and protocol_name in packet and packet[protocol_name].dport == 22:  # Assuming port 22 (SSH) is used for shell access
            num_shells += 1

        return num_shells
    except Exception as e:
        print(f"Error counting shell accesses: {e}")
        return 0  

# Function to count file creation operations in the packet payload
def packet_indicates_file_creation(packet):
    try:
        file_creation_count = 0  
        
        
        if Raw in packet:
            
            payload = packet[Raw].load

            
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8')

                
                file_creation_patterns = ["create file", "new file created", "file creation"]

                
                for pattern in file_creation_patterns:
                    file_creation_count += payload.count(pattern)

        return file_creation_count
    except Exception as e:
        print(f"Error processing packet for file creation: {e}")
        return 0  

# Function to count the number of accesses to the root
def count_root_accesses(packet, protocol_name):  
    try:
        num_root = 0  
        if IP in packet and protocol_name in packet and packet[protocol_name].dport == 22:  # Assuming port 22 (SSH) is used for root access
            num_root += 1

        return num_root
    except Exception as e:
        print(f"Error counting root accesses: {e}")
        return 0 

# Define the pattern or condition for detecting hot hints
def detect_hot_hint(packet, protocol_name):  
    if protocol_name in packet and packet[protocol_name].options and ('hot_hint_flag', None) in packet[protocol_name].options:
        return True
    else:
        return False

# Function to count failed login attempts and check for "su" attempts
def count_failed_logins(packet):
    try:
        su_attempted = 0  
        if Raw in packet:
            payload = packet[Raw].load

            if isinstance(payload, bytes):
                payload = payload.decode('utf-8')
                failed_login_pattern = "Failed login attempt"
                successful_login_pattern = "logged in"
                su_attempt_pattern = "su:"

                num_failed_logins = payload.count(failed_login_pattern)
                
                successful_login = 1 if successful_login_pattern in payload else 0

                su_attempted = 1 if su_attempt_pattern in payload else 0
                
                return num_failed_logins, successful_login, su_attempted
            else:
                return 0, 0, 0 
        else:
            return 0, 0, 0 
    except Exception as e:
        print(f"Error processing packet from count_failed_logins: {e}")
        return 0, 0, 0  

# Function to count the number of file access operations
def count_file_accesses(packet, protocol_name):
    try:
        num_access_files = 0  

        if IP in packet and protocol_name in packet and packet[protocol_name].dport == 21:  # Assuming port 21 (FTP) is used for file access
            num_access_files += 1

        return num_access_files
    except Exception as e:
        print(f"Error counting file access operations: {e}")
        return 0  

def is_guest_login(packet):
    try:
        if Raw in packet:
            payload = packet[Raw].load.decode('utf-8')
            
            guest_variations = ["guest", "anonymous", "anon", "guestuser", "anonuser"]

            if any(variation in payload.lower() for variation in guest_variations):
                return 1  
    except Exception as e:
        print(f"Error decoding payload: {e}")
    return 0  

unique_destination_hosts = set()
def count_connections(packet):
    try:
        destination_ip = packet[IP].dst
        destination_port = packet[IP].dport
        current_timestamp = time.time()
        connection_timestamps[destination_ip] = [ts for ts in connection_timestamps[destination_ip] if current_timestamp - ts <= 2]
        connection_timestamps[destination_ip].append(current_timestamp)
        service_timestamps[destination_port] = [ts for ts in service_timestamps[destination_port] if current_timestamp - ts <= 2]
        service_timestamps[destination_port].append(current_timestamp)
        count = len(connection_timestamps[destination_ip])
        service_count = len(service_timestamps[destination_port])
        unique_destination_hosts.add(destination_ip)

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
                if packet[TCP].flags & 0x01:  
                    total_s_flags_by_srv_count += 1
                if packet[TCP].flags & 0x02:  
                    total_s_flags_by_srv_count += 1
                if packet[TCP].flags & 0x04:  
                    total_s_flags_by_srv_count += 1
                if packet[TCP].flags & 0x08:  
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
        service_info = [(packet[IP].dport, packet[TCP].sport) for packet in packet_data if IP in packet and TCP in packet]
        different_services_count = len(set(service_info))
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
        received_time = time.time()
        pack = Ether() / IP(flags="MF") / TCP() / UDP() / ICMP()        
        duration = int(time.time() - received_time)
        protocol_name = ""  
        hot_hint_count = 0  #need to check 
        host_login = 0 #need to check

        num_outbound_cmds = 0   #need to check 

        
        
        # Extract information from the packet
        if IP in pack:
            protocol_number = pack[IP].proto
            protocol_type = protocol_dictionary_number.get(protocol_number)
            protocol_name = protocol_dictionary_name.get(protocol_number)
            src_bytes = len(pack[protocol_name].payload)
            dst_bytes = len(pack[IP].payload)
            land = 1 if pack[IP].sport == pack[IP].dport else 0    
            wrong_fragment = 1 if pack[IP].flags & 0x01 and pack[IP].flags & 0x02 else 0    # Check if both DF and MF flags are set
            
            if protocol_name == 'TCP' and TCP in pack:  
                urgent_flag = 1 if pack[TCP].flags & 0x20 else 0  

            if detect_hot_hint(pack, protocol_name):  
                hot_hint_count += 1

            num_failed_logins, Logged_In, su_attempted = count_failed_logins(pack)

            root_shell = 1 if pack[protocol_name].dport == 22 else 0
                
            num_root = count_root_accesses(pack, protocol_name) 

            num_file_creations = packet_indicates_file_creation(pack)

            num_shells = count_shell_accesses(pack, protocol_name) 

            num_access_files = count_file_accesses(pack, protocol_name)

            guest_login = is_guest_login(pack)

            count, srv_count = count_connections(pack)

            Serror_rate, Srv_serror_rate = Serror_rate_calculate(pack, count, srv_count)

            Rerror_rate, Srv_Rerror_rate = Check_REJ(pack, count, srv_count)

            Same_srv_rate = srv_count / count if count > 0 else 0

            Diff_srv_rate = calculate_diff_srv_rate(pack, count)
            
            Srv_diff_host_rate = calculate_Srv_diff_host_rate(count, srv_count)

            dst_host_count = len(unique_destination_hosts)

            response = f"\nDuration: {duration}\nProtocol Type: {protocol_type}\nSource Bytes: {src_bytes}\nDestination Bytes: {dst_bytes}\nLand: {land}\nWrong Fragment: {wrong_fragment}\nUrgent Flag: {urgent_flag}\nHot Hint Count: {hot_hint_count}\nNum Failed Logins: {num_failed_logins}\nLogged in: {Logged_In}\nRoot Shell: {root_shell}\nsu_attempted: {su_attempted}\nNum Root: {num_root}\nnum_file_creations: {num_file_creations}\nnum_shells: {num_shells}\nNum Access Files: {num_access_files}\nNum Outbound Commands: {num_outbound_cmds}\nIs Host Login: {host_login}\nIs Guest Login: {guest_login}\ncount: {count}\nsrv_count: {srv_count}\nSerror_rate {Serror_rate}\nSrv_serror_rate: {Srv_serror_rate}\nRerror_rate: {Rerror_rate}\nSrv_Rerror_rate: {Srv_Rerror_rate}\nSame_srv_rate: {Same_srv_rate}\nDiff_srv_rate: {Diff_srv_rate}\nSrv_diff_host_rate: {Srv_diff_host_rate}\ndst_host_count: {dst_host_count}\n\n"        # Print the extracted information to the command prompt
        print(response)

        return ''
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 'Error processing packet'

    
if __name__ == '__main__':
    app.run(host='172.31.37.161', port=5000, debug=True)


