
from scapy.all import IP, TCP
import time

Dst_host_serror_rate = 0
Dst_host_srv_serror_rate = 0
Dst_host_rerror_rate = 0
Dst_host_srv_rerror_rate =0

class NetworkPacketAnalyzer:
    def __init__(self):
        self.connection_timestamps = {}
        self.service_timestamps = {}
        self.unique_destination_hosts = set()
        
    
    def count_shell_accesses(self, packet, protocol_name):
        try:
            num_shells = 0
            if IP in packet and protocol_name in packet and packet[protocol_name].dport == 22:
                num_shells += 1
            return num_shells
        except Exception as e:
            print(f"Error counting shell accesses: {e}")
            return 0

    def packet_indicates_file_creation(self, data):
        try:
            file_creation_count = 0
            data = data.lower()
            file_creation_patterns = ["create file", "new file created", "file creation", "create"]
            for pattern in file_creation_patterns:
                if data == pattern:
                    file_creation_count += 1
            return file_creation_count
        except Exception as e:
            print(f"Error processing packet for file creation: {e}")
            return 0

    def count_root_accesses(self, packet, protocol_name):
        try:
            num_root = 0
            if IP in packet and protocol_name in packet and packet[protocol_name].dport == 22:
                num_root += 1
            return num_root
        except Exception as e:
            print(f"Error counting root accesses: {e}")
            return 0

    def count_failed_logins(self, data):
        try:
            num_failed_logins = 0
            failed_login_pattern = "Failed login attempt"
            su_attempt_pattern = "su root"
            num_failed_logins += 1 if data == failed_login_pattern else 0
            su_attempted = 1 if data == su_attempt_pattern else 0
            return num_failed_logins, su_attempted
        except Exception as e:
            print(f"Error processing packet from count_failed_logins: {e}")
            return 0, 0

    def count_file_accesses(self, packet, protocol_name):
        try:
            num_access_files = 0
            if IP in packet and protocol_name in packet and packet[protocol_name].dport == 21:
                num_access_files += 1
            return num_access_files
        except Exception as e:
            print(f"Error counting file access operations: {e}")
            return 0

    def is_guest_login(self, data):
        try:
            guest_variations = ["guest", "anonymous", "anon", "guestuser", "anonuser"]
            for variation in guest_variations:
                if data.lower() == variation:
                    return 1
        except Exception as e:
            print(f"Error decoding payload: {e}")
        return 0

    def is_host_login(self, data):
        try:
            suspicious_variations = ["root", "admin", "administrator"]
            for variation in suspicious_variations:
                if data.lower() == variation:
                    return 1
        except Exception as e:
            print(f"Error decoding payload: {e}")
        return 0

    def count_connections(self, packet):
        try:
            destination_ip = packet[IP].dst
            destination_port = packet[IP].dport
            current_timestamp = time.time()
            self.connection_timestamps.setdefault(destination_ip, [])
            self.service_timestamps.setdefault(destination_port, [])
            self.connection_timestamps[destination_ip] = [ts for ts in self.connection_timestamps[destination_ip] if current_timestamp - ts <= 2]
            self.connection_timestamps[destination_ip].append(current_timestamp)
            self.service_timestamps[destination_port] = [ts for ts in self.service_timestamps[destination_port] if current_timestamp - ts <= 2]
            self.service_timestamps[destination_port].append(current_timestamp)
            count = len(self.connection_timestamps[destination_ip])
            service_count = len(self.service_timestamps[destination_port])
            self.unique_destination_hosts.add(destination_ip)
            return count, service_count
        except Exception as e:
            print(f"Error counting connections: {e}")
            return 0, 0

    def Serror_rate_calculate(self, packet, count, srv_count):
        try:
            total_s_flags_by_count = 0
            total_s_flags_by_srv_count = 0

            if count > 0 and packet.haslayer(TCP):
                flags = packet[TCP].flags
                total_s_flags_by_count += bool(flags & 0x01)  # FIN
                total_s_flags_by_count += bool(flags & 0x02)  # SYN
                total_s_flags_by_count += bool(flags & 0x04)  # RST
                total_s_flags_by_count += bool(flags & 0x08)  # PSH

            if srv_count > 0 and packet.haslayer(TCP):
                flags = packet[TCP].flags
                total_s_flags_by_srv_count += bool(flags & 0x01)  # FIN
                total_s_flags_by_srv_count += bool(flags & 0x02)  # SYN
                total_s_flags_by_srv_count += bool(flags & 0x04)  # RST
                total_s_flags_by_srv_count += bool(flags & 0x08)  # PSH

            return (
                total_s_flags_by_count / count if count > 0 else 0,
                total_s_flags_by_srv_count / srv_count if srv_count > 0 else 0
            )
        except Exception as e:
            print(f"Error in Serror_rate_calculate: {e}")
            return 0, 0

    def Check_REJ(self, packet, count, srv_count):
        try:
            check_flag_REJ_by_count = 0
            check_flag_REJ_by_srv_count = 0

            if count > 0 and packet.haslayer(TCP) and packet[TCP].flags & 0x10:  # ACK
                check_flag_REJ_by_count += 1

            if srv_count > 0 and packet.haslayer(TCP) and packet[TCP].flags & 0x10:  # ACK
                check_flag_REJ_by_srv_count += 1

            return (
                check_flag_REJ_by_count / count if count > 0 else 0,
                check_flag_REJ_by_srv_count / srv_count if srv_count > 0 else 0
            )
        except Exception as e:
            print(f"Error in Check_REJ: {e}")
            return 0, 0

    def calculate_diff_srv_rate(self, packet_data, count):
        try:
            service_info = [(packet[IP].dport, packet[TCP].sport) for packet in packet_data if IP in packet and TCP in packet]
            different_services_count = len(set(service_info))
            diff_srv_rate = (different_services_count / count) if count > 0 else 0
            return diff_srv_rate
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0

    def calculate_srv_diff_host_rate(self, packet_data, srv_count):
        try:
            # Filter connections to the same service
            relevant_packets = [packet for packet in packet_data 
                                if IP in packet and TCP in packet 
                                and packet[TCP].dport == 5000]  
            # Extract destination IPs
            destination_ips = [packet[IP].dst for packet in relevant_packets]
            
            # Count unique destination IPs
            unique_destination_count = len(set(destination_ips))
            
            # Calculate Srv_diff_host_rate
            srv_diff_host_rate = (unique_destination_count / srv_count) if srv_count > 0 else 0
            
            return srv_diff_host_rate
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0
    

    def update_ip_connection_count(self, ip_address, ip_database):
        try:
            if ip_address in ip_database:
                ip_database[ip_address] += 1
            else:
                ip_database[ip_address] = 1
            
            if ip_database[ip_address] < 1:
                ip_database[ip_address] = 1
            
            return ip_database[ip_address]
        except ip_database as e:
            print(f"An error occurred: {e}")
            return 0


    def update_port_connection_count(self, port_number, port_database):
        try:
            if port_number in port_database:
                port_database[port_number] += 1
            else:
                port_database[port_number] = 1
            
            if port_database[port_number] < 1:
                port_database[port_number] = 1
            
            return port_database[port_number]
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0


    def update_connection(self, connection_database, ip_address, port_number, Dst_host_serror_rate, Dst_host_srv_serror_rate, Dst_host_rerror_rate, Dst_host_srv_rerror_rate):
        try:
            if ip_address not in connection_database:
                connection_database[ip_address] = {port_number: 1}
            else:
                if port_number not in connection_database[ip_address]:
                    connection_database[ip_address][port_number] = 1
                else:
                    connection_database[ip_address][port_number] += 1

            connection_database[ip_address].setdefault('Dst_host_serror_rate', 0)
            connection_database[ip_address].setdefault('Dst_host_srv_serror_rate', 0)
            connection_database[ip_address].setdefault('Dst_host_rerror_rate', 0)
            connection_database[ip_address].setdefault('Dst_host_srv_rerror_rate', 0)

            if Dst_host_serror_rate > 0:
                connection_database[ip_address]['Dst_host_serror_rate'] += 1

            if Dst_host_srv_serror_rate > 0:
                connection_database[ip_address]['Dst_host_srv_serror_rate'] += 1

            if Dst_host_rerror_rate > 0:
                connection_database[ip_address]['Dst_host_rerror_rate'] += 1

            if Dst_host_srv_rerror_rate > 0:
                connection_database[ip_address]['Dst_host_srv_rerror_rate'] += 1

            return connection_database
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0


    def check_flags_in_packet(self, packet):
        try:
            total_s_flags_by_dst_host_count = 0
            total_s_flags_by_dst_host_srv_count = 0
            check_flag_REJ_by_dst_host_count = 0
            check_flag_REJ_by_dst_host_srv_count = 0

            if packet.haslayer(TCP):
                flags = packet[TCP].flags
                total_s_flags_by_dst_host_count += bool(flags & 0x01)  # FIN
                total_s_flags_by_dst_host_count += bool(flags & 0x02)  # SYN
                total_s_flags_by_dst_host_count += bool(flags & 0x04)  # RST
                total_s_flags_by_dst_host_count += bool(flags & 0x08)  # PSH

                total_s_flags_by_dst_host_srv_count += bool(flags & 0x01)  # FIN
                total_s_flags_by_dst_host_srv_count += bool(flags & 0x02)  # SYN
                total_s_flags_by_dst_host_srv_count += bool(flags & 0x04)  # RST
                total_s_flags_by_dst_host_srv_count += bool(flags & 0x08)  # PSH

                if flags & 0x10:  # ACK
                    check_flag_REJ_by_dst_host_count += 1
                    check_flag_REJ_by_dst_host_srv_count += 1

            return total_s_flags_by_dst_host_count, total_s_flags_by_dst_host_srv_count,check_flag_REJ_by_dst_host_count, check_flag_REJ_by_dst_host_srv_count
        except Exception as e:
            print(f"Error processing packet: {e}")
            return 0, 0, 0, 0
        