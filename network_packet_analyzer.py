
from scapy.all import IP, TCP, Raw
import time

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

    def packet_indicates_file_creation(self, packet):
        try:
            file_creation_count = 0
            if Raw in packet:
                payload = packet[Raw].load
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='ignore')  # Add errors='ignore'
                    file_creation_patterns = ["create file", "new file created", "file creation"]
                    for pattern in file_creation_patterns:
                        file_creation_count += payload.count(pattern)
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

    def count_failed_logins(self, packet, data):
        try:
            su_attempted = 0
            if Raw in packet:
                payload = packet[Raw].load
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='ignore')
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
            print("the data is:" + data)
            print("/n/n/n")
            guest_variations = ["guest", "anonymous", "anon", "guestuser", "anonuser"]
            for variation in guest_variations:
                if data.lower() == variation:
                    return 1
        except Exception as e:
            print(f"Error decoding payload: {e}")
        return 0

    def is_host_login(self, packet):
        try:
            suspicious_variations = ["root", "admin", "administrator"]
            if isinstance(packet, bytes):
                payload = packet.decode('utf-8', )
                if any(variation in payload.lower() for variation in suspicious_variations):
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

    def calculate_Srv_diff_host_rate(self, count, srv_count):
        try:
            Srv_diff_host_rate = 1 - (srv_count / count) if count > 0 else 0
            return Srv_diff_host_rate
        except Exception as e:
            print(f"Error calculating Srv_diff_host_rate: {e}")
            return 0
