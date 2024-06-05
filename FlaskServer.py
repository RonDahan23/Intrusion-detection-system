import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

from flask import Flask, request
from scapy.all import *
from network_packet_analyzer import NetworkPacketAnalyzer
from intrusion_detection import IntrusionDetectionModel
import Ascii_logos
import dictionarys
import numpy as np


ip_database = {}
port_database = {}
connection_database = {}

model_path = "/home/ron/Intrusion-detection-system/model"
x_test_path = "/home/ron/Intrusion-detection-system/model/np_X_Test.npy"
y_test_path = "/home/ron/Intrusion-detection-system/model/np_y_Test.npy"

app = Flask(__name__)

analyzer = NetworkPacketAnalyzer()
intrusion_model = IntrusionDetectionModel(model_path, x_test_path, y_test_path)
   

@app.route("/", methods=["GET"])
def index():
    data = request.args.get('data', "")
    if data:
        print(f"Received data: {data}")
    else:
        print("No data parameter received.")
    received_time = time.time()
    res = sniff(count=1, filter="ip")[0]
    packet_sniffer(res, data, received_time)
    print("Packet sniffing complete.")
    return ''


def packet_sniffer(packet, data, received_time):
    try:
        if IP in packet:
            duration = int(time.time() - received_time)

            protocol_number = packet[IP].proto

            protocol_type = int(dictionarys.protocol_dictionary_number.get(protocol_number))

            protocol_name = dictionarys.protocol_dictionary_name.get(protocol_number)

            src_bytes = int((len(bytes(packet)) + len(bytes(data.encode()))))

            dst_bytes = int(len(packet.payload))

            flag = int(dictionarys.TCP_FLAG_NUMBERS.get('SF'))
            if protocol_name == 'TCP' and TCP in packet:
                flags = packet[TCP].sprintf('%TCP.flags%')
                for state, info in dictionarys.TCP_STATES.items():
                    if all(f in flags for f in info["flags"]):
                        #print(f"Packet matches {state} state with flags {flags}")
                        flag = int(dictionarys.TCP_FLAG_NUMBERS.get(state))

            land = int(packet[IP].sport == packet[IP].dport and packet[IP].dst == packet[IP].src)

            wrong_fragment = 0
            if protocol_name == 'TCP' and TCP in packet:
                wrong_fragment = int(packet[IP].flags & 0x01 and packet[IP].flags & 0x02)

            urgent_flag = 0
            if protocol_name == 'TCP' and TCP in packet:
                urgent_flag = int(packet[TCP].flags & 0x20)

            Logged_In = 1

            num_failed_logins, su_attempted = analyzer.count_failed_logins(data)

            root_shell = int(packet[protocol_name].dport == 22)

            num_root = analyzer.count_root_accesses(packet, protocol_name)

            num_file_creations = analyzer.packet_indicates_file_creation(data)

            num_shells = analyzer.count_shell_accesses(packet, 'TCP')

            num_access_files = analyzer.count_file_accesses(packet, 'TCP')

            guest_login = analyzer.is_guest_login(data)

            host_login = analyzer.is_host_login(data)

            count, srv_count = analyzer.count_connections(packet)

            Serror_rate, Srv_serror_rate = analyzer.Serror_rate_calculate(packet, count, srv_count)

            Rerror_rate, Srv_Rerror_rate = analyzer.Check_REJ(packet, count, srv_count)

            Same_srv_rate = srv_count / count if count > 0 else 0

            Diff_srv_rate = analyzer.calculate_diff_srv_rate(packet, count)

            Srv_diff_host_rate = analyzer.calculate_srv_diff_host_rate(packet, srv_count)

            Dst_host_count = analyzer.update_ip_connection_count(packet[IP].dst, ip_database)

            Dst_host_srv_count = analyzer.update_port_connection_count(protocol_number, port_database)

            dst_host_same_srv_rate = Dst_host_srv_count / Dst_host_count if Dst_host_count > 0 else 0
            dst_host_same_srv_rate = round(dst_host_same_srv_rate, 3 - len(str(int(dst_host_same_srv_rate))[-3:]))
            if dst_host_same_srv_rate > 1:
                dst_host_same_srv_rate = 1.00

            Dst_host_serror_rate, Dst_host_srv_serror_rate, Dst_host_rerror_rate, Dst_host_srv_rerror_rate = analyzer.check_flags_in_packet(packet)

            analyzer.update_connection(connection_database, packet[IP].dst, protocol_number, Dst_host_serror_rate, Dst_host_srv_serror_rate, Dst_host_rerror_rate, Dst_host_srv_rerror_rate)

            if packet[IP].dst in connection_database:
                dst_serror_rate = connection_database[packet[IP].dst].get('Dst_host_serror_rate')
                dst_rerror_rate = connection_database[packet[IP].dst].get('Dst_host_rerror_rate')
                
                if Dst_host_count > 0:
                    Dst_host_serror_rate = dst_serror_rate / Dst_host_count if isinstance(dst_serror_rate, (int, float)) else 0
                    Dst_host_rerror_rate = dst_rerror_rate / Dst_host_count if isinstance(dst_rerror_rate, (int, float)) else 0
                else: 
                    Dst_host_serror_rate = 0
                    Dst_host_rerror_rate = 0

                dst_srv_serror_rate = connection_database[packet[IP].dst].get('Dst_host_srv_serror_rate')
                dst_srv_rerror_rate = connection_database[packet[IP].dst].get('Dst_host_srv_rerror_rate')

                if Dst_host_srv_count > 0:
                    Dst_host_srv_serror_rate = dst_srv_serror_rate / Dst_host_srv_count if isinstance(dst_srv_serror_rate, (int, float)) else 0
                    Dst_host_srv_rerror_rate = dst_srv_rerror_rate / Dst_host_srv_count if isinstance(dst_srv_rerror_rate, (int, float)) else 0
                else:
                    Dst_host_srv_serror_rate = 0
                    Dst_host_srv_rerror_rate = 0


            X1 = np.array([duration, protocol_type, src_bytes, dst_bytes, flag, land, wrong_fragment, urgent_flag, 
                num_failed_logins, Logged_In, root_shell, su_attempted, num_root, num_file_creations, 
                num_shells, num_access_files, host_login, guest_login, count, srv_count, Serror_rate,
                Srv_serror_rate, Rerror_rate, Srv_Rerror_rate, Same_srv_rate, Diff_srv_rate, Srv_diff_host_rate, 
                Dst_host_count, Dst_host_srv_count, dst_host_same_srv_rate, Dst_host_serror_rate, 
                Dst_host_srv_serror_rate, Dst_host_rerror_rate, Dst_host_srv_rerror_rate], dtype=float) 

            print(Ascii_logos.Ascii_logo_packet)

            result = intrusion_model.classify(X1)     
            if result == "anomaly":
                print("The machine learning model identified the packet as:", "\033[1;31;40m{}\033[0m".format(result.upper()))  # Red
            else:
                print("The machine learning model identified the packet as:", "\033[1;32;40m{}\033[0m".format(result.upper()))  # Green
            
            print("\033[1;36;40m{}\033[0m".format("\n BASIC FEATURES: \n[==============================]"))
            print(f"\nDuration: {duration}\nProtocol Type: {protocol_type}\nflag: {flag}\nSource Bytes: {src_bytes}\nDestination Bytes: {dst_bytes}\nLand: {land}\nWrong Fragment: {wrong_fragment}\nUrgent Flag: {urgent_flag}\n\n")
            print("\033[1;36;40m{}\033[0m".format(" CONTENT RELATED FEATURES: \n[==============================]"))
            print(f"\nNum Failed Logins: {num_failed_logins}\nLogged in: {Logged_In}\nRoot Shell: {root_shell}\nsu_attempted: {su_attempted}\nNum Root: {num_root}\nnum_file_creations: {num_file_creations}\nnum_shells: {num_shells}\nNum Access Files:{num_access_files}\nIs Host Login: {host_login}\nIs Guest Login: {guest_login}\n\n")
            print("\033[1;36;40m{}\033[0m".format(" TIME RELATED TRAFFIC: \n[==============================]"))
            print(f"\ncount: {count}\nsrv_count: {srv_count}\nSerror_rate {Serror_rate}\nSrv_serror_rate: {Srv_serror_rate}\nRerror_rate: {Rerror_rate}\nSrv_Rerror_rate: {Srv_Rerror_rate}\nSame_srv_rate: {Same_srv_rate}\nDiff_srv_rate: {Diff_srv_rate}\nSrv_diff_host_rate: {Srv_diff_host_rate}\n\n")
            print("\033[1;36;40m{}\033[0m".format(" HOST BASED TRAFFIC: \n[==============================]"))
            print(f"\nDst_host_count: {Dst_host_count}\nDst_host_srv_count: {Dst_host_srv_count}\ndst_host_same_srv_rate: {dst_host_same_srv_rate}\nDst_host_serror_rate: {Dst_host_serror_rate}\nDst_host_srv_serror_rate: {Dst_host_srv_serror_rate}\nDst_host_rerror_rate: {Dst_host_rerror_rate}\nDst_host_srv_rerror_rate: {Dst_host_srv_rerror_rate}\n\n")

            if guest_login > 0 or host_login > 0:
                text_U2R = """
                Checking the URL: Ensure no unauthorized entries attempt to elevate permissions.
                Least Privilege: Grant only the minimal necessary access.
                Regular Updates: Keep software patched and up-to-date.
                Privilege Management: Centralize control over access rights.
                User Education: Increase awareness through education.
                Best Practices: Adhere to established security protocols.
                        """
                print("\033[91m      WARNING\n[==================]\033[0m")
                print("The system detected a manual privilege escalation (U2R) attack attempt.\n")
                print(" Ways of protection the system\n[===============================]")
                print(text_U2R)

            return ''
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 'Error processing packet'
    
if __name__ == "__main__":
    Ascii_logos.welcome()
    app.run(host='172.31.37.161', port=5000, debug=False)