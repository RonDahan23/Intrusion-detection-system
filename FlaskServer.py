import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'


from flask import Flask, request
from scapy.all import *
from network_packet_analyzer import NetworkPacketAnalyzer
from intrusion_detection import IntrusionDetectionModel
import numpy as np


model_path = "/home/ron/Intrusion-detection-system/model"
x_test_path = "/home/ron/Intrusion-detection-system/model/np_X_Test.npy"
y_test_path = "/home/ron/Intrusion-detection-system/model/np_y_Test.npy"

app = Flask(__name__)

analyzer = NetworkPacketAnalyzer()
intrusion_model = IntrusionDetectionModel(model_path, x_test_path, y_test_path)

protocol_dictionary_number = {
    6: '0',  # TCP
    17: '1',  # UDP
    1: '2'  # ICMP
}

protocol_dictionary_name = {
    6: 'TCP',
    17: 'UDP',
    1: 'ICMP'
}


@app.route("/", methods=["GET"])
def index():
    data = request.args.get('data', "")
    if data:
        print(f"Received data: {data}")
    else:
        print("No data parameter received.")
    res = sniff(count=1, filter="ip")[0]
    packet_sniffer(res, data)
    print("Packet sniffing complete.")
    return ''


def packet_sniffer(packet, data):
    #try:
    if IP in packet:
        received_time = time.time()
        duration = int(time.time() - received_time)
        protocol_number = packet[IP].proto
        protocol_type = protocol_dictionary_number.get(protocol_number)
        protocol_name = protocol_dictionary_name.get(protocol_number)
        src_bytes = len(bytes(packet))
        dst_bytes = len(packet.payload)
        land = 1 if packet[IP].sport == packet[IP].dport else 0
        wrong_fragment = 1 if packet[IP].flags & 0x01 and packet[
            IP].flags & 0x02 else 0  # Check if both DF and MF flags are set
        urgent_flag = 0
        if protocol_name == 'TCP' and TCP in packet:
            urgent_flag = 1 if packet[TCP].flags & 0x20 else 0

        num_failed_logins, Logged_In, su_attempted = analyzer.count_failed_logins(packet, data)

        root_shell = 1 if packet[protocol_name].dport == 22 else 0

        num_root = analyzer.count_root_accesses(packet, protocol_name)

        num_file_creations = analyzer.packet_indicates_file_creation(packet)

        num_shells = analyzer.count_shell_accesses(packet, 'TCP')

        num_access_files = analyzer.count_file_accesses(packet, 'TCP')

        guest_login = analyzer.is_guest_login(data)

        host_login = analyzer.is_host_login(data)

        count, srv_count = analyzer.count_connections(packet)

        Serror_rate, Srv_serror_rate = analyzer.Serror_rate_calculate(packet, count, srv_count)

        Rerror_rate, Srv_Rerror_rate = analyzer.Check_REJ(packet, count, srv_count)

        Same_srv_rate = srv_count / count if count > 0 else 0

        Diff_srv_rate = analyzer.calculate_diff_srv_rate([packet], count)

        Srv_diff_host_rate = analyzer.calculate_Srv_diff_host_rate(count, srv_count)

        # X1 = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 6, 1, 1, 0, 0, 0.05, 0.07, 0, 255, 26, 0.1, 0.05, 0, 0, 1, 1, 0, 0])
        # print(intrusion_model.classify(X1))
        print(
            f"\nDuration: {duration}\nProtocol Type: {protocol_type}\nSource Bytes: {src_bytes}\nDestination Bytes: {dst_bytes}\nLand: {land}\nWrong Fragment: {wrong_fragment}\nUrgent Flag: {urgent_flag}\nNum Failed Logins: {num_failed_logins}\nLogged in: {Logged_In}\nRoot Shell: {root_shell}\nsu_attempted: {su_attempted}\nNum Root: {num_root}\nnum_file_creations: {num_file_creations}\nnum_shells: {num_shells}\nNum Access Files:{num_access_files}\nIs Host Login: {host_login}\nIs Guest Login: {guest_login}\ncount: {count}\nsrv_count: {srv_count}\nSerror_rate {Serror_rate}\nSrv_serror_rate: {Srv_serror_rate}\nRerror_rate: {Rerror_rate}\nSrv_Rerror_rate: {Srv_Rerror_rate}\nSame_srv_rate: {Same_srv_rate}\nDiff_srv_rate: {Diff_srv_rate}\nSrv_diff_host_rate: {Srv_diff_host_rate}\n\n\n")
    return ''
    #except Exception as e:
    #    print(f"Error processing packet: {e}")
    #    return 'Error processing packet'


if __name__ == "__main__":
    app.run(host='172.31.37.161', port=5001, debug=False)
