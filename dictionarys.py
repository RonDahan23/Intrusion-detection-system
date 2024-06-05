
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

TCP_STATES = {
    "SF": {"flags": "SA"},       # SYN, ACK
    "S0": {"flags": "S"},        # SYN only (Initial connection request)
    "REJ": {"flags": "RA"},      # RST, ACK (Connection rejected)
    "RSTR": {"flags": "R"},      # RST only (Connection reset)
    "SH": {"flags": "FA"},       # FIN, ACK (Polite request to close the connection)
    "RSTO": {"flags": "RFA"},    # RST, FIN, ACK (Abortive close with data loss acknowledgment)
    "S1": {"flags": "SA"},       # SYN, ACK (Typically part of a connection establishment)
    "RSTOS0": {"flags": "RSA"},  # RST, SYN, ACK (Incorrect, but theoretical overlap of SYN with RST)
    "S3": {"flags": "SFA"},      # SYN, FIN, ACK (Theoretically incorrect, but distinguishing for this example)
    "S2": {"flags": "SAF"},      # SYN, ACK, FIN (Partially closed connection)
    "OTH": {"flags": "PAU"}      # PSH, ACK, URG (Data push with urgent data)
}

TCP_FLAG_NUMBERS = {
    "SF": 0,
    "S0": 1,
    "REJ": 2,
    "RSTR": 3,
    "SH": 4,
    "RSTO": 5,
    "S1": 6,
    "RSTOS0": 7,
    "S3": 8,
    "S2": 9,
    "OTH": 10
}