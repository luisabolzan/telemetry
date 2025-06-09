#!/usr/bin/env python3
import socket
import struct
from collections import namedtuple

# --- CONSTANTS ---
TYPE_IPV4 = 0x0800
PROT_TELEMETRY = 253
SWITCH_IDS = {
    0x7331: "S1", 0x7332: "S2", 0x7333: "S3",
    0x7334: "S4", 0x7335: "S5", 0x0000: "EMPTY"
}

# --- HEADER DEFINITIONS ---
eth_header = struct.Struct('!6s6sH')
ip_header = struct.Struct('!BBHHHBBH4s4s')
path_header_struct = struct.Struct('!HHH')
EthHeader = namedtuple('EthHeader', ['dest', 'src', 'type'])
IpHeader = namedtuple('IpHeader', ['version_ihl', 'diffserv', 'total_len', 'identification',
                                  'flags_frag_offset', 'ttl', 'protocol', 'checksum',
                                  'src_addr', 'dest_addr'])
PathHeader = namedtuple('PathHeader', ['first', 'second', 'third'])

# --- HELPER FUNCTIONS ---
def parse_ethernet_header(data):
    return EthHeader(*eth_header.unpack(data))

def parse_ip_header(data):
    return IpHeader(*ip_header.unpack(data))

def parse_path_header(data):
    return PathHeader(*path_header_struct.unpack(data))

def format_mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def format_ip(bytes_addr):
    return '.'.join(map(str, bytes_addr))

def get_switch_name(switch_id):
    return SWITCH_IDS.get(switch_id, f'Unknown(0x{switch_id:04x})')

# --- MAIN PROGRAM ---
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Waiting for packets...")
    
    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        # 1. Parse Ethernet
        eth = parse_ethernet_header(raw_data[:14])
        if eth.type != TYPE_IPV4:
            continue

        print('\nEthernet Frame:')
        print(f'Destination: {format_mac(eth.dest)}, Source: {format_mac(eth.src)}, Type: IPV4')
        
        # 2. Parse IP
        ip_header_start = 14
        ip_data_segment = raw_data[ip_header_start : ip_header_start + 20]
        if len(ip_data_segment) < 20:
            continue

        ip = parse_ip_header(ip_data_segment)
        actual_ip_header_len = (ip.version_ihl & 0xF) * 4
        
        print('\nIPv4 Packet:')
        print(f'Version: {ip.version_ihl >> 4}, Header Length: {actual_ip_header_len} bytes')
        print(f'TTL: {ip.ttl}, Protocol: {ip.protocol}')     
        print(f'Source: {format_ip(ip.src_addr)}, Destination: {format_ip(ip.dest_addr)}')
        
        # 3. Parse Path Header (Telemetry)
        path_header_start = ip_header_start + actual_ip_header_len 
        path_header_end = path_header_start + 6
        path_data = raw_data[path_header_start : path_header_end]

        if len(path_data) == 6:
            path = parse_path_header(path_data)
            print('\nPath Header (Telemetry):')
            print(f'  Path: [{get_switch_name(path.first)}, {get_switch_name(path.second)}, {get_switch_name(path.third)}]')

        # 4. Decode payload if it's a telemetry packet
        if ip.protocol == PROT_TELEMETRY:
            message_start_offset = path_header_end + 12
            if len(raw_data) > message_start_offset:
                message_bytes = raw_data[message_start_offset:]
                try:
                    text_payload = message_bytes.decode("utf-8", errors="replace")
                    print('\nMessage:')
                    print(f'  {text_payload}')
                except Exception as e:
                    print(f'\nFailed to decode message: {e}')

# ------------------------------------------------------------------

if __name__ == '__main__':
    main()
