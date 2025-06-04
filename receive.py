#!/usr/bin/env python3

import socket
import struct
from collections import namedtuple

# Constants
TYPE_IPV4 = 0x0800

# Header formats
eth_header = struct.Struct('!6s6sH')
ip_header = struct.Struct('!BBHHHBBH4s4s')
counter_header = struct.Struct('!H')

# Named tuples for parsed headers
EthHeader = namedtuple('EthHeader', ['dest', 'src', 'type'])
IpHeader = namedtuple('IpHeader', ['version_ihl', 'diffserv', 'total_len', 'identification',
                                  'flags_frag_offset', 'ttl', 'protocol', 'checksum',
                                  'src_addr', 'dest_addr'])
CounterHeader = namedtuple('CounterHeader', ['value'])

def main():
    # Create raw socket to listen on all interfaces
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # ETH_P_ALL
    
    print("Waiting for packets...")
    
    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        eth = parse_ethernet_header(raw_data[:14])
        
        # Only proceed and print details if it's an IPv4 packet
        if eth.type == TYPE_IPV4:

            print('\nEthernet Frame:')
            print(f'Destination: {format_mac(eth.dest)}, Source: {format_mac(eth.src)}, Type: IPV4')
            
            # Parse IP header (assuming first 20 bytes after Ethernet for consistency with previous version)
            assumed_ip_header_len = 20 
            ip_data_segment = raw_data[14 : 14 + assumed_ip_header_len]

            if len(ip_data_segment) < assumed_ip_header_len:
                print("  Not enough data for assumed IP header.")
                continue # Skip this packet
            
            ip = parse_ip_header(ip_data_segment)
            
            print('\nIPv4 Packet:')
            actual_ip_header_len = (ip.version_ihl & 0xF) * 4 
            print(f'Version: {ip.version_ihl >> 4}, Header Length: {actual_ip_header_len} bytes')
            protocol_display = "TCP" if ip.protocol == 6 else str(ip.protocol)
            print(f'TTL: {ip.ttl}, Protocol: {protocol_display}')     
            print(f'Source: {format_ip(ip.src_addr)}, Destination: {format_ip(ip.dest_addr)}')
            #print(f'TTL: {ip.ttl}, Protocol: {ip.protocol}') # Expected to be 6 (TCP)
            #print(f'Source: {format_ip(ip.src_addr)}, Destination: {format_ip(ip.dest_addr)}')
            
            # Counter header location based on assumed 20-byte IP header
            counter_header_start_offset = 14 + assumed_ip_header_len 
            counter_data = raw_data[counter_header_start_offset : counter_header_start_offset + 2]

            if len(counter_data) == 2:
                counter = parse_counter_header(counter_data)
                print('\nCounter Header:')
                print(f'Counter value: {counter.value}')

                if ip.protocol == 6: # Check if the original protocol was TCP
                    tcp_header_start_offset = counter_header_start_offset + 2 # After Counter Header
                    assumed_tcp_header_length = 20 # Assuming no TCP options
                    
                    message_start_offset = tcp_header_start_offset + assumed_tcp_header_length

                    if ip.total_len > actual_ip_header_len :
                        original_tcp_segment_length = ip.total_len - actual_ip_header_len
                        
                        if original_tcp_segment_length > assumed_tcp_header_length:
                            message_payload_length = original_tcp_segment_length - assumed_tcp_header_length
                            
                            if len(raw_data) >= message_start_offset + message_payload_length:
                                message_bytes = raw_data[message_start_offset : message_start_offset + message_payload_length]
                                print('\nMessage:')
                                try:
                                    print(f'  {message_bytes.decode("utf-8", errors="replace")}')
                                except Exception as e_decode:
                                    print(f'  Could not decode message: {e_decode}')

def parse_ethernet_header(data):
    dest, src, eth_type = eth_header.unpack(data)
    return EthHeader(dest, src, eth_type)

def parse_ip_header(data):
    version_ihl, diffserv, total_len, identification, flags_frag, ttl, proto, checksum, src, dest = ip_header.unpack(data)
    return IpHeader(version_ihl, diffserv, total_len, identification, flags_frag, ttl, proto, checksum, src, dest)

def parse_counter_header(data):
    value, = counter_header.unpack(data)
    return CounterHeader(value)

def format_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def format_ip(bytes_addr):
    return '.'.join(map(str, bytes_addr))

if __name__ == '__main__':
    main()