import dpkt

def get_pcap_duration(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        # Get the first and last timestamp in the pcap file
        start_time = None
        end_time = None
        
        for ts, _ in pcap:
            if start_time is None:
                start_time = ts
            end_time = ts
        
        # Calculate the duration in seconds
        duration = round(end_time - start_time, 2)
        
        return duration



def count_dropped_packets(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        total_packets = 0
        dropped_packets = 0
        previous_ts = None
        
        for ts, _ in pcap:
            total_packets += 1
            
            if previous_ts is not None and ts - previous_ts > 1:
                dropped_packets += int(ts - previous_ts - 1)
            
            previous_ts = ts
        
        return dropped_packets


def analyze_pcap(pcap_file):

    print("We are analyzing the following pcap_file: " + pcap_file)

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        # Variables to track data rates and dropped packets
        total_packets = 0
        total_bytes = 0
        dropped_packets = 0
        
        # Iterate through each packet in the pcap file
        for ts, buf in pcap:
            total_packets += 1
            total_bytes += len(buf)
            
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    
                    # Check for dropped packets
                    if tcp.flags & dpkt.tcp.TH_RST:
                        dropped_packets += 1

            
        
        # Calculate data rate in MegaBytes per second
        duration = get_pcap_duration(pcap_file) # get pcap duration in seconds
        print("The duration (in seconds) is: " + str(duration))
        data_rate = total_bytes / duration / 1000000  # Mbps


        # Calculate packet loss
        dropped_packets_advanced = count_dropped_packets(pcap_file)
        packet_loss = (dropped_packets_advanced / total_packets) * 100


        # Print the results
        print(f"Total packets: {total_packets}")
        print(f"Total bytes: {total_bytes}")
        print(f"Data rate: {data_rate:.2f} Mbps")
        print(f"Dropped packets: {dropped_packets_advanced}")
        print(f"Packet loss: {packet_loss:.2f}%")


pcap_file = '2022-09-12T13_55_50.062627_ST_One.pcap'
analyze_pcap(pcap_file)

import os
rootdir = '/Users/pravinravishanker/Downloads/Challenge/Datasets'

for subdir, dirs, files in os.walk(rootdir):
    for file in files:
        if file.endswith('.pcap') or file.endswith('.pcap1') or file.endswith('.pcap2'):
            print(os.path.join(subdir, file))
            pcap_file = os.path.join(subdir, file)
            analyze_pcap(pcap_file)


