import os
import pandas as pd
from scapy.all import *

def pcapng_to_dataframe(pcapng_files):
    data = []
    
    for file in pcapng_files:
        packets = rdpcap(file)
        
        for packet in packets:
            packet_data = {}
            
            # Extract relevant fields from each packet
            packet_data['Timestamp'] = packet.time
            
            # Extract all available fields from the packet
            for layer in packet.layers():
                layer_name = str(layer)
                fields = packet[layer].fields
                for field_name, field_value in fields.items():
                    # Handle different data types
                    if isinstance(field_value, bytes):
                        field_value = field_value.hex()
                    elif isinstance(field_value, list):
                        field_value = ','.join(map(str, field_value))
                    
                    packet_data[layer_name + '_' + field_name] = field_value
            
            # Append packet information to the data list
            data.append(packet_data)
    
    # Create DataFrame from the collected data
    df = pd.DataFrame(data)
    return df

directory = r'D:\network data\test'  #path to your local folder where pacpng file is stored.

pcapng_files = [os.path.join(directory, file) for file in os.listdir(directory) if file.endswith('.pcapng')]

dataframe = pcapng_to_dataframe(pcapng_files)

dataframe.head()    
dataframe.to_csv("yourfilename.csv")