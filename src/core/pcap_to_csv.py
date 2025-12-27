import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
import os
from src.utils.logger import setup_logger

logger = setup_logger("pcap_converter")

def pcap_to_df(pcap_path):
    """
    Reads a .pcap file and extracts features for the AI model.
    """
    logger.info(f"Reading {pcap_path}... (This might take a while)")
    packets = rdpcap(pcap_path)
    
    data = []
    
    # We will simulate "Flows" by grouping packets. 
    # For this student project, we treat each packet as a data point to keep it simple.
    
    for pkt in packets:
        if IP in pkt:
            try:
                # 1. Protocol
                proto = 0
                if TCP in pkt: proto = 1
                elif UDP in pkt: proto = 2
                
                # 2. Service (Port)
                sport = pkt[IP].sport if TCP in pkt or UDP in pkt else 0
                
                # 3. Flags (TCP only)
                flags = 0
                if TCP in pkt:
                    # Simple mapping of flag bits to an integer
                    flags = int(pkt[TCP].flags)

                # 4. Bytes
                src_bytes = len(pkt[IP].payload)
                
                row = {
                    'duration': 0.1, # Placeholder (real flow duration requires complex logic)
                    'protocol_type': proto,
                    'service': sport,
                    'flag': flags,
                    'src_bytes': src_bytes,
                    'dst_bytes': 0, # Hard to calculate without full flow tracking
                    'count': 1,
                    'srv_count': 1
                }
                data.append(row)
            except Exception as e:
                pass

    df = pd.DataFrame(data)
    logger.info(f"Extracted {len(df)} samples from {pcap_path}")
    return df

def convert_all_pcaps():
    data_dir = os.path.join(os.getcwd(), 'data')
    all_data = []

    # Look for all .pcap files in the data folder
    for filename in os.listdir(data_dir):
        if filename.endswith(".pcap") or filename.endswith(".pcapng"):
            full_path = os.path.join(data_dir, filename)
            df = pcap_to_df(full_path)
            all_data.append(df)
    
    if all_data:
        final_df = pd.concat(all_data, ignore_index=True)
        # Save as CSV for the training script to pick up
        save_path = os.path.join(data_dir, 'training_data.csv')
        final_df.to_csv(save_path, index=False)
        logger.info(f"Successfully saved combined dataset to {save_path}")
    else:
        logger.warning("No .pcap files found in /data folder!")

if __name__ == "__main__":
    convert_all_pcaps()