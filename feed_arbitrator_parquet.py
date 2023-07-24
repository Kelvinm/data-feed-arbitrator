import os
import pandas as pd
import argparse
import lzma
import logging
import time
from scapy.all import rdpcap, UDP
from enum import Enum
from struct import unpack
from datetime import datetime, date
# from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Side(Enum):
    A = 14310
    B = 15310

class PacketProcessor:

    def __init__(self, parquet_file_name, parquet_file_date):
        self.parquet_file_name = f"{parquet_file_date}_{parquet_file_name}"
        self.dataframe = pd.DataFrame(columns=['sequence_num', 'side', 'packet_raw', 'packet_timestamp', 'audit_timestamp'])
        self.dataframe_arbitrated = pd.DataFrame(columns=['sequence_num', 'side', 'packet_raw', 'packet_timestamp', 'audit_timestamp'])
        self.dataframe_path = None
        self.dataframe_arbitrated_path = None


    def process_directory(self, directory):
        start_time = time.time()
        for filename in os.listdir(directory):
            if filename.endswith(('.pcap', '.xz')):
                self.process_file(os.path.join(directory, filename))
        logging.info(f"Processed all files in directory in {time.time() - start_time} seconds")


    # This block of code was my attempt to use a coroutine to parallelize it and load them at the same time.  
    # Given that they both append to the same file at the moment I left it single threaded, but in the future would parallelize the loading of files.

    # def process_directory(self, directory):
    #     start_time = time.time()

    #     with ThreadPoolExecutor() as executor:
    #         futures = {executor.submit(self.process_file, os.path.join(directory, filename)): filename 
    #                    for filename in os.listdir(directory) 
    #                    if filename.endswith(('.pcap', '.xz'))}

    #         for future in as_completed(futures):
    #             filename = futures[future]
    #             try:
    #                 future.result()
    #             except Exception as exc:
    #                 logging.error(f"{filename} generated an exception: {exc}")
    #             else:
    #                 logging.info(f"{filename} has been processed successfully")
    #     logging.info(f"Processed all files in directory in {time.time() - start_time} seconds")


    def process_file(self, file_path):
        logging.info(f"Processing file: {file_path}")
        start_time = time.time()
        if file_path.endswith('.xz'):
            with lzma.open(file_path) as f:
                packets = rdpcap(f)
        else:
            packets = rdpcap(file_path)

        for packet in packets:
            sequence_num, side, packet_raw, packet_timestamp = self.extract_info(packet)
            self.insert_into_dataframe(sequence_num, side.name, packet_raw, packet_timestamp)
        logging.info(f"Processed file: {file_path} in {time.time() - start_time} seconds")

    def extract_info(self, packet):
        side = Side(packet[UDP].sport)
        payload = bytes(packet[UDP].payload)
        sequence_num = unpack('<I', payload[:4])[0]  # Little endian 4-byte integer
        packet_raw = payload[4:-20]
        trailer = payload[-20:]  # 20-byte trailer
        seconds = unpack('>I', trailer[8:12])[0]  # Big endian 4-byte integer
        nanoseconds = unpack('>I', trailer[12:16])[0]  # Big endian 4-byte integer
        packet_timestamp = seconds + nanoseconds * 1e-9
        return sequence_num, side, packet_raw, packet_timestamp

    def insert_into_dataframe(self, sequence_num, side, packet_raw, packet_timestamp):
        audit_timestamp = datetime.now().isoformat()
        self.dataframe.loc[len(self.dataframe)] = [sequence_num, side, packet_raw, packet_timestamp, audit_timestamp]

    def process_arbitrated_packets(self):
        start_time = time.time()
        group_by_sequence_num = self.dataframe.groupby('sequence_num')
        for sequence_num, group in group_by_sequence_num:
            if len(group) == 2:  # Matching sequence numbers
                faster_packet = group.loc[group['packet_timestamp'].idxmin()]
                self.insert_into_arbitrated_dataframe(*faster_packet.values)
        logging.info(f"Processed arbitrated packets in {time.time() - start_time} seconds")

    def insert_into_arbitrated_dataframe(self, sequence_num, side, packet_raw, packet_timestamp, audit_timestamp):
        self.dataframe_arbitrated.loc[len(self.dataframe_arbitrated)] = [sequence_num, side, packet_raw, packet_timestamp, audit_timestamp]


    def save_to_parquet(self):
        start_time = time.time()
        self.dataframe_path = f"{self.parquet_file_name}_all.parquet"
        self.dataframe_arbitrated_path = f"{self.parquet_file_name}_arbitrated.parquet"
        self.dataframe.to_parquet(self.dataframe_path)
        self.dataframe_arbitrated.to_parquet(self.dataframe_arbitrated_path)
        logging.info(f"Saved dataframes to parquet files in {time.time() - start_time} seconds")



class Metrics:

    def __init__(self, parquet_file_name, parquet_file_date):
        file_date_string = parquet_file_date
        self.parquet_file_name = f"{file_date_string}_{parquet_file_name}"
        self.dataframe_path = f"{self.parquet_file_name}_all.parquet"
        self.dataframe_arbitrated_path = f"{self.parquet_file_name}_arbitrated.parquet"
        self.dataframe = pd.read_parquet(self.dataframe_path)
        self.dataframe_arbitrated = pd.read_parquet(self.dataframe_arbitrated_path)


    def total_packets_per_side(self):
        return self.dataframe['side'].value_counts()

    def packets_without_counterpart(self):
        group_by_sequence_num = self.dataframe.groupby('sequence_num')
        counts = group_by_sequence_num.count()
        return counts[counts['side'] == 1]['side'].value_counts()

    def faster_packets(self):
        return self.dataframe_arbitrated['side'].value_counts()

    def average_speed_advantage(self):
        group_by_sequence_num = self.dataframe.groupby('sequence_num')
        time_diffs = {}
        for sequence_num, group in group_by_sequence_num:
            if len(group) == 2:  
                time_diff = abs(group.iloc[0]['packet_timestamp'] - group.iloc[1]['packet_timestamp'])
                faster_side = group.loc[group['packet_timestamp'].idxmin()]['side']
                if faster_side not in time_diffs:
                    time_diffs[faster_side] = []
                time_diffs[faster_side].append(time_diff)
        average_speed_advantage = {side: sum(time_diffs)/len(time_diffs) for side, time_diffs in time_diffs.items()}
        return average_speed_advantage

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', help='Directory pcap files are located')
    parser.add_argument('-p', '--parquet', default='packets', help='Parquet file name, program adds a daily timestamp for persistence')
    parser.add_argument('-dt', '--date', type=str, default=date.today(), help='Date for the parquet files, defaults to today')
    args = parser.parse_args()
    
    _dt = args.date.strftime("%Y%m%d")
    processor = PacketProcessor(args.parquet, _dt)
    processor.process_directory(args.directory)
    processor.process_arbitrated_packets()
    processor.save_to_parquet()

    metrics = Metrics(args.parquet, _dt) 
    print("Total packets per side:")
    print(metrics.total_packets_per_side())
    print("\nNumber of packets without counterpart:")
    print(metrics.packets_without_counterpart())
    print("\nNumber of faster packets:")
    print(metrics.faster_packets())
    print("\nAverage speed advantage:")
    print(metrics.average_speed_advantage())


if __name__ == '__main__':
    main()
