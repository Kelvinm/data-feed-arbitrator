# Market Data Feed Packet Processing and Arbitration

This project provides a Python-based solution for the processing and analysis of market data packets captured from market data recorders. The main goal is to perform feed arbitration on UDP channels and compute several statistics, such as:

- Total number of packets per side (A and B)
- Number of packets in A without a corresponding counterpart in B and vice versa
- Number of packets when A is faster than B and vice versa
- Average speed advantage (time difference) per channel conditioned on being the faster one

## Setup Instructions

### Step 1: Setup a and running

Before starting, it is recommended to use a Python virtual environment to isolate the dependencies used for this project. You can create one using the `venv` module.

```python 
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
python feed_arbitrator_parquet.py -d ./data
```

## Usage

The main script can be run from the command line and takes the directory containing the input files as an argument:


Replace `<directory>` with the path to the directory containing your pcap files. The script will process all pcap files in the given directory and will output the computed statistics to the console.

## Features and Metrics

This script computes several statistics related to the market data packets:

- **Total packets per side**: This is the total number of packets found for each side (A and B).

- **Packets without counterpart**: This is the number of packets in A without a corresponding counterpart in B and vice versa.

- **Faster packets**: This is the number of packets where one side is faster than the other.

- **Average speed advantage**: This is the average difference in packet arrival time between the two sides, conditioned on one side being faster than the other.

These metrics are computed after the feed arbitration is performed on the exchange packet sequence number.

## Considerations


- **Error Handling**: This solution does not include robust error handling. In a production environment, we should add error handling to account for issues like missing files, corrupted files, and invalid packet data.

- **Unit Tests**: This solution includes some unit tests but should be fully fleshed out and further developed to cover edge cases as time goes on.

- **Little Endian Byte Order**: The sequence numbers in the UDP payloads are in Little Endian byte order, which has been accounted for while extracting sequence numbers.

- **Efficiency**: The efficiency of the solution can be further improved by using lower-level libraries (like dpkt instead of scapy) for packet processing. 

- **Data Persistence**: Currently, the script saves processed data into parquet files with a daily timestamp. This data is then read back from the disk when calculating metrics. For better performance, we can consider using a database system or an in-memory data structure for storing packet data.

- **Language Choice**: In a production environment, a project like this would be better served with a faster lower level language.  Rust, C, C++, Golang are some choices.  