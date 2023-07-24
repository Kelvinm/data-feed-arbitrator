import os
from unittest.mock import patch, mock_open, MagicMock
import pandas as pd
import pytest
from feed_arbitrator_parquet import PacketProcessor, Side, Metrics 
from datetime import datetime, timedelta, date

class TestPacketProcessor:
    
    dt = date.today().strftime("%Y%m%d")

    @pytest.fixture
    def processor(self):
        # Create a processor with a specific date
        # specific_date = datetime.now() - timedelta(days=1)
        return PacketProcessor('packets_all.parquet', '20230723')


    def test_init(self, processor):
        assert processor.parquet_file_name == '20230723_packets_all.parquet'
        # today_date_str = datetime.now().strftime("%Y%m%d")
        # assert processor_default_date.parquet_file_name == f'{today_date_str}_test'



    @patch("pandas.DataFrame.to_parquet")
    @patch("feed_arbitrator_parquet.os.listdir")
    def test_process_directory(self, mock_listdir, mock_to_parquet):
        mock_listdir.return_value = ["file1.pcap", "file2.xz", "other_file.txt"]
        processor = PacketProcessor("test", self.dt)

        with patch.object(processor, 'process_file', autospec=True) as mock_process_file:
            processor.process_directory("/test_directory")

        assert mock_process_file.call_count == 2  # Only two valid pcap/xz files
        mock_process_file.assert_any_call("/test_directory/file1.pcap")
        mock_process_file.assert_any_call("/test_directory/file2.xz")

    @patch("feed_arbitrator_parquet.rdpcap")
    def test_process_file(self, mock_rdpcap):
        processor = PacketProcessor("test", self.dt)
        with patch.object(processor, 'insert_into_dataframe', autospec=True) as mock_insert_into_dataframe:
            processor.process_file("file.pcap")
        assert mock_rdpcap.called
        

    def test_insert_into_dataframe(self):
        processor = PacketProcessor("test", self.dt)
        processor.insert_into_dataframe(1, Side.A.name, b"data", 1234567890.0)
        assert len(processor.dataframe) == 1


class TestMetrics:

    dt = date.today().strftime("%Y%m%d")

    @patch("pandas.read_parquet")
    def test_metrics_initialization(self, mock_read_parquet):
        mock_df = pd.DataFrame({
            "sequence_num": [1, 2, 1, 3],
            "side": [Side.A.name, Side.B.name, Side.B.name, Side.A.name],
            "packet_raw": [b"data1", b"data2", b"data3", b"data4"],
            "packet_timestamp": [1234567890.0, 1234567891.0, 1234567890.5, 1234567892.0],
            "audit_timestamp": ["2021-01-01T00:00:00", "2021-01-01T00:00:01", "2021-01-01T00:00:02", "2021-01-01T00:00:03"]
        })
        mock_read_parquet.return_value = mock_df
        metrics = Metrics("test", self.dt)
        assert metrics.dataframe_path == f"{self.dt}_test_all.parquet"  
        assert metrics.dataframe_arbitrated_path == f"{self.dt}_test_arbitrated.parquet"
        pd.testing.assert_frame_equal(metrics.dataframe, mock_df)
        pd.testing.assert_frame_equal(metrics.dataframe_arbitrated, mock_df)

    
