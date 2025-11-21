#!/usr/bin/env python3
"""Tests for test_runner.py"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import sys
import socket
import struct

# Import functions from test_runner
from test_runner import (
    run_test, collect_files, initialize_tpm,
    send_startup_command, main
)


class TestRunTest(unittest.TestCase):
    """Test cases for run_test function"""
    
    @patch('builtins.open', mock_open(read_data=b'\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x7b\x00\x10'))
    def test_run_test_success(self):
        """Test successful test execution"""
        mock_client = Mock()
        # Success response with RC=0
        mock_client.send_command.return_value = b'\x80\x01\x00\x00\x00\x0c\x00\x00\x00\x00'
        
        test_file = Path('/tmp/test.bin')
        result = run_test(mock_client, test_file)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['rc'], 0)
        self.assertEqual(result['file'], 'test.bin')
    
    @patch('builtins.open', mock_open(read_data=b'\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x7b\x00\x10'))
    def test_run_test_failure(self):
        """Test failed test execution with non-zero RC"""
        mock_client = Mock()
        # Failure response with RC=0x100
        mock_client.send_command.return_value = b'\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x00'
        
        test_file = Path('/tmp/test.bin')
        result = run_test(mock_client, test_file)
        
        self.assertFalse(result['success'])
        self.assertEqual(result['rc'], 0x100)
        self.assertEqual(result['file'], 'test.bin')
    
    @patch('builtins.open', mock_open(read_data=b''))
    def test_run_test_empty_file(self):
        """Test handling empty test file"""
        mock_client = Mock()
        test_file = Path('/tmp/empty.bin')
        result = run_test(mock_client, test_file)
        
        self.assertIsNone(result)
    
    @patch('builtins.open', mock_open(read_data=b'\x80\x01\x00\x00\x00\x0c'))
    def test_run_test_short_response(self):
        """Test handling response shorter than 10 bytes"""
        mock_client = Mock()
        mock_client.send_command.return_value = b'\x80\x01'
        
        test_file = Path('/tmp/test.bin')
        result = run_test(mock_client, test_file)
        
        self.assertFalse(result['success'])
        self.assertIsNone(result['rc'])
    
    @patch('builtins.open', mock_open(read_data=b'\x80\x01\x00\x00\x00\x0c'))
    def test_run_test_exception(self):
        """Test handling exception during test execution"""
        mock_client = Mock()
        mock_client.send_command.side_effect = Exception("Connection error")
        
        test_file = Path('/tmp/test.bin')
        result = run_test(mock_client, test_file)
        
        self.assertFalse(result['success'])
        self.assertIn('error', result)
        self.assertEqual(result['error'], "Connection error")


class TestCollectFiles(unittest.TestCase):
    """Test cases for collect_files function"""
    
    def test_collect_files_valid_directory(self):
        """Test collecting files from valid directory"""
        mock_dir = Mock(spec=Path)
        mock_dir.exists.return_value = True
        
        mock_file1 = Mock(spec=Path)
        mock_file1.is_file.return_value = True
        mock_file1.name = 'test1.bin'
        mock_file1.__lt__ = Mock(return_value=True)  # Enable sorting
        
        mock_file2 = Mock(spec=Path)
        mock_file2.is_file.return_value = True
        mock_file2.name = 'test2.bin'
        mock_file2.__lt__ = Mock(return_value=False)  # Enable sorting
        
        mock_dir.iterdir.return_value = [mock_file2, mock_file1]
        
        files = collect_files(mock_dir)
        
        self.assertEqual(len(files), 2)
        self.assertIn(mock_file1, files)
        self.assertIn(mock_file2, files)
    
    def test_collect_files_filters_directories(self):
        """Test that directories are filtered out"""
        mock_dir = Mock(spec=Path)
        mock_dir.exists.return_value = True
        
        mock_file = Mock(spec=Path)
        mock_file.is_file.return_value = True
        
        mock_subdir = Mock(spec=Path)
        mock_subdir.is_file.return_value = False
        
        mock_dir.iterdir.return_value = [mock_file, mock_subdir]
        
        files = collect_files(mock_dir)
        
        self.assertEqual(len(files), 1)
        self.assertIn(mock_file, files)
        self.assertNotIn(mock_subdir, files)
    
    def test_collect_files_nonexistent_directory(self):
        """Test handling nonexistent directory"""
        mock_dir = Mock(spec=Path)
        mock_dir.exists.return_value = False
        
        files = collect_files(mock_dir)
        
        self.assertEqual(files, [])
    
    def test_collect_files_none_directory(self):
        """Test handling None directory"""
        files = collect_files(None)
        self.assertEqual(files, [])


class TestInitializeTPM(unittest.TestCase):
    """Test cases for initialize_tpm function"""
    
    @patch('socket.socket')
    def test_initialize_tpm_success(self, mock_socket_class):
        """Test successful TPM initialization"""
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.return_value = b'\x00\x00\x00\x00'
        
        result = initialize_tpm('localhost')
        
        self.assertTrue(result)
        mock_sock.connect.assert_called_once_with(('localhost', 2322))
        self.assertEqual(mock_sock.sendall.call_count, 2)
        mock_sock.close.assert_called_once()
    
    @patch('socket.socket')
    def test_initialize_tpm_connection_error(self, mock_socket_class):
        """Test handling connection error during initialization"""
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.error("Connection refused")
        
        result = initialize_tpm('localhost')
        
        self.assertFalse(result)
    
    @patch('socket.socket')
    def test_initialize_tpm_custom_port(self, mock_socket_class):
        """Test TPM initialization with custom port"""
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.return_value = b'\x00\x00\x00\x00'
        
        result = initialize_tpm('localhost', platform_port=9999)
        
        self.assertTrue(result)
        mock_sock.connect.assert_called_once_with(('localhost', 9999))


class TestSendStartupCommand(unittest.TestCase):
    """Test cases for send_startup_command function"""
    
    def test_send_startup_command_success(self):
        """Test successful startup command"""
        mock_client = Mock()
        # Success response with RC=0
        mock_client.send_command.return_value = b'\x80\x01\x00\x00\x00\x0a\x00\x00\x00\x00'
        
        result = send_startup_command(mock_client)
        
        self.assertTrue(result)
        mock_client.send_command.assert_called_once()
        
        # Verify startup command
        sent_cmd = mock_client.send_command.call_args[0][0]
        expected = bytes([0x80, 0x01, 0x00, 0x00, 0x00, 0x0C,
                         0x00, 0x00, 0x01, 0x44, 0x00, 0x00])
        self.assertEqual(sent_cmd, expected)
    
    def test_send_startup_command_already_initialized(self):
        """Test startup command when TPM already initialized"""
        mock_client = Mock()
        # RC=0x100 (TPM_RC_INITIALIZE)
        mock_client.send_command.return_value = b'\x80\x01\x00\x00\x00\x0a\x00\x00\x01\x00'
        
        result = send_startup_command(mock_client)
        
        self.assertTrue(result)
    
    def test_send_startup_command_failure(self):
        """Test failed startup command"""
        mock_client = Mock()
        # Failure response with different RC
        mock_client.send_command.return_value = b'\x80\x01\x00\x00\x00\x0a\x00\x00\x02\x00'
        
        result = send_startup_command(mock_client)
        
        self.assertFalse(result)
    
    def test_send_startup_command_exception(self):
        """Test handling exception during startup"""
        mock_client = Mock()
        mock_client.send_command.side_effect = Exception("Network error")
        
        result = send_startup_command(mock_client)
        
        self.assertFalse(result)
    
    def test_send_startup_command_short_response(self):
        """Test handling short response"""
        mock_client = Mock()
        mock_client.send_command.return_value = b'\x80\x01'
        
        result = send_startup_command(mock_client)
        
        self.assertFalse(result)


class TestMain(unittest.TestCase):
    """Test cases for main function"""
    
    @patch('test_runner.TPMClient')
    @patch('test_runner.send_startup_command')
    @patch('test_runner.initialize_tpm')
    @patch('test_runner.collect_files')
    @patch('sys.argv', ['test_runner.py', '--corpus', '/tmp/corpus'])
    @patch('sys.exit')
    def test_main_corpus_only(self, mock_exit, mock_collect, mock_init, 
                              mock_startup, mock_client_class):
        """Test main with corpus directory only"""
        # Setup mocks
        mock_file = Mock(spec=Path)
        mock_file.name = 'test.bin'
        mock_collect.return_value = [mock_file]
        
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.send_command.return_value = b'\x80\x01\x00\x00\x00\x0a\x00\x00\x00\x00'
        
        mock_init.return_value = True
        mock_startup.return_value = True
        
        with patch('builtins.open', mock_open(read_data=b'\x80\x01\x00\x00\x00\x0c')):
            main()
        
        mock_exit.assert_called_once_with(0)
        mock_client.close.assert_called_once()
    
    @patch('test_runner.collect_files')
    @patch('sys.argv', ['test_runner.py'])
    @patch('sys.exit')
    def test_main_no_directories(self, mock_exit, mock_collect):
        """Test main without corpus or crashes"""
        main()
        # Should exit with 1 when no directories provided
        self.assertIn(1, [call[0][0] for call in mock_exit.call_args_list])
    
    @patch('test_runner.TPMClient')
    @patch('test_runner.send_startup_command')
    @patch('test_runner.initialize_tpm')
    @patch('test_runner.collect_files')
    @patch('sys.argv', ['test_runner.py', '--corpus', '/tmp/corpus', '--crashes', '/tmp/crashes'])
    @patch('sys.exit')
    def test_main_with_failures(self, mock_exit, mock_collect, mock_init,
                                mock_startup, mock_client_class):
        """Test main with test failures"""
        mock_file = Mock(spec=Path)
        mock_file.name = 'test.bin'
        mock_collect.side_effect = [[mock_file], []]
        
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        # Failure response
        mock_client.send_command.return_value = b'\x80\x01\x00\x00\x00\x0a\x00\x00\x01\x00'
        
        mock_init.return_value = True
        mock_startup.return_value = True
        
        with patch('builtins.open', mock_open(read_data=b'\x80\x01\x00\x00\x00\x0c')):
            main()
        
        mock_exit.assert_called_once_with(1)
    
    @patch('test_runner.TPMClient')
    @patch('test_runner.send_startup_command')
    @patch('test_runner.initialize_tpm')
    @patch('test_runner.collect_files')
    @patch('sys.argv', ['test_runner.py', '--host', 'example.com', '--port', '9999', '--corpus', '/tmp/corpus'])
    @patch('sys.exit')
    def test_main_custom_host_port(self, mock_exit, mock_collect, mock_init,
                                   mock_startup, mock_client_class):
        """Test main with custom host and port"""
        mock_collect.return_value = []
        mock_init.return_value = True
        mock_startup.return_value = True
        
        main()
        
        mock_client_class.assert_called_once_with('example.com', 9999)
        mock_init.assert_called_once_with('example.com')


if __name__ == '__main__':
    unittest.main()
