#!/usr/bin/env python3
"""Tests for tpm_client.py"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import struct
from tpm_client import TPMClient


class TestTPMClient(unittest.TestCase):
    """Test cases for TPMClient class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.host = 'localhost'
        self.port = 2321
        self.client = TPMClient(self.host, self.port)
    
    def tearDown(self):
        """Clean up after tests"""
        if self.client.sock:
            self.client.close()
    
    def test_init(self):
        """Test TPMClient initialization"""
        self.assertEqual(self.client.host, self.host)
        self.assertEqual(self.client.port, self.port)
        self.assertEqual(self.client.timeout, 5.0)
        self.assertIsNone(self.client.sock)
    
    def test_init_with_custom_timeout(self):
        """Test TPMClient initialization with custom timeout"""
        client = TPMClient(timeout=10.0)
        self.assertEqual(client.timeout, 10.0)
    
    @patch('socket.socket')
    def test_connect(self, mock_socket):
        """Test connecting to TPM simulator"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        self.client.connect()
        
        mock_socket.assert_called_once()
        mock_sock.settimeout.assert_called_once_with(5.0)
        mock_sock.connect.assert_called_once_with((self.host, self.port))
        self.assertEqual(self.client.sock, mock_sock)
    
    def test_close(self):
        """Test closing connection"""
        mock_sock = Mock()
        self.client.sock = mock_sock
        
        self.client.close()
        
        mock_sock.close.assert_called_once()
        self.assertIsNone(self.client.sock)
    
    def test_close_when_not_connected(self):
        """Test closing when no connection exists"""
        self.client.sock = None
        self.client.close()  # Should not raise exception
        self.assertIsNone(self.client.sock)
    
    @patch('socket.socket')
    def test_send_command(self, mock_socket):
        """Test sending a command to TPM"""
        # Mock socket
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        # Mock response
        response_data = b'\x80\x01\x00\x00\x00\x0c\x00\x00\x00\x00'
        mock_sock.recv.side_effect = [
            struct.pack('>I', len(response_data)),  # Response length
            response_data,  # Response data (in chunks)
            struct.pack('>I', 0)  # Return code
        ]
        
        # Test command
        command = bytes([0x80, 0x01, 0x00, 0x00, 0x00, 0x0C,
                        0x00, 0x00, 0x01, 0x7B, 0x00, 0x10])
        
        response = self.client.send_command(command)
        
        # Verify connection was made
        mock_sock.connect.assert_called_once()
        
        # Verify command was sent correctly
        calls = mock_sock.sendall.call_args_list
        self.assertEqual(len(calls), 4)
        
        # Verify command type (SEND_COMMAND = 8)
        self.assertEqual(calls[0][0][0], struct.pack('>I', 8))
        
        # Verify locality (0)
        self.assertEqual(calls[1][0][0], struct.pack('B', 0))
        
        # Verify length
        self.assertEqual(calls[2][0][0], struct.pack('>I', len(command)))
        
        # Verify command data
        self.assertEqual(calls[3][0][0], command)
        
        # Verify response
        self.assertEqual(response, response_data)
    
    @patch('socket.socket')
    def test_recv_all(self, mock_socket):
        """Test receiving exact number of bytes"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        self.client.sock = mock_sock
        
        # Simulate receiving data in chunks
        mock_sock.recv.side_effect = [b'hello', b' ', b'world']
        
        result = self.client._recv_all(11)
        self.assertEqual(result, b'hello world')
    
    @patch('socket.socket')
    def test_recv_all_connection_closed(self, mock_socket):
        """Test handling connection closure during receive"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        self.client.sock = mock_sock
        
        # Simulate connection closure
        mock_sock.recv.return_value = b''
        
        with self.assertRaises(ConnectionError):
            self.client._recv_all(10)
    
    @patch('socket.socket')
    def test_context_manager(self, mock_socket):
        """Test using TPMClient as context manager"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        with TPMClient(self.host, self.port) as client:
            self.assertIsNotNone(client.sock)
            mock_sock.connect.assert_called_once()
        
        mock_sock.close.assert_called_once()
    
    @patch('socket.socket')
    def test_send_command_auto_connect(self, mock_socket):
        """Test that send_command connects if not already connected"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        # Mock response
        response_data = b'\x80\x01\x00\x00\x00\x0c\x00\x00\x00\x00'
        mock_sock.recv.side_effect = [
            struct.pack('>I', len(response_data)),
            response_data,
            struct.pack('>I', 0)
        ]
        
        self.assertIsNone(self.client.sock)
        
        command = bytes([0x80, 0x01, 0x00, 0x00, 0x00, 0x0C])
        self.client.send_command(command)
        
        mock_sock.connect.assert_called_once()
    
    @patch('socket.socket')
    def test_send_command_preserves_connection(self, mock_socket):
        """Test that send_command reuses existing connection"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        self.client.sock = mock_sock
        
        # Mock response
        response_data = b'\x80\x01\x00\x00\x00\x0c\x00\x00\x00\x00'
        mock_sock.recv.side_effect = [
            struct.pack('>I', len(response_data)),
            response_data,
            struct.pack('>I', 0)
        ]
        
        command = bytes([0x80, 0x01, 0x00, 0x00, 0x00, 0x0C])
        self.client.send_command(command)
        
        # Should not call connect again
        mock_sock.connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
