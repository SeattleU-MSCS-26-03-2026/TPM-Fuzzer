#!/usr/bin/env python3
"""Minimal TPM simulator client using mssim protocol"""

import socket
import struct

class TPMClient:
    def __init__(self, host='localhost', port=2321, timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        
    def connect(self):
        """Connect to TPM simulator"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        
    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            self.sock = None
            
    def send_command(self, command_bytes):
        """Send TPM command, return response"""
        if not self.sock:
            self.connect()
            
        # mssim protocol: command_type(4) + locality(1) + length(4) + data
        self.sock.sendall(struct.pack('>I', 8))  # Command type: SEND_COMMAND
        self.sock.sendall(struct.pack('B', 0))   # Locality: 0
        self.sock.sendall(struct.pack('>I', len(command_bytes)))
        self.sock.sendall(command_bytes)
        
        # Response: length(4) + data + return_code(4)
        resp_len = struct.unpack('>I', self.sock.recv(4))[0]
        response = self._recv_all(resp_len)
        self.sock.recv(4)  # Return code (ignore for now)
        
        return response
    
    def _recv_all(self, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, *args):
        self.close()


if __name__ == "__main__":
    # Quick test
    with TPMClient() as client:
        # TPM2_GetRandom(16 bytes)
        cmd = bytes([0x80, 0x01, 0x00, 0x00, 0x00, 0x0C,
                     0x00, 0x00, 0x01, 0x7B, 0x00, 0x10])
        response = client.send_command(cmd)
        print(f"Response: {response.hex()}")
