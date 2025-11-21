
import argparse
import sys
from pathlib import Path
from tpm_client import TPMClient 
import socket
import struct

def run_test(client, test_file):
    """Run single test file against TPM"""
    with open(test_file, 'rb') as f:
        cmd = f.read()
    
    if not cmd:
        return None
        
    try:
        response = client.send_command(cmd)
        # Check response code (bytes 6-10)
        if len(response) >= 10:
            rc = int.from_bytes(response[6:10], 'big')
            return {'file': test_file.name, 'rc': rc, 'success': rc == 0}
        return {'file': test_file.name, 'rc': None, 'success': False}
    except Exception as e:
        return {'file': test_file.name, 'error': str(e), 'success': False}

def collect_files(directory):
    """Get all test files from directory"""
    if not directory or not directory.exists():
        return []
    return sorted([f for f in directory.iterdir() if f.is_file()])

def initialize_tpm(host, platform_port=2322):
    """Initialize TPM via platform commands"""
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, platform_port))
        
        # Send Power On (command 1) and NV On (command 11)
        for cmd in [1, 11]:
            sock.sendall(struct.pack('>I', cmd))
            sock.recv(4)  # Ignore response
        
        sock.close()
        return True
    except Exception as e:
        print(f"Warning: Could not initialize TPM platform: {e}")
        return False

def send_startup_command(client):
    """Send TPM2_Startup(TPM_SU_CLEAR) command"""
    # TPM2_Startup(TPM_SU_CLEAR): tag=8001, size=0c, cmd=0144, param=0000
    startup_cmd = bytes([0x80, 0x01, 0x00, 0x00, 0x00, 0x0C,
                         0x00, 0x00, 0x01, 0x44, 0x00, 0x00])
    try:
        response = client.send_command(startup_cmd)
        if len(response) >= 10:
            rc = int.from_bytes(response[6:10], 'big')
            return rc == 0 or rc == 0x100  # Success or already initialized
    except Exception as e:
        print(f"Warning: TPM2_Startup failed: {e}")
    return False

def main():
    parser = argparse.ArgumentParser(description='Run TPM tests')
    parser.add_argument('--host', default='localhost', help='TPM host')
    parser.add_argument('--port', type=int, default=2321, help='TPM port')
    parser.add_argument('--corpus', type=Path, help='Corpus directory')
    parser.add_argument('--crashes', type=Path, help='Crashes directory')
    args = parser.parse_args()
    
    if not args.corpus and not args.crashes:
        print("Error: Need --corpus or --crashes")
        sys.exit(1)
    
    # Initialize TPM
    print("Initializing TPM...")
    initialize_tpm(args.host)
    
    # Collect test files
    corpus_files = collect_files(args.corpus)
    crash_files = collect_files(args.crashes)
    
    print(f"Found {len(corpus_files)} corpus, {len(crash_files)} crash files")
    
    # Run tests
    client = TPMClient(args.host, args.port)
    
    # Send startup command
    if not send_startup_command(client):
        print("Warning: TPM startup may have failed")
    
    results = []
    
    for f in corpus_files + crash_files:
        result = run_test(client, f)
        if result:
            results.append(result)
            status = "PASS" if result['success'] else "FAIL"
            # color output: green PASS, red FAIL, yellow for errors
            if result.get('success'):
                color = '\033[32m'
            elif result.get('error'):
                color = '\033[33m'
            else:
                color = '\033[31m'
            reset = '\033[0m'
            print(f"{result['file']}: {color}{status}{reset}")
    
    client.close()
    
    # Summary
    passed = sum(1 for r in results if r['success'])
    print(f"\n{passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)

if __name__ == '__main__':
    main()
