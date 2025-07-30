#!/usr/bin/env python3
"""
EasySave3 Save File Encryption/Decryption Tool
A Python command-line tool for encrypting and decrypting EasySave3 save files.
"""

import argparse
import gzip
import json
import os
import sys
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes


class SaveFileAnalyzer:
    """Analyzes save file format and encryption status."""
    
    @staticmethod
    def is_gzip(data):
        """Check if data starts with gzip magic bytes."""
        return len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B
    
    @staticmethod
    def is_json(data):
        """Check if data is valid JSON."""
        try:
            json.loads(data.decode('utf-8'))
            return True
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
    
    @classmethod
    def analyze_save_file(cls, data, password=None):
        """
        Analyze save file format and return status information.
        
        Args:
            data (bytes): Raw file data
            password (str): Optional password for decryption test
            
        Returns:
            dict: Analysis results with keys: encrypted, gzipped, status
        """
        if not data:
            return {"encrypted": False, "gzipped": False, "status": "No data"}
        
        # Check if it's already JSON
        if cls.is_json(data):
            return {"encrypted": False, "gzipped": False, "status": "Unencrypted JSON"}
        
        # Check if it's gzipped
        if cls.is_gzip(data):
            return {"encrypted": False, "gzipped": True, "status": "GZip compressed only"}
        
        # If we have a password, try to decrypt and analyze
        if password:
            try:
                iv = data[:16]
                key = PBKDF2(password, iv, 16, count=100, hmac_hash_module=SHA1)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(data[16:])
                
                # Remove PKCS7 padding
                padding_length = decrypted[-1]
                decrypted = decrypted[:-padding_length]
                
                if cls.is_gzip(decrypted):
                    return {"encrypted": True, "gzipped": True, "status": "Encrypted + GZip compressed"}
                elif cls.is_json(decrypted):
                    return {"encrypted": True, "gzipped": False, "status": "Encrypted only"}
                else:
                    return {"encrypted": True, "gzipped": False, "status": "Encrypted (unknown format)"}
            except Exception:
                return {"encrypted": True, "gzipped": False, "status": "Encrypted (wrong password?)"}
        
        return {"encrypted": False, "gzipped": False, "status": "Unknown format"}


class EasySave3Tool:
    """Main tool class for EasySave3 save file operations."""
    
    def __init__(self):
        self.known_passwords = {
            "Phasmophobia": "t36gref9u84y7f43g",
            "Lethal Company": "lcslime14a5",
            "Strike Force Heroes": "6tr cr$#@%T#GFTVn",
            "Brewpub Simulator": "browar23",
            "DOJO NTR": "wanzg!1f**k",
            "Virtual Succubus": "VSPassword1",
            "NIGHT-RUNNERS PROLOGUE": "15IiJlm7~W",
            "Supermarket Together": "g#asojrtg@omos)^yq",
            "Othercide": "sajdkfSecretzaslkjlh",
            "Blue Prince Demo": "s1lencefoll0wzthoseNthe5hall0wz110inF0Gw3areL0stNf1reWEareFOUND",
            "SULFUR": "h!9VLSj*cDyrR!WK^iBcN3dLooLrXq3m",
            "R.E.P.O.": "Why would you want to cheat?... :o It's no fun. :') :'D"
        }
    
    def decrypt_save_file(self, input_file, output_file, password=None):
        """
        Decrypt a save file.
        
        Args:
            input_file (str): Path to encrypted save file
            output_file (str): Path for decrypted output
            password (str): Decryption password (optional)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            
            print(f"Analyzing file: {input_file}")
            analysis = SaveFileAnalyzer.analyze_save_file(data, password)
            print(f"Status: {analysis['status']}")
            
            # Process the data based on analysis
            processed_data = data
            
            # Decrypt if password provided and file appears encrypted
            if password and analysis['encrypted']:
                try:
                    iv = data[:16]
                    key = PBKDF2(password, iv, 16, count=100, hmac_hash_module=SHA1)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(data[16:])
                    
                    # Remove PKCS7 padding
                    padding_length = decrypted[-1]
                    processed_data = decrypted[:-padding_length]
                    print("✓ Decryption successful")
                except Exception as e:
                    print(f"✗ Decryption failed: {e}")
                    return False
            
            # Decompress if gzipped
            if SaveFileAnalyzer.is_gzip(processed_data):
                try:
                    processed_data = gzip.decompress(processed_data)
                    print("✓ Decompression successful")
                except Exception as e:
                    print(f"✗ Decompression failed: {e}")
                    return False
            
            # Write output
            with open(output_file, 'wb') as f:
                f.write(processed_data)
            
            print(f"✓ Decrypted file saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"✗ Error processing file: {e}")
            return False
    
    def encrypt_save_file(self, input_file, output_file, password=None, use_gzip=False):
        """
        Encrypt a save file.
        
        Args:
            input_file (str): Path to plaintext save file
            output_file (str): Path for encrypted output
            password (str): Encryption password (optional)
            use_gzip (bool): Whether to compress with gzip
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            
            print(f"Processing file: {input_file}")
            processed_data = data
            
            # Compress if requested
            if use_gzip:
                try:
                    processed_data = gzip.compress(processed_data)
                    print("✓ Compression successful")
                except Exception as e:
                    print(f"✗ Compression failed: {e}")
                    return False
            
            # Encrypt if password provided
            if password:
                try:
                    # Generate random IV
                    iv = get_random_bytes(16)
                    key = PBKDF2(password, iv, 16, count=100, hmac_hash_module=SHA1)
                    
                    # Add PKCS7 padding
                    padding_length = 16 - (len(processed_data) % 16)
                    processed_data += bytes([padding_length] * padding_length)
                    
                    # Encrypt
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    encrypted = cipher.encrypt(processed_data)
                    
                    # Prepend IV
                    processed_data = iv + encrypted
                    print("✓ Encryption successful")
                except Exception as e:
                    print(f"✗ Encryption failed: {e}")
                    return False
            
            # Write output
            with open(output_file, 'wb') as f:
                f.write(processed_data)
            
            print(f"✓ Encrypted file saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"✗ Error processing file: {e}")
            return False
    
    def analyze_file(self, input_file, password=None):
        """
        Analyze a save file and display information.
        
        Args:
            input_file (str): Path to save file
            password (str): Optional password for analysis
        """
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            
            analysis = SaveFileAnalyzer.analyze_save_file(data, password)
            
            print(f"\n=== File Analysis: {input_file} ===")
            print(f"File size: {len(data)} bytes")
            print(f"Status: {analysis['status']}")
            print(f"Encrypted: {'Yes' if analysis['encrypted'] else 'No'}")
            print(f"Compressed: {'Yes' if analysis['gzipped'] else 'No'}")
            
            if analysis['encrypted'] and not password:
                print("\nNote: File appears encrypted but no password provided for full analysis.")
            
        except Exception as e:
            print(f"✗ Error analyzing file: {e}")
    
    def list_known_passwords(self):
        """Display known game passwords."""
        print("\n=== Known Game Passwords ===")
        for game, password in self.known_passwords.items():
            print(f"{game:<25} : {password}")
        print("\nTip: Use these passwords with the -p/--password option")
    
    def run(self):
        """Main entry point for the tool."""
        parser = argparse.ArgumentParser(
            description="EasySave3 Save File Encryption/Decryption Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Analyze a save file
  python easysave3_tool.py analyze savefile.txt

  # Decrypt a save file
  python easysave3_tool.py decrypt savefile.txt decrypted.json -p "t36gref9u84y7f43g"

  # Encrypt a save file with compression
  python easysave3_tool.py encrypt decrypted.json encrypted.txt -p "t36gref9u84y7f43g" --gzip

  # List known passwords
  python easysave3_tool.py passwords
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze save file format')
        analyze_parser.add_argument('input', help='Input save file')
        analyze_parser.add_argument('-p', '--password', help='Password for analysis')
        
        # Decrypt command
        decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt save file')
        decrypt_parser.add_argument('input', help='Input encrypted file')
        decrypt_parser.add_argument('output', help='Output decrypted file')
        decrypt_parser.add_argument('-p', '--password', help='Decryption password')
        
        # Encrypt command
        encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt save file')
        encrypt_parser.add_argument('input', help='Input plaintext file')
        encrypt_parser.add_argument('output', help='Output encrypted file')
        encrypt_parser.add_argument('-p', '--password', help='Encryption password')
        encrypt_parser.add_argument('--gzip', action='store_true', help='Compress with gzip')
        
        # Passwords command
        subparsers.add_parser('passwords', help='List known game passwords')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        if args.command == 'analyze':
            self.analyze_file(args.input, args.password)
        elif args.command == 'decrypt':
            success = self.decrypt_save_file(args.input, args.output, args.password)
            sys.exit(0 if success else 1)
        elif args.command == 'encrypt':
            success = self.encrypt_save_file(args.input, args.output, args.password, args.gzip)
            sys.exit(0 if success else 1)
        elif args.command == 'passwords':
            self.list_known_passwords()


if __name__ == '__main__':
    tool = EasySave3Tool()
    tool.run()