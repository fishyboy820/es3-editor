# EasySave3 Python Tool

A command-line Python tool for encrypting and decrypting EasySave3 save files.

## Installation

1. Install Python 3.6 or higher
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Analyze a save file
```bash
python easysave3_tool.py analyze savefile.txt
python easysave3_tool.py analyze savefile.txt -p "password123"
```

### Decrypt a save file
```bash
# Decrypt with password
python easysave3_tool.py decrypt encrypted_save.txt decrypted.json -p "t36gref9u84y7f43g"

# Decrypt without password (gzip only)
python easysave3_tool.py decrypt compressed_save.txt decrypted.json
```

### Encrypt a save file
```bash
# Encrypt with password only
python easysave3_tool.py encrypt decrypted.json encrypted_save.txt -p "t36gref9u84y7f43g"

# Encrypt with password and gzip compression
python easysave3_tool.py encrypt decrypted.json encrypted_save.txt -p "t36gref9u84y7f43g" --gzip
```

### List known game passwords
```bash
python easysave3_tool.py passwords
```

## Known Game Passwords

The tool includes passwords for these games:
- Phasmophobia: `t36gref9u84y7f43g`
- Lethal Company: `lcslime14a5`
- Strike Force Heroes: `6tr cr$#@%T#GFTVn`
- Brewpub Simulator: `browar23`
- And many more...

## File Format Detection

The tool automatically detects:
- **Unencrypted JSON** - Plain text save files
- **GZip compressed only** - Compressed but not encrypted
- **Encrypted only** - Encrypted but not compressed  
- **Encrypted + GZip compressed** - Both encrypted and compressed
- **Unknown format** - Unrecognized file format

## Examples

```bash
# Analyze a Phasmophobia save file
python easysave3_tool.py analyze SaveFile.txt -p "t36gref9u84y7f43g"

# Decrypt it
python easysave3_tool.py decrypt SaveFile.txt SaveFile_decrypted.json -p "t36gref9u84y7f43g"

# Edit the JSON file manually, then re-encrypt
python easysave3_tool.py encrypt SaveFile_decrypted.json SaveFile_new.txt -p "t36gref9u84y7f43g" --gzip
```

## Technical Details

- **Encryption**: AES-128-CBC
- **Key Derivation**: PBKDF2 with SHA1, 100 iterations
- **IV**: Random 16 bytes, prepended to encrypted data
- **Padding**: PKCS7
- **Compression**: Standard gzip

## Disclaimer

This tool is not affiliated with EasySave3 or Moodkie Interactive. Use at your own risk and always backup your save files before editing.