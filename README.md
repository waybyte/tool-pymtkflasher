# MT6261/MT2503 Flash Tool
Python based flash tool for Mediatek MT6261 and MT2503 SoC.

# Usage

```
usage: mtkflasher.py [-h] -p PORT [-b BAUD] [-o OPT] [-n] [-v] firmware [firmware ...]

MT6261/MT2503 Flash Tool

positional arguments:
  firmware              Firmware binary file.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Serial port for flashing. (default: None)
  -b BAUD, --baud BAUD  Serial port baudrate. (default: 460800)
  -o OPT, --opt OPT     Flash Options:
                            0: Download Firmware and Format
                            1: Download Firmware only (default: 1)
  -n, --no-reset        Do not reset after flashing (default: False)
  -v, --version         show program's version number and exit
```

## Credits
Georgi Angelov (@Wiz-IO) for initial work  
Anton Rieckert (@alrieckert) for pre-format fix
