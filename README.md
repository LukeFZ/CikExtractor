# CikExtractor

*Utility to dump stored packed CIK (Content Integrity Key) data for MSIXVC packages from the registry. Additionally leverages emulation to derive your device encryption key to decrypt the CIKs for normal usage.*

## Disclaimer

**Warning: All keys derived and decrypted by this tool are sensitive information. You should never share a derived key with anyone, especially not your unique device key. This tool is for educational and research purposes only.**

## Requirements

- Windows 10+
- [.NET 6.0.x](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) installed
- Python 3 added to your PATH, along with the **[Qiling](https://github.com/qilingframework/qiling)** package installed
- Administrator privileges (for dumping the required registry keys)

## Usage

- Download the [latest release](https://github.com/LukeFZ/CikExtractor/releases/latest).
- Extract the downloaded zip file.
- Run *CikExtractor.exe*.

The derived device key will be printed to the console, and will also be saved to *deviceKey.txt* in the app directory.
Decrypted CIKs will be saved in the *Cik* subfolder.

## How to use the keys for decryption

You can use the generated *Cik* directory and the keys within with [xvdtool, by emoose.](https://github.com/emoose/xvdtool)
Example command:
```
// To decrypt (Note: will in-place-decrypt, so replacing the existing file):
./xvdtool.exe -nd -eu -cik "<cik-guid-here>" -cikfile "<path-to-.cik-file>" <path-to-msixvc-file>

// Then, to extract the files within:
./xvdtool.exe -nd -xf "<path-to-output-folder>" <path-to-decrypted-msixvc-file>
```

You can also use the derived device key to decrypt local XML licenses that contain keys directly, but that is not currently implemented.

## Special Thanks

- [XvddKeyslotUtil](https://github.com/billyhulbert/XvddKeyslotUtil), by billyhulbert
	- Inspired me to also look into how Windows handles CIKs and their storage/derivation.
- [Information about SystemPolicyInfo](https://github.com/KiFilterFiberContext/windows-software-policy), by KiFilterFiberContext
	- Their findings helped me to better understand the licensing flow and how all of the different parts work together, and their unpacking script inspired me to also use Qiling for the vault emulation.
- [xvdtool](https://github.com/emoose/xvdtool) and [this SPLicenseBlock struct](https://github.com/emoose/xbox-reversing/blob/master/templates/SPLicenseBlock.bt), both by emoose