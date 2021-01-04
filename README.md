# Total Commander FTP Password Recovery Tool

[Total Commander](https://www.ghisler.com/) (formerly known as ~~
Windows Commander~~) is a classic file manager for Windows, Windows CE, Windows Phone, and now also Android.

Total Commander has a built-in FTP/FXP client and it keeps the FTP logins and encrypted passwords in **wcx_ftp.ini** configuration file.

![Total Commander FTP Password Recovery Tool](https://www.pelock.com/img/en/products/total-commander-ftp-password-recovery/total-commander-ftp-password-recovery.png
 "Total Commander FTP Password Recovery Tool")

The use of reverse engineering allowed to [recover password encryption algorithm source code](https://www.pelock.com/services/source-code-recovery).

## Total Commander Password Decoder Algorithm

I have [reverse engineered](https://www.pelock.com/services) and recreated the password decoding algorithm years ago.

It was made available by me to another [FlashFXP](https://www.flashfxp.com/) software to import FTP connection profiles from Total Commander.

I give you source codes for both the original assembly decoding algorithm and a PHP implementation of this algorithm.

## Total Commander Online Decoder

You can either use one of the provided source codes or use my own online implementation to make things faster:

https://www.pelock.com/products/total-commander-ftp-password-recovery

