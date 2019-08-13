# NxNandManager

NxNandManager is a command line (and GUI) utility for Windows 7 & 10,
the primary purpose of which is to copy, decrypt and encrypt Nintendo Switch content (full NAND or specific partition) from/to a file or physical drive.

![Png](http://laumonier.org/NxNandManager_v2.0.png)   

## Features   
- Full NAND backup & restore (BOOT0, BOOT1, RAWNAND)   
- Copy from/to specific partition (RAWNAND)    
- NAND decryption/encryption using bis keys    
- Option to wipe all console unique id's and certificates (a.k.a Incognito)   
- Display useful information about NAND file/drive (Firmware ver., exFat driver, S/N, etc.)   
- Enable/Disable auto RCM (BOOT0)  

## Compatibility

All dumps made with Hekate are supported by NxNandManager (and vice versa).  

NxNM also supports splitted dumps (such as SX OS's (emu)NAND dumps).      
Split filenames should be :   
```basename[00->99].(bin|.*)``` or ```basename[0->9].(bin|.*)``` or ```basename.[0->∝]```   
Set the first split file as input

## How to mount and open your Nintendo Switch's NAND ?

 1) Use [memloader](https://github.com/rajkosto/memloader) v3 to mount eMMC on your computer ([TegraRcmGUI](https://github.com/eliboa/TegraRcmGUI) provides an easy means to do it).   
 2) Open NxNandManager (CLI : add argument --list to list all available physical drives, GUI : File > Open drive).   
 3) Select the mounted drive. You can now perform backup/restore operations.   

![Png](http://laumonier.org/switch/NxNandManager_v1.1_howto_open_drive.png)   

## CLI Usage

```NxNandManager.exe [--list] [--info] [--enable_autoRCM] [--disable_autoRCM] -i inputFilename|\\.\PhysicalDriveX [-o outputFilename|\\.\PhysicalDriveX] [-part=nxPartitionName] [lFlags]```

Arguments | Description 
--------- | -----------
-i | Path to input file or physical drive 
-o | Path to output file or physical drive 
-part= | Partition to copy (apply to both input & output if possible)<br />Possible values are PRODINFO, PRODINFOF, SAFE, SYSTEM, USER,<br />BCPKG2-2-Normal-Sub, BCPKG2-3-SafeMode-Main, etc. (see --info)
-d | Decrypt content (-keyset mandatory) 
-e | Encrypt content (-keyset mandatory) 
-keyset | Path to keyset file (bis keys) 
--gui | Launch graphical user interface (optional) 
--info | Display information about input/output (depends on NAND type): <br/>NAND type, partitions, encryption, autoRCM status...<br />...more info when -keyset provided: firmware ver., S/N, last boot date
--list | List compatible physical drives`
--incognito | Wipe all console unique id's and certificates from CAL0 (a.k.a incognito)<br />Only apply to input type RAWNAND or PRODINFO partition
--enable_autoRCM | Enable auto RCM. -i must point to a valid BOOT0 file/drive 
--disable_autoRCM | Disable auto RCM. -i must point to a valid BOOT0 file/drive


Flags | Description
------ | -----------
BYPASS_MD5SUM | Used to by-pass all md5 verifications<br/>Dump/Restore is faster but less secure
FORCE | Program will never prompt for user confirmation


## Examples

### Dump full NAND to file

- From physical drive (you first need to mount NX eMMC with [memloader](https://github.com/rajkosto/memloader) (via [TegraRcmGUI](https://github.com/eliboa/TegraRcmGUI) for ex) :  
```.\NxNandManager.exe -i \\.\PhysicalDrive3 -o "C:\Users\Public\NAND dump\rawnand.bin" ```

- From existing dump file :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o D:\rawnand2.bin ```


### Dump specific partition to file

- Dump SYSTEM partition from physical drive :  
```.\NxNandManager.exe -i \\.\PhysicalDrive3 -o "C:\Users\Public\NAND dump\SYSTEM.bin" -part=SYSTEM```

- Extract PRODINFOF partition from existing dump file :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o D:\PRODINFOF.bin -part=PRODINFOF```


### Restore NAND dump

- Restore full raw NAND to physical drive :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o \\.\PhysicalDrive3```

- Restore full splitted raw NAND to physical drive :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\full00.bin" -o \\.\PhysicalDrive3```

- Restore specific partition to physical drive :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o \\.\PhysicalDrive3 -part=PRODINFO```  
or  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\PRODINFO" -o \\.\PhysicalDrive3 -part=PRODINFO```

### Copy partition from file to rawNand file

- Copy specific partition from rawNand file :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o "C:\Users\Public\NAND dump\rawnand2.bin" -part=BCPKG2-1-Normal-Main```  

- Copy specific partition from partition file :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\BCPKG2-1-Normal-Main" -o "C:\Users\Public\NAND dump\rawnand2.bin" -part=BCPKG2-1-Normal-Main```  

### Decryption / Encryption

- Decrypt full rawnand :   
```NxNandManager.exe -i rawnand.bin -o rawnand.dec -d -keyset keys.dat```

- Decrypt single partition file :   
```NxNandManager.exe -i PRODINFO -o PRODINFO.dec -d -keyset keys.dat```

- Encrypt single partition file :   
```NxNandManager.exe -i PRODINFO.dec -o PRODINFO.enc -e -keyset keys.dat```

- Decrypt & restore single partition file to physical drive   
```NxNandManager.exe -i PRODINFO.dec -o \\.\PhysicalDrive3 -part=PRODINFO -e -keyset keys.dat```

- Encrypt & restore full rawnand   
```NxNandManager.exe -i rawnand.dec -o \\.\PhysicalDrive3 -e -keyset keys.dat```


## Build

### CLI : MinGW (recommended if not using Visual Studio), MSYS and MSYS2 with GCC

**Dependency :** [OpenSSL](https://www.openssl.org/source/). You can grab my own pre-compiled binaries for mingw32/64 [here](https://drive.google.com/open?id=1lG_h82EfO-EGe0co7eip2WGkmOTv5zdQ).

```
git clone https://github.com/eliboa/NxNandManager   
cd NxNandManager/NxNandManager
make
```

**Note :** Line ```#define ENABLE_GUI``` of "NxNandManager.h" file has to be commented

### CLI + GUI (Qt) : MinGW64, MSVC

**Dependency :** [Qt](https://www.qt.io/download), [OpenSSL](https://www.openssl.org/source/)

QtCreator : Use ```NxNandManager/NxNandManager.pro``` project file

Visual Studio ([Qt Visual Studio Tools](https://marketplace.visualstudio.com/items?itemName=TheQtCompany.QtVisualStudioTools-19123) needed) :  Use ```NxNandManager.sln``` solution file


## Credits

- Special thanks to [shadow256](https://github.com/shadow2560) without whom this work would not have been possible
- rajkosto for his amazing work on [memloader](https://github.com/rajkosto/memloader).
- CTCaer's [hekate](https://github.com/CTCaer/hekate), which I borrowed a few pieces of code
- MCMrARM for [switch_decrypt](https://github.com/MCMrARM/switch_decrypt)
- blawar for [incognito](https://github.com/blawar/incognito)   
- shchmue for [Firmware Version Inspector](https://github.com/shchmue/FVI)