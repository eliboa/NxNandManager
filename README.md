# NxNandManager

![Png](http://laumonier.org/switch/NxNandManager4.0b_00.png)

## What can this program do ?

- Backup or restore any Switch's NAND (file or drive) => full sysNAND, full emuNAND, boot partitions or user partitions.
- Encrypt or decrypt native encrypted partition (PRODINFO, PRODINFOF, SAFE, SYTEM & USER) using BIS keys.
- Resize your NAND (USER partition only).
- Retrieve and display useful information about NAND file/drive (Firmware version, device ID, exFat driver, S/N, etc.) using BIS keys
- Splitted dumps are fully supported (backup & restore). However the program cannot split an existing dump nor can it split the output file in any case.
- Option to wipe console unique ids and certificates (a.k.a Incognito) from PRODINFO
- Enable/Disable auto RCM (BOOT0)
- Create emuNAND (file or partition based) from any NAND image (RAWNAND or FULL NAND)   
![Png](http://laumonier.org/switch/NxNandManager4.0b_03.png)
- "Advanced copy" feature (passthrough zeroes, split output, zip output, etc.)   
![Png](http://laumonier.org/switch/NxNandManager4.0b_02.png)

## Supported file format

It should be noted that the program does not check the file extension to detect if a file is supported or not. It'll look for specific signature inside binary data (magic number) when possible. If the file is fully encrypted, the program will detect the type by inspecting the filename  (without extension) and the file size. Therefore, a single partition file (encrypted) should be named after the partition name ("SAFE.bin", "SAFE.enc" or "SAFE.whatever" will work, "SAFE_01.bin" will not).

## Supported drives

NxNandManager can detect physical drives that contains a valid NAND (or partition) such as memloader drives (tool for mounting Nintendo Switch's NAND on a computer) or SD card containing an emuNAND partition (SX OS hidden partition or emuMMC partition).

## How to mount and open your Nintendo Switch's NAND (GUI) ?

### sysNAND or emuNAND (via Hekate)
 1) Launch Hekate/Nyx (v5.2+) on your Nintendo Switch. Navigate to Tools > USB Tools    
 2) Either select "eMMC RAW GPP" (sysNand) or "emu RAW GPP" (emuNAND) to mount your NAND on your computer (you can mount BOOT0/BOOT1 separately). Set "Read-Only" to OFF if you want to perform restore operations.   
 3) Open NxNandManager then open new drive (CTRL + D).   
 3) Select the mounted drive. You can now perform backup/restore operations.   
   
### emuNAND (partition)
 1) Mount the SD card containing emuNAND on your computer
 2) Open NxNandManager then open new drive (CTRL + D).
 3) Select the drive labelled "FULL NAND".
 
### emuNAND (files)
 1) Mount the SD card containing emuNAND on your computer
 2) Open NxNandManager then open new file (CTRL + O).
 3) Open the first split file of your emuNAND (i.e "sdmmc:\emuMMC\SD00\eMMC\00" for emuMMC or "sdmmc:\sxos\emunand\full.00.bin" for SX OS's emuNAND)

## NxStorage types

The following types are supported by NxNandManager :   

Type | Description | Can be restored from
---- | ----------- | --------------------
BOOT0 | BOOT0 partition (single file) | BOOT0<br />or<br />FULL NAND (partial restore)
BOOT1 | BOOT1 partition (single file) | BOOT1<br />or<br />FULL NAND (partial restore)
PRODINFO | PRODINFO partition (single file).<br />Also known as "CAL0" | PRODINFO <br />or<br /> FULL NAND, RAWNAND (partial restore)
PRODINFOF | PRODINFO partition (single file) | PRODINFOF <br />or<br />FULL NAND, RAWNAND (partial restore)
BCPKG2-1-Normal-Main | BCPKG2-1-Normal-Main partition (single file) | BCPKG2-1-Normal-Main<br />or<br />FULL NAND, RAWNAND (partial restore)
BCPKG2-2-Normal-Sub | BCPKG2-2-Normal-Sub partition (single file) | BCPKG2-2-Normal-Sub<br />or<br />FULL NAND, RAWNAND (partial restore)
BCPKG2-3-SafeMode-Main | BCPKG2-3-SafeMode-Main partition (single file) | BCPKG2-3-SafeMode-Main<br />or<br />FULL NAND, RAWNAND (partial restore)
BCPKG2-4-SafeMode-Sub | BCPKG2-4-SafeMode-Sub partition (single file) | BCPKG2-4-SafeMode-Sub<br />or<br />FULL NAND, RAWNAND (partial restore)
BCPKG2-5-Repair-Main | BCPKG2-5-Repair-Main partition (single file) | BCPKG2-5-Repair-Main<br />or<br />FULL NAND, RAWNAND (partial restore)
BCPKG2-6-Repair-Sub | BCPKG2-6-Repair-Sub partition (single file) | BCPKG2-6-Repair-Sub partition<br />or<br />FULL NAND, RAWNAND (partial restore)
SAFE | SAFE partition (single file) | SAFE<br />or<br />FULL NAND, RAWNAND (partial restore)
SYSTEM | SYSTEM partition (single file) | SYSTEM<br />or<br />FULL NAND, RAWNAND (partial restore)
USER | USER partition (single file) | USER<br />or<br />FULL NAND, RAWNAND (partial restore)
RAWNAND | RAWNAND contains: <br />- GPT (partition table)<br />- PRODINFO<br />- PRODINFOF<br />- BCPKG2-1-Normal-Main<br />- BCPKG2-2-Normal-Sub<br />- BCPKG2-3-SafeMode-Main<br />- BCPKG2-4-SafeMode-Sub<br />- BCPKG2-5-Repair-Main<br />- BCPKG2-6-Repair-Sub<br />- SAFE<br />- SYSTEM<br />- USER<br />- GPT backup | RAWNAND<br />or<br />FULL NAND<br />or<br />any valid partition (partial restore)
FULL NAND | FULL NAND contains: <br />- BOOT0<br />- BOOT1<br />- GPT (partition table)<br />- PRODINFO<br />- PRODINFOF<br />- BCPKG2-1-Normal-Main<br />- BCPKG2-2-Normal-Sub<br />- BCPKG2-3-SafeMode-Main<br />- BCPKG2-4-SafeMode-Sub<br />- BCPKG2-5-Repair-Main<br />- BCPKG2-6-Repair-Sub<br />- SAFE<br />- SYSTEM<br />- USER<br />- GPT backup | FULL NAND<br />or<br />RAWNAND (partial restore)<br />or<br />any valid partition (partial restore)


## How long does it take to backup or restore NAND ?

Well, obviously, performance depends greatly on hardware/drive limitations. For example, if you're doing backup/restore operations on a drive mounted through "memloader", the transfer speed will be very slow, due to memloader limitations.

That said, the transfer rate will be reduced if you choose to encrypt or decrypt data. Data integrity validation (MD5 hash) can also affect the tranfer rate.

## Compatibility

All dumps made with Hekate are supported by NxNandManager (and vice versa).  

NxNandManager also supports splitted dumps (such as SX OS's (emu)NAND dumps).      
Split filenames should be :   
```basename[00->99].(bin|.*)``` or ```basename[0->9].(bin|.*)``` or ```basename.[0->∝]```   
Set the first split file as input

## CLI Usage

```NxNandManager.exe [--list] -i inputFilename|\\.\PhysicalDriveX [-o outputFilename|\\.\PhysicalDriveX] [-part=nxPartitionName]  [--info] [--enable_autoRCM] [--disable_autoRCM] [--incognito] [-user_resize=n] [Flags]```

Arguments | Description 
--------- | -----------
-i | Path to input file or physical drive. <br />input must be a valid NxStorage type (RAWNAND, FULL NAND, BOOT0, BOOT1, SYSTEM, etc)
-o | Path to output file or physical drive <br />If output is a valide NxStorage, the program will restore output from input
-part= | Partition(s) to copy (apply to both input & output if possible)<br />Use a comma (\",\") separated list to provide multiple partitions<br />Possible values are PRODINFO, PRODINFOF, SAFE, SYSTEM, USER, BCPKG2-2-Normal-Sub, BCPKG2-3-SafeMode-Main, etc. (see --info)<br />You can use "-part=RAWNAND" to dump RAWNAND from input type FULL NAND
-d | Decrypt content (-keyset mandatory).<br />Only applies to RAWNAND, FULL NAND, PRODINFO, PRODINFOF, SAFE, SYSTEM & USER
-e | Encrypt content (-keyset mandatory).<br />Only applies to RAWNAND, FULL NAND, PRODINFO, PRODINFOF, SAFE, SYSTEM & USER
-keyset | Path to a file containing bis keys.
-user_resize= | Size in Mb for new USER partition in output.<br />Only applies to input type RAWNAND or FULL NAND<br />Use FORMAT_USER flag to format partition during copy<br />GPT and USER's FAT will be modified<br /> output (-o) must be a new file
--gui | Launch graphical user interface (optional) 
--info | Display information about input/output (depends on NAND type): <br/>NAND type, partitions, encryption, autoRCM status...<br />...more info when -keyset provided: firmware ver., S/N, device ID, ...
--list | List compatible physical drives`
--incognito | Wipe all console unique ids and certificates from CAL0 (a.k.a incognito)<br />Only apply to input type RAWNAND or PRODINFO partition
--enable_autoRCM | Enable auto RCM. -i must point to a valid BOOT0 file/drive 
--disable_autoRCM | Disable auto RCM. -i must point to a valid BOOT0 file/drive

Flag | Description
------ | -----------
BYPASS_MD5SUM | Used to by-pass all md5 verifications<br/>Dump/Restore is faster but less secure
FORCE | Program will never prompt for user confirmation
FORMAT_USER | To format USER partition (-user_resize arg mandatory)


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

### NAND decryption/encryption (AES-XTS)

NxNandManager can decrypt or encrypt NAND file/drive (rawnand or encrypted partition file "PRODINFO", "SAFE", "SYSTEM", etc).   
A keyset file containing biskeys must be provided.

Use ```-d``` argument to decrypt, ```-e``` to encrypt. 

Keys can be provided by the ```-keyset``` argument to the keyset filename.   
The program can parse keyset files made with biskeydump or lockpick :
```
   BIS Key 0 (crypt): <16-byte hex key>
   BIS Key 0 (tweak): <16-byte hex key>
   ...
```
or
```
   bis_key_00 = <32-byte hex key>
   bis_key_01 = <32-byte hex key>
   ...
```

When -keyset and --info arguments are provided, the program can also retrieve some useful information, such as firmware version, exFat driver, last boot time, etc.   

#### Examples
Decrypt full rawnand :   
```NxNandManager.exe -i rawnand.bin -o rawnand.dec -d -keyset keys.dat```

Decrypt single partition file :   
```NxNandManager.exe -i PRODINFO -o PRODINFO.dec -d -keyset keys.dat```

Encrypt single partition file :   
```NxNandManager.exe -i PRODINFO.dec -o PRODINFO.enc -e -keyset keys.dat```

Decrypt & restore single partition file to physical drive   
```NxNandManager.exe -i PRODINFO.dec -o \\.\PhysicalDrive3 -part=PRODINFO -e -keyset keys.dat```

Encrypt & restore full rawnand   
```NxNandManager.exe -i rawnand.dec -o \\.\PhysicalDrive3 -e -keyset keys.dat```

## Build

### CLI : MinGW

**Dependency :** [OpenSSL](https://www.openssl.org/source/). You can grab my own pre-compiled binaries for mingw32/64 [here](https://drive.google.com/open?id=1lG_h82EfO-EGe0co7eip2WGkmOTv5zdQ).

```
git clone https://github.com/eliboa/NxNandManager   
cd NxNandManager/NxNandManager
make
```

**Note :** Line ```#define ENABLE_GUI``` of "NxNandManager.h" file has to be commented

### CLI + GUI (Qt) : MinGW

**Dependency :** [Qt](https://www.qt.io/download), [OpenSSL](https://www.openssl.org/source/)

QtCreator : Use ```NxNandManager/NxNandManager.pro``` project file

## Credits

- Special thanks to [shadow256](https://github.com/shadow2560) without whom this work would not have been possible
- rajkosto for his amazing work on [memloader](https://github.com/rajkosto/memloader).
- CTCaer's [hekate](https://github.com/CTCaer/hekate), which I borrowed a few pieces of code
- MCMrARM for [switch_decrypt](https://github.com/MCMrARM/switch_decrypt)
- blawar for [incognito](https://github.com/blawar/incognito)   
- shchmue for [Firmware Version Inspector](https://github.com/shchmue/FVI)
