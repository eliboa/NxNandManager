# NxNandManager

NxNandManager is a command line (and GUI) utility for Windows 7 & 10,
the primary purpose of which is to copy Nintendo Switch content (full NAND or specific partition) from/to a file or physical drive.

![Png](http://laumonier.org/switch/NxNandManager_v1.1.png)   

## Features   
- Full NAND backup & restore (BOOT0, BOOT1, RAWNAND)   
- Copy from/to specific partition (RAWNAND)    
- Dump integrity verification (MD5)   
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

![Png](http://splatoon.eu/switch/NxNandManager_v1.1_howto_open_drive.png)   

## CLI Usage

```NxNandManager.exe [--list] [--info] [--enable_autoRCM] [--disable_autoRCM] -i inputFilename|\\.\PhysicalDriveX [-o outputFilename|\\.\PhysicalDriveX] [-part=nxPartitionName] [lFlags]```

Arguments | Description | Example
--------- | ----------- | -------
--gui | Launch graphical user interface (optional) | ```--gui```
--info | Display detailed information about input (-i) & output (-o) streams | ```--info -i rawnand.bin```
--list | List compatible physical drives | ```--list```
--enable_autoRCM | Enable auto-RCM for BOOT0 partition indicated with -i param | ```--enable_autoRCM -i BOOT0```<br/>```--enable_autoRCM -i "C:\some dir\BOOT0"```<br/>```--enable_autoRCM -i \\.\PhysicalDrive3```
--disable_autoRCM | Disable auto-RCM for BOOT0 partition indicated with -i param | ```--disable_autoRCM -i BOOT0```<br/>```--disable_autoRCM -i "C:\some dir\BOOT0"```<br/>```--disable_autoRCM -i \\.\PhysicalDrive3```
-i | Path to input file or physical drive | ```-i rawnand.bin```<br/>```-i "C:\some dir\rawnand.bin"```<br/>```-i \\.\PhysicalDrive3```
-o | Path to output file or physical drive | ```-o rawnand.bin```<br/>```-o \\.\PhysicalDrive3```
-part= | Copy from/to a specific NAND partition (optional) | ```-part=PRODINFO```<br/>```-part=BCPKG2-2-Normal-Sub```

lFlags | Description
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


## Build

### CLI : MinGW (recommended if not using Visual Studio), MSYS and MSYS2 with GCC

```
git clone https://github.com/eliboa/NxNandManager   
cd NxNandManager
make
```

**Note :** Line ```#define ENABLE_GUI``` of "NxNandManager.h" file has to be commented

### CLI + GUI (Qt) : MinGW64, MSVC

**Dependency :** [Qt](https://www.qt.io/download)

Visual Studio ([Qt Visual Studio Tools](https://marketplace.visualstudio.com/items?itemName=TheQtCompany.QtVisualStudioTools-19123) needed) :  Use ```NxNandManager.sln``` solution file

QtCreator : Use ```NxNandManager/NxNandManager.pro``` project file


## Credits

- Special thanks to [shadow256](https://github.com/shadow2560) without whom this work would not have been possible
- rajkosto for his amazing work on [memloader](https://github.com/rajkosto/memloader).
- CTCaer's [hekate](https://github.com/CTCaer/hekate), which I borrowed a few pieces of code
