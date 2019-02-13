# NxNandManager

NxNandManager is a command line (and GUI) utility for Windows 7 & 10, 
the primary purpose of which is to copy Nintendo Switch content (full NAND or specific partition) from/to a file or physical drive.

***First beta release will be out soon***

## Usage

```NxNandManager.exe [--list] [--info] -i inputFilename|\\.\PhysicalDriveX [-o outputFilename|\\.\PhysicalDriveX] [-part=nxPartitionName] [lFlags]```

Arguments | Description | Example
--------- | ----------- | -------
--gui | Launch graphical user interface (optional)  | ```--gui```
--info | Display detailed information about input (-i) & output (-o) streams | ```--info -i rawnand.bin```
--list | List compatible physical drives
-i | Path to input file or physical drive | ```-i rawnand.bin```<br/>```-i "C:\some dir\rawnand.bin"```<br/>```-i \\.\PhysicalDrive3```
-o | Path to output file or physical drive | ```-o rawnand.bin```<br/>```-o \\.\PhysicalDrive3```
-part= | Copy from/to a specific NAND partition (optional) | ```-part=PRODINFO```<br/>```-part=BCPKG2-2-Normal-Sub```

lFlags | Description 
------ | -----------
BYPASS_MD5SUM | Used to by-pass all md5 verifications<br/>Dump/Restore is faster but less secure
FORCE | Program will never prompt for user confirmation
DEBUG_MODE | Program will display some infos that could be usful for debugging.

## Compatibility

Hekate's rawnand/paritions dump are supported.
Splitted dump (such as SX (emu)NAND dump) will be added very soon

## Examples

### Dump full NAND to file

- From physical drive (you first need to mount NX eMMC with [memloader](https://github.com/rajkosto/memloader) (via [TegraRcmGUI](https://github.com/eliboa/TegraRcmGUI) for ex) :  
```.\NxNandManager.exe -i \\.\PhysicalDrive3 -o "C:\Users\Public\NAND dump\rawnand.bin" ```

- From existing dump file :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o D:\rawnand2.bin ```


### Dump specific partition to file

- Dump SYSTEM partition from physical drive :  
```.\NxNandManager.exe -i \\.\PhysicalDrive3 -o "C:\Users\Public\NAND dump\PRODINFOF.bin" -part=SYSTEM```

- Extract PRODINFOF partition from existing dump file :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o D:\PRODINFOF.bin -part=PRODINFOF```


### Restore full NAND dump

- Restore full raw NAND to physical drive :  
```.\NxNandManager.exe -i "C:\Users\Public\NAND dump\rawnand.bin" -o \\.\PhysicalDrive3```
