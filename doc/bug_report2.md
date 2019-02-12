# shadow, 2019 Feb 12: 
* Rawnand is detected as an unknown nand type by --info param (file or physicaldrive), probably on 6.1.0 firmware and under (tested on 6.1.0 and 4.0.1). After some other tests, it seems to be a problem with OS version (Windows 7).
* Time of dump is not displayed (compilation with Mingw).

# eliboa, 2019 Feb 12 (MinGW - Windows 7 Pro):

***Test rawnand 6.1 / file (cutted at 94633984 bytes but contains GPT at the right offset):***  
**arguments : --info -i "bintest\output_file_raw.bin" -o bintest\rawnand.bin DEBUG_MODE**  
INPUT ARGUMENT is bintest\output_file_raw.bin.  
OUTPUT ARGUMENT is bintest\rawnand.bin.  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = bintest\output_file_raw.bin  
NxStorage::InitStorage - Initialize  
Looking for magic "010021000E00000009000000" at offset 1328  
Looking for magic "504B3131" at offset 5044  
Looking for magic "504B3131" at offset 5104  
Looking for magic "504B3131" at offset 5156  
Looking for magic "504B3131" at offset 4840  
Looking for magic "504B3131" at offset 4816  
Looking for magic "504B3131" at offset 4848  
Looking for magic "500052004F00440049004E0046004F" at offset 664  
magic offset found ! Type = RAWNAND, firmware = 0.00  
NxStorage::ParseGpt - Partition USER found  
NxStorage::ParseGpt - Partition SYSTEM found  
NxStorage::ParseGpt - Partition SAFE found  
NxStorage::ParseGpt - Partition BCPKG2-6-Repair-Sub found  
NxStorage::ParseGpt - Partition BCPKG2-5-Repair-Main found  
NxStorage::ParseGpt - Partition BCPKG2-4-SafeMode-Sub found  
NxStorage::ParseGpt - Partition BCPKG2-3-SafeMode-Main found  
NxStorage::ParseGpt - Partition BCPKG2-2-Normal-Sub found  
NxStorage::ParseGpt - Partition BCPKG2-1-Normal-Main found  
NxStorage::ParseGpt - Partition PRODINFOF found  
NxStorage::ParseGpt - Partition PRODINFO found  
NxStorage::InitStorage - File size = 94633984 bytes  
NxStorage::NxStorage - path = bintest\rawnand.bin  
NxStorage::InitStorage - Initialize  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - bintest\rawnan  
d.bin  
--- INPUT ---  
File/Disk : File  
NAND type : RAWNAND  
Size      : 90.25 Mb  
            01 PRODINFO  (3.98 Mb)  
            02 PRODINFOF  (4.00 Mb)  
            03 BCPKG2-1-Normal-Main  (8.00 Mb)  
            04 BCPKG2-2-Normal-Sub  (8.00 Mb)  
            05 BCPKG2-3-SafeMode-Main  (8.00 Mb)  
            06 BCPKG2-4-SafeMode-Sub  (8.00 Mb)  
            07 BCPKG2-5-Repair-Main  (8.00 Mb)  
            08 BCPKG2-6-Repair-Sub  (8.00 Mb)  
            09 SAFE  (64.00 Mb)  
            10 SYSTEM  (2.50 Gb)  
            11 USER  (26.00 Gb)  
--- OUTPUT ---  
File/Disk : File  
NAND type : INVALID  
Size      : 0 byte


***Test rawnand 6.1 / file (cutted at 94633984 bytes but contains GPT at the right offset):***  
**arguments : -i "bintest\output_file_raw.bin" -o bintest\rawnand.bin**  
Copying from input file (type: RAWNAND) to output file... (100%)  
Finished. 90.25 Mb dumped  
Computing MD5 checksum... (100%)  
Verified (checksums are IDENTICAL)  
***Elapsed time : 5.39s.***  