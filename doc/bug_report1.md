# shadow, 2019 Feb 11: 
Rawnand is detected as an unknown nand type by --info param (file or physicaldrive), probably on 6.1.0 firmware and under (tested on 6.1.0 and 4.0.1).

# eliboa, 2019 Feb 11 (Visual Studio):

## Visual Studio
***Test rawnand 5.1 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\rawnand.bin" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\rawnand.bin.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\rawnand.bin  
NxStorage::InitStorage - BOOT0 hex = 010000000000000042004300  
NxStorage::InitStorage - BOOT1 hex = 00000000  
NxStorage::InitStorage - RAWNAND hex = 500052004f00440049004e0046004f  
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
NxStorage::InitStorage - File size = 31268536320  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : RAWNAND  
Size      : 29.12 Gb  
Partitions: 01 PRODINFO  (3.98 Mb)  
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
  
***Test rawnand 6.1 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\rawnand.bin" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\rawnand.bin.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\rawnand.bin  
NxStorage::InitStorage - BOOT0 hex = 010000000000000042004300  
NxStorage::InitStorage - BOOT1 hex = 00000000  
NxStorage::InitStorage - RAWNAND hex = 500052004f00440049004e0046004f  
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
NxStorage::InitStorage - File size = 31268536320  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : RAWNAND  
Size      : 29.12 Gb  
Partitions: 01 PRODINFO  (3.98 Mb)  
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
  
***Test rawnand 6.2 / physical drive:***  
**arguments : --info -i \\.\PHYSICALDRIVE3 DEBUG_MODE**  
INPUT ARGUMENT is \\.\PHYSICALDRIVE3.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = \\.\PHYSICALDRIVE3  
NxStorage::InitStorage - Drive size is 31264289280 bytes  
NxStorage::InitStorage - BOOT0 hex = 010000000000000042004300  
NxStorage::InitStorage - BOOT1 hex = 00000000  
NxStorage::InitStorage - RAWNAND hex = 500052004f00440049004e0046004f  
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
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : Disk  
NAND type : RAWNAND  
Size      : 29.12 Gb  
Partitions: 01 PRODINFO  (3.98 Mb)  
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
  
***Test boot1 6.2 / physical drive:***  
**arguments : --info -i \\.\PHYSICALDRIVE3 DEBUG_MODE**  
INPUT ARGUMENT is \\.\PHYSICALDRIVE3.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = \\.\PHYSICALDRIVE3  
NxStorage::InitStorage - Drive size is 4194304 bytes  
NxStorage::InitStorage - BOOT0 hex = 049b110001200096fff7cbfd  
NxStorage::InitStorage - BOOT1 hex = 504b3131  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : Disk  
NAND type : BOOT1  
Size      : 4.00 Mb  
  
***Test boot1 6.1 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\BOOT1" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\BOOT1.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\BOOT1  
NxStorage::InitStorage - BOOT0 hex = 049b110001200096fff7cbfd  
NxStorage::InitStorage - BOOT1 hex = 504b3131  
NxStorage::InitStorage - File size = 4194304  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : BOOT1  
Size      : 4.00 Mb  
  
***Test boot1 5.1 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\BOOT1" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\BOOT1.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\BOOT1  
NxStorage::InitStorage - BOOT0 hex = 7047436083607047f7b51400  
NxStorage::InitStorage - BOOT1 hex = 834207d2  
NxStorage::InitStorage - RAWNAND hex = 00f074f8012000f080f83320000138  
NxStorage::InitStorage - File size = 4194304  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : UNKNOWN  
Size      : 4.00 Mb  
  
##MinGW  
***Test rawnand 5.1 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\rawnand.bin" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\rawnand.bin.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\rawnand.bin  
NxStorage::InitStorage - BOOT0 hex = 010000000000000042004300  
NxStorage::InitStorage - BOOT1 hex = 00000000  
NxStorage::InitStorage - RAWNAND hex = 500052004f00440049004e0046004f  
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
NxStorage::InitStorage - File size = 31268536320  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : RAWNAND  
Size      : 29.12 Gb  
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
  
***Test rawnand 6.2 / physical drive:***  
**arguments : --info -i \\.\PHYSICALDRIVE3 DEBUG_MODE**  
INPUT ARGUMENT is \\.\PHYSICALDRIVE3.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = \\.\PHYSICALDRIVE3  
NxStorage::InitStorage - Drive size is 31264289280 bytes  
NxStorage::InitStorage - BOOT0 hex = 010000000000000042004300  
NxStorage::InitStorage - BOOT1 hex = 00000000  
NxStorage::InitStorage - RAWNAND hex = 500052004f00440049004e0046004f  
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
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : Disk  
NAND type : RAWNAND  
Size      : 29.12 Gb  
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
  
***Test rawnand 6.1 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\rawnand.bin" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\rawnand.bin.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\rawnand.bin  
NxStorage::InitStorage - BOOT0 hex = 010000000000000042004300  
NxStorage::InitStorage - BOOT1 hex = 00000000  
NxStorage::InitStorage - RAWNAND hex = 500052004f00440049004e0046004f  
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
NxStorage::InitStorage - File size = 31268536320  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : RAWNAND  
Size      : 29.12 Gb  
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
  
***Test boot1 6.2 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\BOOT1" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\BOOT1.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 6.1 20181029-clean\BOOT1  
NxStorage::InitStorage - BOOT0 hex = 049b110001200096fff7cbfd  
NxStorage::InitStorage - BOOT1 hex = 504b3131  
NxStorage::InitStorage - File size = 4194304  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : BOOT1  
Size      : 4.00 Mb  
  
***Test boot1 5.1 / file:***  
**arguments : --info -i "S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\BOOT1" DEBUG_MODE**  
INPUT ARGUMENT is S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\BOOT1.  
OUTPUT ARGUMENT is (null).  
BYPASS_MD5SUM is false.  
NxStorage::NxStorage - path = S:\dev\switch\nand_dump\Switch Neon 5.1 20180624\BOOT1  
NxStorage::InitStorage - BOOT0 hex = 7047436083607047f7b51400  
NxStorage::InitStorage - BOOT1 hex = 834207d2  
NxStorage::InitStorage - RAWNAND hex = 00f074f8012000f080f83320000138  
NxStorage::InitStorage - File size = 4194304  
NxStorage::NxStorage - path = (null)  
NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - (null)  
File/Disk : File  
NAND type : UNKNOWN  
Size      : 4.00 Mb  

