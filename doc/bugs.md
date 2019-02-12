# Bugs verified:

* Rawnand dumped hasn't a good size (must be 31 268 536 320 octets, for now it is 31264289280 octets).
* Rawnand is detected as an unknown nand type by --info param (file or physicaldrive), probably on 6.1.0 firmware and under (tested on 6.1.0 and 4.0.1). After some other tests, it seems to be a problem with OS version (Windows 7).
* Time of dump is not displayed (compilation with Mingw).

