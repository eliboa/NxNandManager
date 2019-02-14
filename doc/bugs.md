# Bugs verified:

* Restauring a partition on a PhysicalDrive Cause a MD5 check of all the PhysicalPartition after copy, that result in a MD5 comparison that will be false.  
  -> Should be fixed. MD5 checks are bypassed when restoring to physical drive
  >> Verified, OK.
* PRODINFO doesn't restaure properly, error of size writen at the end of the process.  
  -> Should be fixed.
  >> No: (ERROR : 4176896 bytes to read but 4194304 bytes written) with a Hekate dump, not tested with NNM dump.
* backup GPT lookup always fails (rawanand drive / file)
