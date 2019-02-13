# Bugs verified:

* Restauring a partition on a PhysicalDrive Cause a MD5 check of all the PhysicalPartition after copy, that result in a MD5 comparison that will be false.
* PRODINFO doesn't restaure properly, error of size writen at the end of the process.
* backup GPT lookup always fails (rawanand drive / file)
