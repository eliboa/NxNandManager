# Bugs verified:

* Restauring a partition on a PhysicalDrive will not work, this is caused by the new security implementation, the type of the partition must be defined or the error controls must be specific for this type of restaure. This bug is on a WIP state.