# Bugs verified:

* When trying to extract a partition from a file and if MD5SUM is verified, the program terminate with an error. The partition is dumped but the MD5 verification cause this error:
"terminate called after throwing an instance of 'std::logic_error'
  what():  basic_string::_M_construct null not valid
This application has requested the Runtime to terminate it in an unusual way.
Please contact the application's support team for more information."  
=> Should be fixed
* backup GPT lookup always fails (rawnand drive / file)
=> Should be fixed
