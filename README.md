# About

utftp is a C library and an application implementing the *T*rivial *F*ile *T*ransfer *P*rotocol.


The application was supposed to serve only as an example for the library but, since the commonly used TFTP implementations have various problems (in my eyes), I decided to give it some more features.

My aim is that it:

- doesn't accidentally send its log output on a UDP socket
- allows using symlinks in some way (because they can be quite useful)
- doesn't mangle file names
- allows finer grained control over receiving files (max. file size, don't overwrite, don't create)
