WinDivertTool.exe
=================

`WinDivertTool.exe` is a simple program for:

* Listing information about which (if any) programs are using WinDivert.
* Terminating all programs that are using WinDivert.
* Uninstalling WinDivert from your system.

`WinDivertTool.exe` is designed to work for any version of WinDivert.

What is WinDivert?
------------------

WinDivert is an open source (LGPL) software package for capturing and
modifying network packets for Windows.  WinDivert was originally developed as
part of the [ReQrypt](https://github.com/basil00/reqrypt) project for
tunneling HTTP(S) traffic.  Since then, WinDivert has used by many
applications such as packet filtering, packet sniffing, firewalls, NATs,
VPNs, tunneling applications, etc.  Some projects that use WinDivert include:

* [CitadelCore](https://github.com/TechnikEmpire/CitadelCore.Windows)
* [Clumsy](https://github.com/jagt/clumsy)
* [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI/)
* [mitmproxy](https://github.com/mitmproxy/mitmproxy/)
* [Inssidious](https://github.com/dfct/Inssidious/)
* [ReQrypt](https://github.com/basil00/reqrypt)
* [SnoopSpy](https://github.com/gilgil1973/snoop90)
* [Suricata](https://github.com/OISF/suricata)
* [Tallow](https://github.com/basil00/TorWall)
* [TcpCrypt](https://github.com/scslab/tcpcrypt)
* ...and many more.

Why is WinDivert on my system?
------------------------------

If you find any of the `WinDivert.dll`, `WinDivert32.sys` or
`WinDivert64.sys` files on your system it probably means one (or more)
program/application is using WinDivert.  You can run `WinDivertTool.exe` to
get a list of all programs currently using WinDivert, for example:

        C:\> WinDivertTool.exe
        __      ___      ___  _             _  _____         _
        \ \    / (_)_ _ |   \(_)_ _____ _ _| ||_   _|__  ___| |
         \ \/\/ /| | ' \| |) | \ V / -_) '_|  _|| |/ _ \/ _ \ |
          \_/\_/ |_|_||_|___/|_|\_/\___|_|  \__||_|\___/\___/_| VERSION 2.2
        
        ...
        
        FOUND   C:\Program Files (x86)\Tallow\tallow.exe
                ProcessId=2216
                Hash=2cafec8e56c0380a61d6e5eea1e5ad0b618bb2d1936b4fe6d9ce7c839f051bea (SHA256)
                WinDivertVersion=2.2.X
                WinDivertFilter="outbound and ip.DstAddr >= 44.0.0.0 and ip.DstAddr <= 44.255.255.255"
                WinDivertLayer=NETWORK
                WinDivertPriority=-1755
                WinDivertFlags=0
        
        ...

In this example, the `WinDivertTool.exe` output indicates that a program
called `tallow.exe` (see the
[Tallow project](https://github.com/basil00/TorWall)) is using WinDivert.  The
`WinDivertTool.exe` also prints some additional technical information,
including the process ID and hash, as well as the WinDivert version, filter
string, layer, priority and flags.

How do I uninstall WinDivert?
-----------------------------

The recommended method for uninstalling WinDivert is to uninstall whatever
application is using it.  In the example above, this can be achieved by
uninstalling [Tallow](https://github.com/basil00/TorWall).

`WinDivertTool.exe` can also *forcibly* terminate all programs/applications
using WinDivert and uninstall the WinDivert driver(s) from your system.  This
approach is not recommended and should only be used as a last resort.  To
forcibly uninstall WinDivert, run `WinDivertTool.exe` with the `uninstall`
argument:

        C:\> WinDivertTool.exe uninstall

Note that this will not prevent the program/application from reinstalling
WinDivert after `WinDivertTool.exe` has completed.

Security Considerations
-----------------------

For security reasons, a program using WinDivert must have *Administrator*
access rights, else the WinDivert driver will refuse to load/work.  This
policy mirrors similar policies for related tools on other platforms, such as
*divert sockets* for MacOSX and `netfilterqueue` for Linux.  Programs do not
run as *Administrator* by default, and a program requesting *Administrator*
rights will trigger a comfirmation via the *UAC prompt*.

This means that **all programs listed by `WinDivertTool.exe` are running with
Administrator access rights**.

`WinDivertTool.exe` also requires *Administrator* access to query the
relevant the system for WinDivert drivers and handles.  Furthermore, process
termination also requires *Administrator* access.  As a result, you may be
prompted by Windows UAC when `WinDivertTool.exe` is run.  `WinDivertTool.exe`
does not install the WinDivert driver, but it may query any existing
WinDivert driver that is already installed on your system.

Limitations
-----------

After WinDivert has been uninstalled, `WinDivertTool.exe` cannot prevent
another application reinstalling it.  If you do not want a program using
WinDivert then you must uninstall the program.

`WinDivertTool.exe` cannot detect modified versions of the WinDivert driver
and service.

`WinDivertTool.exe` cannot get detailed information from older versions
(pre-2.0.0) of the WinDivert driver.  As a result, some information may be
missing and displayed as `???`.

`WinDivertTool.exe` is beta quality software so there may be some bugs.
Please report any bug here: https://github.com/basil00/WinDivertTool/issues

Building
--------

`WinDivertTool.exe` depends on the WinDivert runtime.  To build, unzip
the WinDivert source code into the current directory then run `make`.
Currently only Linux cross-compilation is supported.

License
-------

`WinDivertTool.exe` is distributed under the GNU Public License (GPL) Version 3.

