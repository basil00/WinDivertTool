CC = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres
CFLAGS = -Os -Iinclude/ -m32 -Wall -s -DPSAPI_VERSION=1 -D_WIN32_WINNT=0x0600
PROG = WinDivertTool.exe

all:
	$(WINDRES) WinDivertTool.rc -O coff -o WinDivertTool.res
	$(CC) $(CFLAGS) -o $(PROG) WinDivertTool.c WinDivertTool.res -lpsapi

clean:
	rm -rf $(OBJS) $(PROG)


