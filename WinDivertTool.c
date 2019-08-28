/*
 * WinDivertTool.c
 * Copyright (C) 2019, basil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UNICODE
#define UNICODE
#endif

#define MIN(x, y)                   ((x) < (y)? (x): (y))

/****************************************************************************/
/* WINDIVERT.DLL                                                            */
/****************************************************************************/

#include "dll/windivert.c"

#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <conio.h>

#include "sha256.c"

/****************************************************************************/
/* MODES                                                                    */
/****************************************************************************/

#define MODE_LIST               0
#define MODE_KILL               1
#define MODE_UNINSTALL          2

static int mode = MODE_LIST;

/****************************************************************************/
/* NTDLL.DLL                                                                */
/****************************************************************************/

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectNameInformation 1

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(ULONG, PVOID, ULONG,
    PULONG);
typedef NTSTATUS (NTAPI *_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE,
    ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

static _NtQuerySystemInformation NtQuerySystemInformation = NULL;
static _NtDuplicateObject NtDuplicateObject = NULL;
static _NtQueryObject NtQueryObject = NULL;

/****************************************************************************/
/* MESSAGES                                                                 */
/****************************************************************************/

/*
 * Output.
 */
static HANDLE console = INVALID_HANDLE_VALUE;
static HANDLE log     = INVALID_HANDLE_VALUE;

/*
 * Output strings/chars/integers.
 */
static void writeStr(const char *str)
{
    if (console != INVALID_HANDLE_VALUE)
        (VOID)WriteFile(console, str, lstrlenA(str), NULL, NULL);
    if (log != INVALID_HANDLE_VALUE)
        (VOID)WriteFile(log, str, lstrlenA(str), NULL, NULL);
}
static void writeChar(char c)
{
    char buf[2] = {c, '\0'};
    writeStr(buf);
}
static void writeInt(int i)
{
    char buf[32];
    HRESULT result;
    
    result = StringCbPrintfA(buf, sizeof(buf), "%d",  i);
    if (FAILED(result))
        writeStr("???");
    else
        writeStr(buf);
}

/*
 * Output a message.
 */
static void message(const char *type, DWORD color, const char *message,
    DWORD err, ...)
{
    va_list args;
    char buf[BUFSIZ], *errBuf;
    HRESULT result;
    size_t len;
    DWORD errLen;

    SetConsoleTextAttribute(console, color);
    writeStr(type);
    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
        FOREGROUND_BLUE);
    writeStr(": ");

    va_start(args, err);
    result = StringCbVPrintfA(buf, sizeof(buf), message, args);
    va_end(args);
    if (FAILED(result))
        (VOID)StringCbCopyA(buf, sizeof(buf)-1, message);
    result = StringCbLengthA(buf, sizeof(buf)-32, &len);
    if (FAILED(result))
        return;
    else if (err != ERROR_SUCCESS)
    {
        buf[len++] = ':';
        buf[len++] = ' ';
        errBuf = buf + len;
        errLen = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, 0, err, 0, errBuf,
            sizeof(buf)-len-1, 0);
        if (errLen >= 2 && errBuf[errLen-2] == '\r' && errBuf[errLen-1] == '\n')
        {
            errBuf[errLen-2] = '\n';
            errBuf[errLen-1] = '\0';
        }
    }
    else
    {
        buf[len++] = '\n';
        buf[len++] = '\0';
    }
    writeStr(buf);
}

/*
 * Gracefully exit.
 */
static void exitTool(UINT code)
{
    HWND window;
    DWORD pid;

    if (log != INVALID_HANDLE_VALUE)
    {
        CloseHandle(log);
        log = INVALID_HANDLE_VALUE;
    }
    if (console != INVALID_HANDLE_VALUE)
    {
        window = GetConsoleWindow();
        if (window != NULL)
            GetWindowThreadProcessId(window, &pid);
        if (window == NULL || pid == GetCurrentProcessId())
        {
            writeStr("Press any key to exit...");
            _getch();
        }
    }
    ExitProcess(code);
}

#define log(msg, ...)                                                       \
    message("log", FOREGROUND_GREEN, (msg), 0, ## __VA_ARGS__)
#define warning(msg, err, ...)                                              \
    message("warning", FOREGROUND_RED | FOREGROUND_GREEN, (msg), (err),     \
        ## __VA_ARGS__)
#define error(msg, err, ...)                                                \
    do {                                                                    \
        message("error", FOREGROUND_RED, (msg), (err), ## __VA_ARGS__);     \
        exitTool(1);                                                         \
    } while (FALSE)

/****************************************************************************/
/* WINDIVERT TRACKING                                                       */
/****************************************************************************/

#define WINDIVERT_ALL_FLAGS                                                 \
    ((UINT64)(WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_DROP |                  \
     WINDIVERT_FLAG_RECV_ONLY | WINDIVERT_FLAG_SEND_ONLY |                  \
     WINDIVERT_FLAG_NO_INSTALL | WINDIVERT_FLAG_FRAGMENTS))

/*
 * WinDivert Versions.
 */
#define WINDIVERT_VERSION_1_0_X     1
#define WINDIVERT_VERSION_1_1_X     2
#define WINDIVERT_VERSION_1_2_X     3
#define WINDIVERT_VERSION_1_3_X     4
#define WINDIVERT_VERSION_1_4_X     5
#define WINDIVERT_VERSION_GEQ_2_0_X 6
#define WINDIVERT_VERSION_2_0_X     7
#define WINDIVERT_VERSION_2_1_X     8
#define WINDIVERT_VERSION_2_2_X     9
#define WINDIVERT_VERSION_GT_2_2_X  10
#define WINDIVERT_VERSION_UNKNOWN   11

/*
 * WinDivert drivers.
 */
static const char * const versions[] =
{
    "WinDivert1.0", "WinDivert1.1", "WinDivert1.2", "WinDivert1.3",
    "WinDivert1.4", "WinDivert"
};
static BOOL installed[] = {TRUE, TRUE, TRUE, TRUE, TRUE, TRUE};

/*
 * Convert WinDivert version to string.
 */
static const char *versionToString(unsigned version)
{
    switch (version)
    {
        case WINDIVERT_VERSION_1_0_X:
            return "1.0.X";
        case WINDIVERT_VERSION_1_1_X:
            return "1.1.X";
        case WINDIVERT_VERSION_1_2_X:
            return "1.2.X";
        case WINDIVERT_VERSION_1_3_X:
            return "1.3.X";
        case WINDIVERT_VERSION_1_4_X:
            return "1.4.X";
        case WINDIVERT_VERSION_2_0_X:
            return "2.0.X";
        case WINDIVERT_VERSION_GEQ_2_0_X:
            return ">= 2.0.X";
        case WINDIVERT_VERSION_2_1_X:
            return "2.1.X";
        case WINDIVERT_VERSION_2_2_X:
            return "2.2.X";
        case WINDIVERT_VERSION_GT_2_2_X:
            return "> 2.2.X";
        default:
            return "unknown";
    }
}

typedef struct _WINDIVERT_ENTRY
{
    struct _WINDIVERT_ENTRY *next;
    HANDLE process;
    DWORD pid;
    unsigned version;
    PVOID handle;
    const char *filter;
    const char *exe;
    UINT8 sha256[32];
    INT64 timestamp;
    UINT64 flags;
    WINDIVERT_LAYER layer;
    INT16 priority;
    BOOL killed;
} WINDIVERT_ENTRY, *PWINIVERT_ENTRY;

static PWINIVERT_ENTRY table = NULL;

/*
 * Duplicate a string.
 */
static const char *duplicateString(HANDLE heap, const char *str)
{
    HRESULT result;
    size_t len;
    char *strCopy;

    SetLastError(ERROR_SUCCESS);
    result = StringCbLengthA(str, UINT16_MAX, &len);
    if (FAILED(result))
        return NULL;

    strCopy = HeapAlloc(heap, 0, len+1);
    if (strCopy == NULL)
        return NULL;

    CopyMemory(strCopy, str, len+1);
    return strCopy;
}

/*
 * Calculate SHA256 sum.
 */
extern void sha256Sum(const char *filename, UINT8 *result)
{
    SHA256_CTX cxt;
    HANDLE file;
    UINT8 buf[8192];
    DWORD len;

    file = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        warning("failed to open file \"%s\" for reading", GetLastError(),
            filename);
        ZeroMemory(result, 32);
        return;
    }
    sha256Init(&cxt);
    SetLastError(0);
    while (ReadFile(file, (char *)buf, sizeof(buf), &len, NULL) && len > 0)
        sha256Update(&cxt, buf, len);
    sha256Final(&cxt, result);
    if (GetLastError() != 0)
    {
        warning("failed to read data from file \"%s\"", GetLastError(),
            filename);
        ZeroMemory(result, 32);
    }
    CloseHandle(file);
}

/*
 * Allocate a WINDIVERT_ENTRY.
 */
static PWINIVERT_ENTRY allocateEntry(DWORD pid, HANDLE process,
    const char *exe, const char *filter)
{
    PWINIVERT_ENTRY entry;
    HANDLE heap;
    
    heap = GetProcessHeap();
    if (heap == NULL)
    {
allocate_failed:
        warning("failed to allocate WinDivert entry for process %d (%s)",
            GetLastError(), pid, exe);
        return NULL;
    }
      
    entry = (PWINIVERT_ENTRY)HeapAlloc(heap, HEAP_ZERO_MEMORY,
        sizeof(WINDIVERT_ENTRY));
    if (entry == NULL)
        goto allocate_failed;

    entry->pid     = pid;
    entry->process = NULL;
    if (process != NULL &&
        !DuplicateHandle(GetCurrentProcess(), process,
            GetCurrentProcess(), &entry->process, 0, FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        warning("failed to duplicate handle for process %d (%s)",
            GetLastError(), pid, exe);
        entry->process = NULL;
    }

    entry->exe = duplicateString(heap, exe);
    if (entry->exe == NULL)
        warning("failed to duplicate executable path string \"%s\" for "
            "process %d", GetLastError(), exe, pid);
	sha256Sum(exe, entry->sha256);

    if (filter != NULL)
    {
        entry->filter = duplicateString(heap, filter);
        if (entry->filter == NULL)
            warning("failed to duplicate filter string \"%s\" for process "
                "%d (%s)", GetLastError(), filter, pid, exe);
    }

    return entry;
}

/*
 * Add an entry from driver.
 */
static void addDriverEntry(DWORD pid, HANDLE process, const char *exe,
    INT64 timestamp, unsigned version, const char *filter,
    WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
{
    PWINIVERT_ENTRY entry = allocateEntry(pid, process, exe, filter);
    if (entry == NULL)
        return;
    entry->timestamp = timestamp;
    entry->version   = version;
    entry->flags     = flags;
    entry->layer     = layer;
    entry->priority  = priority;
    entry->next      = table;
    table            = entry;
}

/*
 * Add an entry from a handle.
 */
static void addHandleEntry(DWORD pid, HANDLE process, const char *exe,
    HANDLE handle, unsigned version)
{
    PWINIVERT_ENTRY entry;

    for (entry = table; entry != NULL; entry = entry->next)
    {
        if (entry->pid == pid && entry->version > version)
            return;     // Already found entry.
    }

    entry = allocateEntry(pid, process, exe, NULL);
    if (entry == NULL)
        return;

    entry->version = version;
    entry->next    = table;
    table          = entry;
}

/*
 * Kill all WinDivert client processes.
 */
static BOOL killAll(BOOL force)
{
    PWINIVERT_ENTRY entry;
    const char *exe;
    char c;
    DWORD i;
    BOOL confirmed, success;

    if (table == NULL)
        return TRUE;
    if (!force)
    {
        // Terminating processes is not ideal.  Better check with the user.
        writeStr("\nForcibly terminate the following program(s) that are "
            "using WinDivert?\n");
        for (entry = table, i = 0; entry != NULL; entry = entry->next, i++)
        {
            exe = (entry->exe == NULL? "???": entry->exe);
            writeChar('\t');
            writeInt(i+1);
            writeStr(". ");
            writeStr(exe);
            writeStr(" (");
            writeInt(entry->pid);
            writeStr(")\n");
        }
        writeChar('\n');
        confirmed = FALSE;
        while (!confirmed)
        {
            writeStr("Terminate programs (Y or N)? ");
            c = _getch();
            writeChar(c);
            writeChar('\n');
            switch (c)
            {
                case 'y': case 'Y':
                    confirmed = TRUE;
                    break;
                case 'n': case 'N':
                    writeStr("Operation aborted by the user.\n");
                    exitTool(0);
                default:
                    break;
            }
        }
    }

    success = TRUE;
    for (entry = table; entry != NULL; entry = entry->next)
    {
        exe = (entry->exe == NULL? "???": entry->exe);
        log("terminating WinDivert client process %d (%s)", entry->pid, exe);
        if (entry->process == NULL)
        {
            success = FALSE;
            warning("failed to terminate process %d (%s), no process handle "
                "available", ERROR_SUCCESS, entry->pid, exe);
        }
        else if (!TerminateProcess(entry->process, 1) &&
                    GetLastError() != ERROR_ACCESS_DENIED)
        {
            success = FALSE;
            warning("failed to terminate process %d (%s)", GetLastError(),
                entry->pid, exe);
        }
        else
            entry->killed = TRUE;
        if (entry->process != NULL)
            CloseHandle(entry->process);
    }

    return success;
}

/*
 * Print report.
 */
static void printReport(BOOL killed, BOOL uninstalled)
{
    PWINIVERT_ENTRY entry;
    const char *exe;
    BOOL or, zero;
    UINT8 byte;
    int i, j;
 
    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
        FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    if (table == NULL)
    {
        writeStr("\nNo programs are using WinDivert.\n");
        goto print_report_exit;
    }

    writeStr("\nThe following program(s) are using WinDivert:\n");
    for (entry = table, i = 0; entry != NULL; entry = entry->next, i++)
    {
        switch (mode)
        {
            case MODE_UNINSTALL:
            case MODE_KILL:
                SetConsoleTextAttribute(console,
                    FOREGROUND_RED | FOREGROUND_INTENSITY);
                if (entry->killed)
                {
                    writeStr("\nKILLED  ");
                    break;
                }
                // Fallthrough
            default:
                SetConsoleTextAttribute(console, FOREGROUND_GREEN |
                    FOREGROUND_INTENSITY);
                writeStr("\nFOUND   ");
                break;
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        writeStr(entry->exe);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);

        writeStr("\n\tProcessId=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        writeInt(entry->pid);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        
        writeStr("\n\tHash=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        zero = TRUE;
        for (j = 0; zero && j < sizeof(entry->sha256); j++)
            zero = (entry->sha256[j] == 0);
        if (zero)
            writeStr("???");
        else
        {
            for (j = 0; j < sizeof(entry->sha256); j++)
            {
                byte = (entry->sha256[j] >> 4);
                writeChar((byte < 10? '0' + byte: 'a' + (byte - 10)));
                byte = (entry->sha256[j] & 0x0F);
                writeChar((byte < 10? '0' + byte: 'a' + (byte - 10)));
            }
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        writeStr(" (SHA256)");
 
        writeStr("\n\tWinDivertVersion=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        writeStr(versionToString(entry->version));
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        if (entry->version < WINDIVERT_VERSION_2_1_X &&
            entry->version != WINDIVERT_VERSION_1_4_X &&
            entry->version != WINDIVERT_VERSION_GEQ_2_0_X)
        {
            writeStr(" (");
            SetConsoleTextAttribute(console, FOREGROUND_RED |
                FOREGROUND_INTENSITY);
            writeStr("warning: this version of WinDivert is "
                "obsolete, DO NOT USE!");
            SetConsoleTextAttribute(console, FOREGROUND_RED |
                FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            writeChar(')');
        }
        if (entry->version < WINDIVERT_VERSION_2_0_X)
        {
            writeStr(" (");
            SetConsoleTextAttribute(console, FOREGROUND_RED |
                FOREGROUND_INTENSITY);
            writeStr("warning: cannot retrieve detailed information "
                "from old version of WinDivert");
            SetConsoleTextAttribute(console, FOREGROUND_RED |
                FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            writeChar(')');
        }

        writeStr("\n\tWinDivertFilter=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        if (entry->filter == NULL)
            writeStr("???");
        else
        {
            writeChar('\"');
            writeStr(entry->filter);
            writeChar('\"');
            if (entry->filter[0] == '@')
            {
                writeStr(" (");
                SetConsoleTextAttribute(console, FOREGROUND_RED |
                    FOREGROUND_INTENSITY);
                writeStr("warning: failed to decompile filter object");
                SetConsoleTextAttribute(console, FOREGROUND_RED |
                    FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                writeChar(')');
            }
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);

        writeStr("\n\tWinDivertLayer=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        if (entry->filter == NULL)
            writeStr("???");
        else
        {
            switch (entry->layer)
            {
				case WINDIVERT_LAYER_NETWORK:
            	    writeStr("NETWORK");
            	    break;
            	case WINDIVERT_LAYER_NETWORK_FORWARD:
            	    writeStr("NETWORK_FORWARD");
            	    break;
            	case WINDIVERT_LAYER_FLOW:
            	    writeStr("FLOW");
            	    break;
            	case WINDIVERT_LAYER_SOCKET:
            	    writeStr("SOCKET");
            	    break;
            	case WINDIVERT_LAYER_REFLECT:
            	    writeStr("REFLECT");
            	    break;
            	default:
            	    writeStr("???");
            	    break;
            }
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);

        writeStr("\n\tWinDivertPriority=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        if (entry->filter == NULL)
            writeStr("???");
        else
            writeInt(entry->priority);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);

        writeStr("\n\tWinDivertFlags=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_INTENSITY);
        if (entry->filter == NULL)
            writeStr("???");
        else if (entry->flags == 0)
            writeChar('0');
        else
        {
            or = FALSE;
            if ((entry->flags & WINDIVERT_FLAG_SNIFF) != 0)
            {
                writeStr("SNIFF");
                or = TRUE;
            }
            if ((entry->flags & WINDIVERT_FLAG_DROP) != 0)
            {
                if (or)
                    writeChar('|');
                writeStr("DROP");
                or = TRUE;
            }
            if ((entry->flags & WINDIVERT_FLAG_RECV_ONLY) != 0)
            {
                if (or)
                    writeChar('|');
                writeStr("RECV_ONLY");
                or = TRUE;
            }
            if ((entry->flags & WINDIVERT_FLAG_SEND_ONLY) != 0)
            {
                if (or)
                    writeChar('|');
                writeStr("SEND_ONLY");
                or = TRUE;
            }
            if ((entry->flags & WINDIVERT_FLAG_NO_INSTALL) != 0)
            {
                if (or)
                    writeChar('|');
                writeStr("NO_INSTALL");
                or = TRUE;
            }
            if ((entry->flags & WINDIVERT_FLAG_FRAGMENTS) != 0)
            {
                if (or)
                    writeChar('|');
                writeStr("FRAGMENTS");
                or = TRUE;
            }
            if ((entry->flags & ~WINDIVERT_ALL_FLAGS) != 0)
            {
                if (or)
                    writeChar('|');
                writeStr("???");
            }
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);

        writeChar('\n');
    }

print_report_exit:
    writeChar('\n');
    if (!killed)
    {
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        writeStr("*** FAILED ***\n");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        writeStr("The following WinDivert client program(s) could not be "
            "terminated:\n");
        for (entry = table, i = 1; entry != NULL; entry = entry->next)
        {
            if (entry->killed)
                continue;
            i++;
            exe = (entry->exe == NULL? "???": entry->exe);
            writeChar('\t');
            writeInt(i);
            writeStr(". ");
            writeStr(exe);
            writeStr(" (");
            writeInt(entry->pid);
            writeStr(")\n");
        }
        writeStr("Please consult the log file for more information.\n");
    }
    else if (!uninstalled)
    {
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        writeStr("*** FAILED ***\n");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        writeStr("The following WinDivert driver(s) could not be "
            "uninstalled:\n");
        for (i = 0, j = 0; i < sizeof(versions) / sizeof(versions[0]); i++)
        {
            if (!installed[i])
                continue;
            j++;
            writeChar('\t');
            writeInt(j);
            writeStr(versions[i]);
            writeChar('\n');
        }
        writeStr("Please consult the log file for more information.\n");
    }
    else
    {
        SetConsoleTextAttribute(console,
            FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        writeStr("SUCCESS!\n");
    }
    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
        FOREGROUND_BLUE);
}

/****************************************************************************/
/* WINDIVERT DEVICE                                                         */
/****************************************************************************/

/*
 * Query modern WinDivert driver.
 */
static void queryWinDivertDriver(void)
{
    HANDLE handle, process;
    UINT8 packet[8192];
    UINT packetLen;
    char path[MAX_PATH+1];
    const char *exe = "???";
    static char filter[8192];
    WINDIVERT_ADDRESS addr;
    UINT64 major, minor;
    DWORD len;
    unsigned version = WINDIVERT_VERSION_GEQ_2_0_X;

    handle = WinDivertOpen("true", WINDIVERT_LAYER_REFLECT, 777,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY |
            WINDIVERT_FLAG_NO_INSTALL);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
            return;
        warning("failed to open WinDivert driver handle", GetLastError());
        return;
    }

    if (!WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH))
    {
        warning("failed to shutdown WinDivert driver handle", GetLastError());
        return;
    }

    if (WinDivertGetParam(handle, WINDIVERT_PARAM_VERSION_MAJOR, &major) &&
        WinDivertGetParam(handle, WINDIVERT_PARAM_VERSION_MINOR, &minor))
    {
        if (major == 2)
        {
            switch (minor)
            {
                case 0:
                    version = WINDIVERT_VERSION_2_0_X;
                    break;
                case 1:
                    version = WINDIVERT_VERSION_2_1_X;
                    break;
                case 2:
                    version = WINDIVERT_VERSION_2_2_X;
                    break;
                default:
                    version = WINDIVERT_VERSION_GT_2_2_X;
                    break;
            }
        }
        else if (major > 2)
            version = WINDIVERT_VERSION_GT_2_2_X;
    }

    while (TRUE)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr))
        {
            if (GetLastError() == ERROR_NO_DATA)
                break;
            warning("failed to read WinDivert handle information",
                GetLastError());
            break;
        }

        // Get the process name:
        exe = "???";
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_TERMINATE, FALSE, addr.Reflect.ProcessId);
        if (process != NULL)
        {
            len = sizeof(path)-1;
            if (QueryFullProcessImageNameA(process, 0, path, &len))
                exe = path;
        }

        // Get the filter:
        if (!WinDivertHelperFormatFilter((char *)packet, addr.Reflect.Layer,
                filter, sizeof(filter)-1))
        {
            warning("failed to decompile filter object for process %d",
                GetLastError(), addr.Reflect.ProcessId);
            CopyMemory(filter, packet, MIN(packetLen, sizeof(filter)-1));
            filter[sizeof(filter)-1] = '\0';
        }

        log("found WinDivert handle (pid=%d, exe=\"%s\", "
                "version=\"%s\" filter=\"%s\")", addr.Reflect.ProcessId, exe,
                versionToString(version), filter);

        addDriverEntry(addr.Reflect.ProcessId, process, exe,
            addr.Reflect.Timestamp, version, filter, addr.Reflect.Layer,
            addr.Reflect.Priority, addr.Reflect.Flags);
        CloseHandle(process);
    }

    WinDivertClose(handle);
}

/*
 * Stop all WinDivert drivers.
 */
static BOOL uninstallWinDivert(void)
{
	HANDLE mutex, manager, service;
    SERVICE_STATUS status;
    size_t i;
    DWORD err;
    BOOL succeeded, found;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL)
        error("failed to uninstall WinDivert driver(s), could not open "
            "service manager", GetLastError());

    // Attempt to lock the driver install mutex, but continue no matter what.
    mutex = CreateMutexA(NULL, FALSE, "WinDivertDriverInstallMutex");
    if (mutex == NULL)
        warning("failed to create WinDivert driver install mutex",
            GetLastError());
    else
    {
        err = WaitForSingleObject(mutex, INFINITE);
        switch (err)
        {
            case WAIT_OBJECT_0: case WAIT_ABANDONED:
                break;
            default:
                warning("failed to wait for WinDivert driver install "
                    "mutex", err);
                break;
        }
    }

    succeeded = TRUE;
    found     = FALSE;
    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++)
    {
        service = OpenServiceA(manager, versions[i], SERVICE_ALL_ACCESS);
        if (service == NULL)
        {
            err = GetLastError();
            CloseServiceHandle(service);
            if (err == ERROR_SERVICE_DOES_NOT_EXIST)
            {
                installed[i] = FALSE;
                continue;
            }
            warning("failed to uninstall %s driver, could not open service",
                err, versions[i]);
            succeeded = FALSE;
            continue;
        }
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
        {
            if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            {
                warning("failed to uninstall %s driver, could not stop "
                    "service", GetLastError(), versions[i]);
                CloseServiceHandle(service);
                succeeded = FALSE;
                continue;
            }
        }
        // status.dwCurrentState != SERVICE_STOPPED)
        if (!DeleteService(service))
        {
            if (GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
            {
                warning("failed to uninstall %s driver, could not mark "
                    "service for deletion", GetLastError(), versions[i]);
                CloseServiceHandle(service);
                succeeded = FALSE;
                continue;
            }
        }
        CloseServiceHandle(service);
        installed[i] = FALSE;
        log("marked %s service for deletion", versions[i]);
        found = TRUE;
    }
    CloseServiceHandle(manager);
    if (mutex != NULL)
    {
        ReleaseMutex(mutex);
        CloseHandle(mutex);
    }
    if (found)
        log("marked all WinDivert services for deletion, the WinDivert "
            "driver(s) will be automatically uninstalled after all "
            "WinDivert client programs have terminated");
    else
        log("no WinDivert driver(s) found");
    return succeeded;
}


/****************************************************************************/
/* WINDIVERT HANDLES                                                        */
/****************************************************************************/

/*
 * Test if the handle name is WinDivert (\Device\WinDivert*)
 */
static unsigned isWinDivertDevice(const WCHAR *str, USHORT strLen)
{
    const WCHAR prefixLower[] = L"\\device\\windivert";
    const WCHAR prefixUpper[] = L"\\DEVICE\\WINDIVERT";
    unsigned version;
    USHORT i;

    for (i = 0; i < strLen && prefixLower[i] && prefixUpper[i]; i++)
    {
        if (str[i] != prefixLower[i] && str[i] != prefixUpper[i])
            return 0;
    }
    if (prefixLower[i] != L'\0')
        return 0;
    switch (str[i++])
    {
        case L'\0':
            return WINDIVERT_VERSION_GEQ_2_0_X;
        case '1':
            if (str[i++] == L'.')
                break;
            // Fallthrough:
        default:
            return WINDIVERT_VERSION_UNKNOWN;
    }
    switch (str[i++])
    {
        case L'0':
            version = WINDIVERT_VERSION_1_0_X;
            break;
        case L'1':
            version = WINDIVERT_VERSION_1_1_X;
            break;
        case L'2':
            version = WINDIVERT_VERSION_1_2_X;
            break;
        case L'3':
            version = WINDIVERT_VERSION_1_3_X;
            break;
        case L'4':
            version = WINDIVERT_VERSION_1_4_X;
            break;
        default:
            return WINDIVERT_VERSION_UNKNOWN;
    }
    return (str[i] == L'\0'? version: WINDIVERT_VERSION_UNKNOWN);
}

/*
 * Query worker state.
 */
static HANDLE queryThread = NULL;
static HANDLE inEvent     = NULL;
static HANDLE outEvent    = NULL;
static HANDLE inHandle    = NULL;
static unsigned outResult = 0;

/*
 * Query worker thread.
 */
static DWORD queryWorker(LPVOID arg)
{
    UINT8 buf[8192];
    ULONG returnLength;

    while (WaitForSingleObject(inEvent, INFINITE) == WAIT_OBJECT_0)
    {
        if (!NT_SUCCESS(NtQueryObject(inHandle, ObjectNameInformation,
                buf, sizeof(buf)-1, &returnLength)))
        {
            // Name too big == not WinDivert:
            outResult = FALSE;
            SetEvent(outEvent);
            continue;
        }
		const UNICODE_STRING *name = (const UNICODE_STRING *)buf;

        // Check for WinDivert:
        outResult = isWinDivertDevice(name->Buffer, name->Length);
        SetEvent(outEvent);
    }

    return 0;
}

/*
 * Query handle.
 */
static unsigned queryHandle(HANDLE handle, PSYSTEM_HANDLE sysHandle,
    const char *exe)
{
    const DWORD timeout = 80;               // 80ms
    DWORD result;

    // The call to NtQueryObject can sometimes hang.  To work around this
    // issue, we call NtQueryObject from a separate thread with a timeout.

    if (queryThread == NULL)
    {
        inEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (inEvent == NULL)
            error("failed to create event", GetLastError());
        outEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (outEvent == NULL)
            error("failed to create event", GetLastError());
        queryThread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)queryWorker, NULL, 0, NULL);
        if (queryThread == NULL)
            error("failed to create query thread", GetLastError());
    }

    inHandle = handle;
    SetEvent(inEvent);

    // Wait for the result from the worker.
    switch (result = WaitForSingleObject(outEvent, timeout))
    {
        case WAIT_TIMEOUT:
            if (!TerminateThread(queryThread, 1))
                error("failed to terminate query thread", GetLastError());
            ResetEvent(inEvent);
            queryThread = CreateThread(NULL, 0,
                (LPTHREAD_START_ROUTINE)queryWorker, NULL, 0, NULL);
            warning("failed to query handle (%u) for process %d (%s)",
                WAIT_TIMEOUT, sysHandle->Handle, sysHandle->ProcessId, exe);
            if (WaitForSingleObject(outEvent, 0) != WAIT_OBJECT_0)
                return 0;
            // Fallthrough:
        case WAIT_OBJECT_0:
            return outResult;
        default:
            error("failed to wait for query thread", result);
            return 0;
    }
}

static void queryWinDivertHandles()
{
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION info;
    ULONG size = (1 << 23);         // 8MB
    DWORD pid = 0, myPid = GetCurrentProcessId();
    char path[MAX_PATH+1];
    const char *exe = "???";
    DWORD len;
    HANDLE process = NULL;
    unsigned version;
    ULONG i;

    // STEP #1: Get the system handle information:
    info = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (info == NULL)
    {
allocation_failed_error:
        error("failed to allocate %u bytes for handle information",
            GetLastError(), size);
    }
    while ((status = NtQuerySystemInformation(SystemHandleInformation,
                info, size, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (!VirtualFree(info, 0, MEM_RELEASE))
            warning("failed to free %u bytes for handle information",
                GetLastError(), size);
        size *= 2;
        info = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (info == NULL)
            goto allocation_failed_error;
    }
    if (!NT_SUCCESS(status))
        error("failed to query handle information (status=0x%.8x)",
            ERROR_SUCCESS, status);
    
    log("found %u handle entries with total size of %ubytes",
        info->HandleCount, info->HandleCount * sizeof(SYSTEM_HANDLE));

    log("scanning all entries for handles to a legacy WinDivert device "
        "(it is normal to see timeouts)");
    for (i = 0; i < info->HandleCount; i++)
    {
        PSYSTEM_HANDLE handle = info->Handles + i;
        HANDLE dupHandle = NULL;

        if (handle->ProcessId == myPid)
            continue;

        // 36 == File handle:
        if (handle->ObjectTypeNumber != 36)
            continue;

        // Get process:
        if (handle->ProcessId != pid)
        {
            if (process != NULL)
                CloseHandle(process);
            process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_READ |
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE,
                handle->ProcessId);
            pid = handle->ProcessId;
            exe = "???";
            if (process == NULL)
            {
                if (handle->ProcessId == 0 ||
                        GetLastError() == ERROR_ACCESS_DENIED)
                {
                    // This error occurs for system processes (which do not use
                    // WinDivert anyway), so ignore it.
                    continue;
                }
                warning("failed to open process %d", GetLastError(),
                    handle->ProcessId);
            }
            else
            {
                len = sizeof(path)-1;
                if (QueryFullProcessImageNameA(process, 0, path, &len))
                    exe = path;
            }
        }
        if (process == NULL)
            continue;

        // Duplicate handle:
        if (!NT_SUCCESS(NtDuplicateObject(process,
                (PVOID)(UINT_PTR)handle->Handle, GetCurrentProcess(),
                &dupHandle, 0, 0, 0)))
            continue;

        // Check for WinDivert:
        version = queryHandle(dupHandle, handle, exe);
        CloseHandle(dupHandle);
        if (version == 0)
            continue;
        
        // Handle belongs to WinDivert.
        log("found WinDivert handle (pid=%d, handle=%u, exe=\"%s\", "
                "version=\"%s\")", handle->ProcessId, handle->Handle, exe,
                versionToString(version));

        addHandleEntry(handle->ProcessId, process, exe,
            (HANDLE)(UINT_PTR)handle->Handle, version);
    }

    VirtualFree(info, 0, MEM_RELEASE);
    if (process != NULL)
        CloseHandle(process);
}

/****************************************************************************/
/* ENTRY                                                                    */
/****************************************************************************/

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    const char *logName = "WinDivertTool.log";
    char logPath[MAX_PATH+1];
    DWORD r, err;
    BOOL force = FALSE, killed = TRUE, uninstalled = TRUE;
    HRESULT result;
    HMODULE ntdll;

    console = GetStdHandle(STD_OUTPUT_HANDLE);
    err = GetLastError();
    
    if (argc > 3)
    {
usage:
        writeStr("usage: WinDivertTool.exe\n");
        writeStr("       WinDivertTool.exe list\n");
        writeStr("       WinDivertTool.exe [--force] kill\n");
        writeStr("       WinDivertTool.exe [--force] uninstall\n\n");
        writeStr("COMMANDS:\n\n");
        writeStr("\tlist\n");
        writeStr("\t\tList all programs using WinDivert.\n");
        writeStr("\tkill\n");
        writeStr("\t\tForcibly terminate all programs using WinDivert.\n");
        writeStr("\tuninstall\n");
        writeStr("\t\tForcibly terminate all programs using WinDivert and\n");
        writeStr("\t\tuninstall all WinDivert drivers.\n\n");
        writeStr("OPTIONS:\n\n");
        writeStr("\t--force\n");
        writeStr("\t\tDo not prompt before terminating programs.\n\n");
        return 0;
    }
    else if (argc == 3)
    {
        if (lstrcmpiA(argv[1], "--force") != 0)
            goto usage;
        else if (lstrcmpiA(argv[2], "kill") == 0)
            mode = MODE_KILL;
        else if (lstrcmpiA(argv[2], "uninstall") == 0)
            mode = MODE_UNINSTALL;
        else
            goto usage;
        force = TRUE;
    }
    else if (argc == 2)
    {
        if (lstrcmpiA(argv[1], "list") == 0)
            mode = MODE_LIST;
        else if (lstrcmpiA(argv[1], "kill") == 0)
            mode = MODE_KILL;
        else if (lstrcmpiA(argv[1], "uninstall") == 0)
            mode = MODE_UNINSTALL;
        else
            goto usage;
    }

    r = GetTempPathA(sizeof(logPath)-1, logPath);
    if (r > 0 && r <= MAX_PATH)
    {
        result = StringCchCatA(logPath, sizeof(logPath)-1, logName);
        if (!FAILED(result))
        {
            (VOID)DeleteFileA(logPath);
            log = CreateFileA(logPath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    r = GetLastError();

    SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	writeStr("__      ___      ___  _             _  _____         _\n");
	writeStr("\\ \\    / (_)_ _ |   \\(_)_ _____ _ _| ||_   _|__  ___| |\n");
	writeStr(" \\ \\/\\/ /| | ' \\| |) | \\ V / -_) '_|  _|| |/ _ \\/ _ "
		"\\ |\n");
	writeStr("  \\_/\\_/ |_|_||_|___/|_|\\_/\\___|_|  \\__||_|\\___/\\__"
		"_/_|");
    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
        FOREGROUND_BLUE | FOREGROUND_INTENSITY);    
    writeStr(" VERSION ");
    writeInt(WINDIVERT_VERSION_MAJOR);
    writeChar('.');
    writeInt(WINDIVERT_VERSION_MINOR);
    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
        FOREGROUND_BLUE);    
    writeStr("\n\nWinDivertTool ");
    writeInt(WINDIVERT_VERSION_MAJOR);
    writeChar('.');
    writeInt(WINDIVERT_VERSION_MINOR);
	writeStr(" Copyright (C) 2019 basil\n");
    writeStr("License GPLv3+: GNU GPL version 3 or later "
        "<http://gnu.org/licenses/gpl.html>.\n");
    writeStr("This is free software: you are free to change and "
		"redistribute it.\n");
    writeStr("There is NO WARRANTY, to the extent permitted by law.\n\n");

    if (console == INVALID_HANDLE_VALUE)
        warning("failed to open console", err);
    if (log == INVALID_HANDLE_VALUE)
        warning("failed to open log file \"%s\"", r, logName);
    else
        log("saving a copy of the output to file \"%s\"", logPath);

    log("initializing the WinDivert runtime");
    if (!WinDivertDllEntry(GetCurrentProcess(), DLL_PROCESS_ATTACH, NULL))
        error("failed to initiaiize the WinDivert runtime", GetLastError());

    log("loading %s", "ntdll.dll");
    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL)
        error("failed to get \"%s\" handle", GetLastError(), "ntdll.dll");
    NtQuerySystemInformation = (PVOID)GetProcAddress(ntdll,
        "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL)
        error("failed to get \"%s\" from \"%s\"", GetLastError(),
            "NtQuerySystemInformation", "ntdll.dll");
    NtDuplicateObject = (PVOID)GetProcAddress(ntdll, "NtDuplicateObject");
    if (NtDuplicateObject == NULL)
        error("failed to get \"%s\" from \"%s\"", GetLastError(),
            "NtDuplicateObject", "ntdll.dll");
    NtQueryObject = (PVOID)GetProcAddress(ntdll, "NtQueryObject");
    if (NtQueryObject == NULL)
        error("failed to get \"%s\" from \"%s\"", GetLastError(),
            "NtQueryObject", "ntdll.dll");

    log("PASS #1: detecting handles to WinDivert drivers version 2.0.0 "
        "or above");
    queryWinDivertDriver();

    log("PASS #2: detecting handles to legacy WinDivert drivers version "
        "1.4.X or below");
    queryWinDivertHandles();

    switch (mode)
    {
        case MODE_KILL:
            killed = killAll(force);
            break;
        case MODE_UNINSTALL:
            killed      = killAll(force);
            uninstalled = uninstallWinDivert();
            break;
    }

    log("printing report:");
    printReport(killed, uninstalled);

    exitTool(0);
}

