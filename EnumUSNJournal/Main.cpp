#include <Windows.h>
#include <WinIoCtl.h>
#include <stdio.h>

#define BUFFER_SIZE 4096

void FormatDateTime(PSYSTEMTIME ptm, LPTSTR szBuffer, DWORD iBuffLen)
{
	SYSTEMTIME tmSys;
	if (ptm)
		tmSys = *ptm;
	else
		GetLocalTime(&tmSys);
	sprintf_s(szBuffer, iBuffLen,
		"%04d-%02d-%02d %02d:%02d:%02d.%03d",
		tmSys.wYear, tmSys.wMonth, tmSys.wDay,
		tmSys.wHour, tmSys.wMinute, tmSys.wSecond,
		tmSys.wMilliseconds);
}

//void show_record(HANDLE hVol, PUSN_RECORD pRecord, USN max_usn, LPTSTR szBuffer, DWORD iBuffLen)
//{
//	DWORD bytecount = 1;
//
//	printf("=================================================================\n");
//	printf("RecordLength: %u\n", pRecord->RecordLength);
//	printf("MajorVersion: %u\n", (DWORD)pRecord->MajorVersion);
//	printf("MinorVersion: %u\n", (DWORD)pRecord->MinorVersion);
//	printf("FileReferenceNumber: %lu\n", pRecord->FileReferenceNumber);
//	printf("ParentFRN: %lu\n", pRecord->ParentFileReferenceNumber);
//	printf("USN: %lu\n", pRecord->Usn);
//	printf("Timestamp: %lu\n", pRecord->TimeStamp);
//	printf("Reason: %u\n", pRecord->Reason);
//	printf("SourceInfo: %u\n", pRecord->SourceInfo);
//	printf("SecurityId: %u\n", pRecord->SecurityId);
//	printf("FileAttributes: %x\n", pRecord->FileAttributes);
//	printf("FileNameLength: %u\n", (DWORD)pRecord->FileNameLength);
//
//	//printf("FileName: %.*ls\n", filenameend - filename, filename);
//	printf("File name: %.*S\n", pRecord->FileNameLength / 2, pRecord->FileName);
//
//	//buffer = VirtualAlloc(NULL, BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
//	MFT_ENUM_DATA_V0 mft_enum_data = { 0 };
//	mft_enum_data.StartFileReferenceNumber = pRecord->ParentFileReferenceNumber;
//	mft_enum_data.LowUsn = 0;
//	mft_enum_data.HighUsn = max_usn;
//
//	memset(szBuffer, 0, BUFFER_SIZE);
//	if (!DeviceIoControl(hVol, FSCTL_ENUM_USN_DATA, &mft_enum_data, sizeof(mft_enum_data), szBuffer, BUFFER_SIZE, &bytecount, NULL))
//	{
//		printf("FSCTL_ENUM_USN_DATA (show_record): %u\n", GetLastError());
//		return;
//	}
//
//	PUSN_RECORD parent_record = (PUSN_RECORD)(((PUCHAR)szBuffer) + sizeof(USN));
//
//	if (parent_record->FileReferenceNumber != pRecord->ParentFileReferenceNumber)
//	{
//		printf("=================================================================\n");
//		printf("Couldn't retrieve FileReferenceNumber %u\n", pRecord->ParentFileReferenceNumber);
//		return;
//	}
//
//	show_record(hVol, parent_record, max_usn, szBuffer, iBuffLen);
//}

bool GetFullPathByFileReferenceNumber(HANDLE hVol, DWORDLONG FileReferenceNumber)
{
	typedef ULONG(__stdcall *PNtCreateFile)(
		PHANDLE FileHandle,
		ULONG DesiredAccess,
		PVOID ObjectAttributes,
		PVOID IoStatusBlock,
		PLARGE_INTEGER AllocationSize,
		ULONG FileAttributes,
		ULONG ShareAccess,
		ULONG CreateDisposition,
		ULONG CreateOptions,
		PVOID EaBuffer,
		ULONG EaLength);
	PNtCreateFile NtCreatefile = (PNtCreateFile)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateFile");

	typedef struct _UNICODE_STRING {
		USHORT Length, MaximumLength;
		PWCH Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;
	UNICODE_STRING fidstr = { 8, 8, (PWSTR)&FileReferenceNumber };

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES;
	const ULONG OBJ_CASE_INSENSITIVE = 0x00000040UL;
	OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), hVol, &fidstr, OBJ_CASE_INSENSITIVE, 0, 0 };

	HANDLE hFile;
	ULONG iosb[2];
	const ULONG FILE_OPEN_BY_FILE_ID = 0x00002000UL;
	const ULONG FILE_OPEN = 0x00000001UL;
	ULONG status = NtCreatefile(&hFile, GENERIC_ALL, &oa, iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_OPEN_BY_FILE_ID, NULL, 0);
	if (status == 0)
	{
		typedef struct _IO_STATUS_BLOCK {
			union {
				NTSTATUS Status;
				PVOID Pointer;
			};
			ULONG_PTR Information;
		} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
		typedef enum _FILE_INFORMATION_CLASS {
			// бнбн
			FileNameInformation = 9
			// бнбн
		} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
		typedef NTSTATUS(__stdcall *PNtQueryInformationFile)(
			HANDLE FileHandle,
			PIO_STATUS_BLOCK IoStatusBlock,
			PVOID FileInformation,
			DWORD Length,
			FILE_INFORMATION_CLASS FileInformationClass);
		PNtQueryInformationFile NtQueryInformationFile = (PNtQueryInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationFile");

		typedef struct _OBJECT_NAME_INFORMATION {
			UNICODE_STRING Name;
		} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
		IO_STATUS_BLOCK IoStatus;
		size_t allocSize = sizeof(OBJECT_NAME_INFORMATION) + MAX_PATH * sizeof(WCHAR);
		POBJECT_NAME_INFORMATION pfni = (POBJECT_NAME_INFORMATION)operator new(allocSize);
		status = NtQueryInformationFile(hFile, &IoStatus, pfni, allocSize, FileNameInformation);
		if (status == 0)
		{
			printf("C:\%.*S\n", pfni->Name.Length / 2, &pfni->Name.Buffer);
		}
		operator delete(pfni);

		CloseHandle(hFile);
	}

	return status == 0;
}

int main()
{
	HANDLE hVol = INVALID_HANDLE_VALUE;
	hVol = CreateFile(TEXT("\\\\.\\D:"),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);

	if (hVol == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed (%d)\n", GetLastError());
		return 0;
	}

	USN_JOURNAL_DATA JournalData = { 0 };
	DWORD dwBytes = 0;;
	BOOL bRet = DeviceIoControl(hVol,
		FSCTL_QUERY_USN_JOURNAL,
		NULL,
		0,
		&JournalData,
		sizeof(JournalData),
		&dwBytes,
		NULL);
	if (!bRet)
	{
		printf("Query journal failed (%d)\n", GetLastError());
		return 0;
	}

	printf("UsnJournalID: %lu\n", JournalData.UsnJournalID);
	printf("FirstUsn: %lu\n", JournalData.FirstUsn);
	printf("NextUsn: %lu\n", JournalData.NextUsn);
	printf("LowestValidUsn: %lu\n", JournalData.LowestValidUsn);
	printf("MaxUsn: %lu\n", JournalData.MaxUsn);
	printf("MaximumSize: %lu\n", JournalData.MaximumSize);
	printf("AllocationDelta: %lu\n", JournalData.AllocationDelta);

	//MFT_ENUM_DATA_V1 mft_enum_data = { 0 };
	MFT_ENUM_DATA_V0 mft_enum_data = { 0 };
	//mft_enum_data.StartFileReferenceNumber = 0;
	//mft_enum_data.LowUsn = 0;
	mft_enum_data.HighUsn = JournalData.NextUsn;

	CHAR Buffer[BUFFER_SIZE];
	DWORD BytesReturned = 0;
	PUSN_RECORD UsnRecord;
	//DWORDLONG filecount = 0;

	for (;;)
	{
		memset(Buffer, 0, BUFFER_SIZE);
		bRet = DeviceIoControl(hVol,
			FSCTL_ENUM_USN_DATA,
			&mft_enum_data,
			sizeof(mft_enum_data),
			Buffer, BUFFER_SIZE,
			&BytesReturned, NULL);
		if (!bRet)
		{
			printf("FSCTL_ENUM_USN_DATA: %u\n", GetLastError());
			//printf("File count: %lu\n", filecount);
			//GetTickCount();
			break;
		}
		DWORD dwRetBytes = BytesReturned - sizeof(USN);
		// Find the first record
		PUSN_RECORD UsnRecord = (PUSN_RECORD)(((PUCHAR)Buffer) + sizeof(USN));
		// This loop could go on for a long time, given the current buffer size.
		while (UsnRecord && dwRetBytes > 0)
		{
			printf("RecordLength: %d\n", UsnRecord->RecordLength);
			printf("MajorVersion: %d\n", UsnRecord->MajorVersion);
			printf("MinorVersion: %d\n", UsnRecord->MinorVersion);
			printf("FileReferenceNumber: %I64x\n", UsnRecord->FileReferenceNumber);
			printf("ParentFileReferenceNumber: %I64x\n", UsnRecord->ParentFileReferenceNumber);
			printf("USN: %I64x\n", UsnRecord->Usn);
			FILETIME filetime;
			filetime.dwLowDateTime = UsnRecord->TimeStamp.LowPart;
			filetime.dwHighDateTime = UsnRecord->TimeStamp.HighPart;
			SYSTEMTIME sysTime;
			FileTimeToSystemTime(&filetime, &sysTime);
			CHAR szBuff[64] = { 0 };
			FormatDateTime(&sysTime, szBuff, 64);
			printf("TimeStamp: %s\n", szBuff);
			printf("Reason: 0x%x\n", UsnRecord->Reason);
			printf("File name: %.*S\n", UsnRecord->FileNameLength / 2, UsnRecord->FileName);
			//char fileName[MAX_PATH] = {0};
			//WideCharToMultiByte(CP_OEMCP,NULL,UsnRecord->FileName,strLen/2,fileName,strLen,NULL,FALSE);
			bool bR = GetFullPathByFileReferenceNumber(hVol, UsnRecord->ParentFileReferenceNumber);
			//if (bR)
			//	printf("\\%S\n", UsnRecord->FileName);
			//else
			//	printf("???\\%S\n", UsnRecord->FileName);
			printf("-------------------------------------------------------------------------------------\n");
			
			if (UsnRecord->RecordLength == 0)
			{
				break;
			}
			//show_record(hVol, UsnRecord, JournalData.NextUsn, Buffer, BUFFER_SIZE);
			dwRetBytes -= UsnRecord->RecordLength;
			// Find the next record
			UsnRecord = (PUSN_RECORD)((PCHAR)UsnRecord + UsnRecord->RecordLength);
		}
		// Update starting USN for next call
		mft_enum_data.StartFileReferenceNumber = *(USN *)&Buffer;
		Sleep(200);
	}

	CloseHandle(hVol);
	return 0;
}