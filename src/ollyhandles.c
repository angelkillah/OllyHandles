#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winternl.h>
#include <tlhelp32.h>

#include "plugin.h"

#define PLUGIN_NAME		L"OllyHandles"    
#define VERSION			L"2.00.00"      

#define SystemHandleInformation		16
#define ObjectNameInformation		1
#define ObjectTypeInformation		2

#define STATUS_INFO_LENGTH_MISMATCH		0xC0000004

typedef NTSTATUS(WINAPI *ZWQUERYSYSTEMINFORMATION)(ULONG SystemInformationClass,
												   PVOID SystemInformation,
												   ULONG SystemInformationLength,
												   PULONG ReturnLength);

typedef NTSTATUS(WINAPI *ZWQUERYOBJECT)(HANDLE Handle,
										ULONG ObjectInformationClass,
										PVOID ObjectInformation,
										ULONG ObjectInformationLength,
										PULONG ReturnLength);


typedef struct _SYSTEM_HANDLE {
	ULONG		uIdProcess;
	UCHAR		ObjectType;    
	UCHAR		Flags;         
	USHORT		Handle;
	ULONG		pObject;
	ACCESS_MASK	GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;


typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG			uCount;
	SYSTEM_HANDLE	Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


typedef struct _HANDLE_DATA {
  DWORD		dwHandle;  // handle id
  wchar_t   wType[TEXTLEN];  // resource type
  wchar_t   wName[TEXTLEN];  // resource name
} HANDLE_DATA, *PHANDLE_DATA;

HINSTANCE hdllinst = NULL;             
t_table   handletable = {{0}};          


////////////////////////////////////////////////////////////////////////////////
//////////////////////////// DRAWING FUNC //////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int handletable_draw(wchar_t *s,uchar *mask,int *select, t_table *pt,t_drawheader *ph,int column,void *cache) 
{  
	int len = 0;
	PHANDLE_DATA pHandleData = (PHANDLE_DATA)ph;

	switch(column) 
	{
    case 0: // column 0 (Handle)
		len = swprintf(s, TEXTLEN, L"0x%08x", pHandleData->dwHandle);
		break;
	case 1: // column 1 (Type)
		len = swprintf(s, TEXTLEN, L"%ws", pHandleData->wType);
		break;
	case 2: // column 2 (Name)
		len = swprintf(s, TEXTLEN, L"%ws", pHandleData->wName);
		break;
    default:
		break;
	}
  return len;
}

long handletable_proc(t_table *pt, HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
	switch(msg)
	{
	case WM_USER_UPD: // called on automatic update, table must update its contents
		InvalidateRect(pt->hw, NULL, FALSE); // the entire window should be redrawn
		break;
	case WM_USER_CREATE:
		Setautoupdate(&handletable, 1);
		break;
	default:
		break;
	}
	return 0;
}


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// PAYLOAD //////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

BOOL wrapper_ZwQuerySystemInformation(PSYSTEM_HANDLE_INFORMATION *pSystemHandleInformation)
{
	DWORD dwSize = 0;
	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;

	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	
	dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);
	*pSystemHandleInformation = malloc(dwSize);
	
	if(ZwQuerySystemInformation(SystemHandleInformation, *pSystemHandleInformation, dwSize, &dwSize) == STATUS_INFO_LENGTH_MISMATCH) 
	{	
		free(*pSystemHandleInformation);
		*pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(dwSize);
		return (ZwQuerySystemInformation(SystemHandleInformation, *pSystemHandleInformation, dwSize, &dwSize) == 0);
	}
	
    return FALSE;
}

// retrieve the child PID (the debugged process)	
DWORD get_debugged_pid()
{
	DWORD current_pid;
	DWORD debugged_pid = 0;
	HANDLE hSnapshot;
	PROCESSENTRY32 pe = {0};

	current_pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);
	if(Process32First(hSnapshot, &pe))
	{
		do
		{
			if(pe.th32ParentProcessID == current_pid)
			{
				debugged_pid = pe.th32ProcessID;
				break;
			}
		} while(Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return debugged_pid;
}

void payload()
{
	NTSTATUS ret;
	HANDLE_DATA handledata = {0};
	HANDLE hProcess;
	HANDLE hDupHandle;
	PVOID ObjectNameInfo = NULL;
	PVOID ObjectTypeInfo = NULL;
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectType;
	PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = NULL;
	ZWQUERYOBJECT ZwQueryObject = NULL;
	DWORD debugged_pid = 0;
	DWORD dwSize = 0;
	DWORD i = 0;


    if (!(wrapper_ZwQuerySystemInformation (&pSystemHandleInformation))) {
        return;
    }
    
	/* clear log table */
	Deletesorteddatarange(&(handletable.sorted), 0x00000000, 0xFFFFFFFF);

	ZwQueryObject = (ZWQUERYOBJECT)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");

	debugged_pid = get_debugged_pid();

	for(i=0; i<pSystemHandleInformation->uCount; i++)
	{
		if(pSystemHandleInformation->Handles[i].uIdProcess == debugged_pid)
		{			
			handledata.dwHandle = pSystemHandleInformation->Handles[i].Handle;
			hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pSystemHandleInformation->Handles[i].uIdProcess);
			if(hProcess == INVALID_HANDLE_VALUE)
				exit(0);

			if(DuplicateHandle(hProcess, (HANDLE)handledata.dwHandle, GetCurrentProcess(), &hDupHandle, 0, 0, 0) != 0)
			{
				ObjectNameInfo = malloc(0x1000);
				ret = ZwQueryObject(hDupHandle, ObjectNameInformation, ObjectNameInfo, 0x1000, &dwSize);
				if(ret == STATUS_INFO_LENGTH_MISMATCH)
				{
					free(ObjectNameInfo);
					ObjectNameInfo = malloc(dwSize);
				}
				ObjectName = *(PUNICODE_STRING)ObjectNameInfo;

				ObjectTypeInfo = malloc(0x1000);
				ret = ZwQueryObject(hDupHandle, ObjectTypeInformation, ObjectTypeInfo, 0x1000, &dwSize);
				if(ret == STATUS_INFO_LENGTH_MISMATCH)
				{
					free(ObjectTypeInfo);
					ObjectTypeInfo = malloc(dwSize);
				}
				ObjectType = *(PUNICODE_STRING)ObjectTypeInfo;
				
				swprintf(handledata.wType, TEXTLEN, L"%ls", ObjectType.Buffer);
				swprintf(handledata.wName, TEXTLEN, L"%ls", ObjectName.Buffer);
				Addsorteddata(&(handletable.sorted), &handledata);		
			}			
		}
	}
	free(pSystemHandleInformation);
	free(ObjectNameInfo);
	free(ObjectTypeInfo);
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////// PLUGIN MENU WINDOWS ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Menu processing function
static int menu_handler(t_table *pt,wchar_t *name,ulong index,int mode) {
	if (mode==MENU_VERIFY)
		return MENU_NORMAL;                
	else if (mode==MENU_EXECUTE) 
	{
		if (handletable.hw==NULL)
			Createtablewindow(&handletable,0,handletable.bar.nbar,NULL,NULL,PLUGIN_NAME);
		else
			Activatetablewindow(&handletable);
		if(get_debugged_pid())
			payload();
		return MENU_REDRAW;
	}
	return MENU_ABSENT;
}

static t_menu mainmenu[] = {
  { L"OllyHandles",
       L"Open handles window",
       KK_DIRECT | KK_CTRL | 'L', menu_handler, NULL, 0},
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

t_menu *ODBG2_Pluginmenu(wchar_t *type) {

	if(wcscmp(type, PWM_MAIN) == 0 || wcscmp(type, PWM_DISASM) == 0)
		return mainmenu;
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// PLUGIN INITIALIZATION /////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static t_menu handlesmenu[] = {       
  { L"|>STANDARD",
       L"",                            
       K_NONE, NULL, NULL, 0
  }
};

BOOL WINAPI DllEntryPoint(HINSTANCE hi,DWORD reason,LPVOID reserved) 
{
	if (reason==DLL_PROCESS_ATTACH)
		hdllinst=hi;                       
	return 1;                           
}

int ODBG2_Pluginquery(int ollydbgversion,ulong *features, wchar_t pluginname[SHORTNAME],wchar_t pluginversion[SHORTNAME]) 
{
	if (ollydbgversion<201)
		return 0;
	StrcopyW(pluginname, SHORTNAME, PLUGIN_NAME);       
	StrcopyW(pluginversion, SHORTNAME, VERSION);       
	return PLUGIN_VERSION;               
}

int ODBG2_Plugininit(void) 
{	
	if(Createsorteddata(&handletable.sorted, sizeof(HANDLE_DATA), 1, NULL , NULL, SDM_NOSIZE) != 0) 
	{
		Addtolist(0, DRAW_HILITE, L"[%s]: Unable to created sorted table data.", PLUGIN_NAME);
		return -1;
	}

	StrcopyW(handletable.name,SHORTNAME,PLUGIN_NAME);

	handletable.mode = TABLE_SAVEPOS | TABLE_AUTOUPD;        
    handletable.bar.visible = 1; 

    handletable.bar.name[0] = L"Handle";
	handletable.bar.expl[0] = L"";
    handletable.bar.mode[0] = BAR_FLAT;
    handletable.bar.defdx[0] = 24;

    handletable.bar.name[1] = L"Type";
	handletable.bar.expl[1] = L"";
    handletable.bar.mode[1] = BAR_FLAT;
    handletable.bar.defdx[1] = 30;

    handletable.bar.name[2] = L"Name";
	handletable.bar.expl[2] = L"";
    handletable.bar.mode[2] = BAR_FLAT;
    handletable.bar.defdx[2] = 256;
    
	handletable.bar.nbar = 3;
	handletable.tabfunc = (TABFUNC*)handletable_proc;
    handletable.custommode = 0;
    handletable.customdata = NULL;
    handletable.updatefunc = NULL;
    handletable.drawfunc = (DRAWFUNC *)handletable_draw;
    handletable.tableselfunc = NULL;
    handletable.menu = (t_menu*)handlesmenu;

	return 0;
}

void ODBG2_Pluginreset(void)
{
	Deletesorteddatarange(&(handletable.sorted), 0x00000000, 0xFFFFFFFF);
}

void ODBG2_Plugindestroy(void)
{
	Destroysorteddata(&(handletable.sorted));
}


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// PLUGIN EVENTS /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

void ODBG2_Pluginnotify (int iCode, void *pData, DWORD dwParam1, DWORD dwParam2)
{
	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(dwParam1);
	UNREFERENCED_PARAMETER(dwParam2);

	switch (iCode) {
        case PN_NEWPROC:
        case PN_NEWTHR:
        case PN_PREMOD:
        case PN_NEWMOD:
	    case PN_RUN:
            // Whenever the execution status change, refresh the plugin table
            if (get_debugged_pid ()) {
			    payload();
            }
		break;

	    default:
		break;
	}
}