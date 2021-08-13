package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

func main() {
	err := sePrivEnable("SeDebugPrivilege")
	if err != nil {
		fmt.Printf("seDebug: %s\n", err)
		os.Exit(1)
	}

	pidHandle, err := handleToSelf()
	if err != nil {
		fmt.Printf("pidHandle: %s\n", err)
		os.Exit(1)
	}

	pbi, err := getProcessBasicInformation(pidHandle)
	if err != nil {
		fmt.Printf("getPBI: %s\n", err)
		os.Exit(1)
	}

	ldr := pbi.PebBaseAddress.Ldr
	for cur := ldr.InMemoryOrderModuleList.Flink; cur != &ldr.InMemoryOrderModuleList; cur = cur.Flink {
		curP := unsafe.Pointer(cur)
		structOffset := unsafe.Offsetof(windows.LDR_DATA_TABLE_ENTRY{}.InMemoryOrderLinks)
		entry := (*windows.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(curP) - structOffset))
		fmt.Printf("%s\n", entry.FullDllName.String())
	}
}

func handleToSelf() (handle windows.Handle, err error) {
	// var attrs uint32 = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	attrs := uint32(PROCESS_ALL_ACCESS)
	pid := uint32(os.Getpid())
	// pid := uint32(16920)
	handle, err = windows.OpenProcess(attrs, false, pid)
	return
}

// https://github.com/shenwei356/rush/blob/3699d8775d5f4d429351700fea4231de0ec1e281/process/process_windows.go#L251
func getProcessBasicInformation(processHandle windows.Handle) (pbi windows.PROCESS_BASIC_INFORMATION, err error) {
	pbiLen := uint32(unsafe.Sizeof(pbi))
	err = windows.NtQueryInformationProcess(processHandle, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), pbiLen, &pbiLen)
	if err != nil {
		return
	}

	pbiStructLen := unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})
	if pbiLen < uint32(pbiStructLen) {
		err = fmt.Errorf("Bad size for PROCESS_BASIC_INFORMATION")
		return
	}
	return
}

func sePrivEnable(s string) error {

	TH32CS_SNAPPROCESS := 0x00000002

	type LUID struct {
		LowPart  uint32
		HighPart int32
	}
	type LUID_AND_ATTRIBUTES struct {
		Luid       LUID
		Attributes uint32
	}
	type TOKEN_PRIVILEGES struct {
		PrivilegeCount uint32
		Privileges     [1]LUID_AND_ATTRIBUTES
	}

	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges := modadvapi32.NewProc("AdjustTokenPrivileges")

	procLookupPriv := modadvapi32.NewProc("LookupPrivilegeValueW")
	var tokenHandle syscall.Token
	thsHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	syscall.OpenProcessToken(
		thsHandle,                       //  HANDLE  ProcessHandle,
		syscall.TOKEN_ADJUST_PRIVILEGES, //	DWORD   DesiredAccess,
		&tokenHandle,                    //	PHANDLE TokenHandle
	)
	var luid LUID
	r, _, e := procLookupPriv.Call(
		uintptr(0), //LPCWSTR lpSystemName,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))), //LPCWSTR lpName,
		uintptr(unsafe.Pointer(&luid)),                       //PLUID   lpLuid
	)
	if r == 0 {
		return e
	}
	SE_PRIVILEGE_ENABLED := uint32(TH32CS_SNAPPROCESS)
	privs := TOKEN_PRIVILEGES{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&privs)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if r == 0 {
		return e
	}
	return nil
}
