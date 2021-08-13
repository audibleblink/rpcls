package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS   = 0x1F0FFF
	SE_PRIVILEGE_ENABLED = 0x00000002
	PID                  = 0
)

func main() {
	err := sePrivEnable("SeDebugPrivilege")
	if err != nil {
		fmt.Printf("seDebug: %s\n", err)
		os.Exit(1)
	}
	// time.Sleep(90 * time.Second)

	pidHandle, err := handleForPid(PID)
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

func handleForPid(pid int) (handle windows.Handle, err error) {
	if pid == 0 {
		return windows.CurrentProcess(), err
	}
	// attrs := PROCESS_ALL_ACCESS
	attrs := windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	handle, err = windows.OpenProcess(uint32(attrs), false, uint32(pid))
	return
}

func getProcessBasicInformation(processHandle windows.Handle) (pbi windows.PROCESS_BASIC_INFORMATION, err error) {
	pbiLen := uint32(unsafe.Sizeof(pbi))
	err = windows.NtQueryInformationProcess(processHandle, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), pbiLen, &pbiLen)
	if err != nil {
		return
	}

	pbiStructLen := unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})
	if pbiLen < uint32(pbiStructLen) {
		err = fmt.Errorf("Bad size for process_basic_information")
		return
	}
	return
}

func sePrivEnable(privString string) (err error) {
	procHandle := windows.CurrentProcess()

	var tokenHandle windows.Token
	windows.OpenProcessToken(procHandle, windows.TOKEN_ADJUST_PRIVILEGES, &tokenHandle)

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privString), &luid)
	if err != nil {
		return err
	}

	privs := &windows.Tokenprivileges{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = uint32(SE_PRIVILEGE_ENABLED)

	returnLen := uint32(0)
	err = windows.AdjustTokenPrivileges(tokenHandle, false, privs, 0, nil, &returnLen)
	return err
}
