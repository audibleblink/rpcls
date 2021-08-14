package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SizeofListEntry      = 0x20
	ListEntryOffset      = 0x20
	PROCESS_ALL_ACCESS   = 0x1F0FFF
	SE_PRIVILEGE_ENABLED = 0x00000002
	PID                  = 8408
	// PID = 0
)

func main() {
	err := sePrivEnable("SeDebugPrivilege")
	if err != nil {
		fmt.Printf("seDebug: %s\n", err)
		os.Exit(1)
	}

	pidHandle, err := handleForPid(PID)
	if err != nil {
		fmt.Printf("pidHandle: %s\n", err)
		os.Exit(1)
	}

	pbi, err := procBasicInfo(pidHandle)
	if err != nil {
		fmt.Printf("getPBI: %s\n", err)
		os.Exit(1)
	}

	// partially fill the peb to get access to the Ldr.InMemoryOrderModuleList
	err = fillRemotePEB(pidHandle, &pbi)
	if err != nil {
		fmt.Printf("readRemotePEB: %s\n", err)
		os.Exit(1)
	}

	head := windows.LDR_DATA_TABLE_ENTRY{}
	head.InMemoryOrderLinks.Flink = pbi.PebBaseAddress.Ldr.InMemoryOrderModuleList.Flink

	stop := uintptr(unsafe.Pointer(pbi.PebBaseAddress.Ldr)) - ListEntryOffset

	for uintptr(unsafe.Pointer(head.InMemoryOrderLinks.Flink)) != stop {
		base := unsafe.Pointer(head.InMemoryOrderLinks.Flink)
		size := uint32(unsafe.Sizeof(head))
		dest := unsafe.Pointer(&head.InMemoryOrderLinks.Flink)
		err = readMemory(pidHandle, base, dest, size)
		if err != nil {
			fmt.Printf("fart: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("%#v\n", head.FullDllName.String())
	}

}

func handleForPid(pid int) (handle windows.Handle, err error) {
	if pid == 0 {
		handle = windows.CurrentProcess()
		return
	}
	// attrs := windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	attrs := PROCESS_ALL_ACCESS
	handle, err = windows.OpenProcess(uint32(attrs), true, uint32(pid))
	return
}

func procBasicInfo(handle windows.Handle) (pbi windows.PROCESS_BASIC_INFORMATION, err error) {
	pbiSize := unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})
	var returnedLen uint32

	err = windows.NtQueryInformationProcess(
		handle,
		windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi),
		uint32(pbiSize),
		&returnedLen)
	return
}

func fillRemotePEB(hProc windows.Handle, pbi *windows.PROCESS_BASIC_INFORMATION) error {

	// read in top level peb
	base := unsafe.Pointer(pbi.PebBaseAddress)
	pbi.PebBaseAddress = &windows.PEB{}
	size := uint32(unsafe.Sizeof(*pbi.PebBaseAddress))
	dest := unsafe.Pointer(pbi.PebBaseAddress)
	err := readMemory(hProc, base, dest, size)
	if err != nil {
		return err
	}

	// with peb.Ldr populated with the remote Ldr pointer, re-read
	base = unsafe.Pointer(pbi.PebBaseAddress.Ldr)
	pbi.PebBaseAddress.Ldr = &windows.PEB_LDR_DATA{}
	size = uint32(unsafe.Sizeof(*pbi.PebBaseAddress.Ldr))
	dest = unsafe.Pointer(pbi.PebBaseAddress.Ldr)
	err = readMemory(hProc, base, dest, size)
	if err != nil {
		return err
	}

	// base = unsafe.Pointer(&pbi.PebBaseAddress.Ldr.InMemoryOrderModuleList)
	// pbi.PebBaseAddress.Ldr.InMemoryOrderModuleList = windows.LIST_ENTRY{}
	// dest = unsafe.Pointer(&pbi.PebBaseAddress.Ldr.InMemoryOrderModuleList)
	// size = uint32(unsafe.Sizeof(pbi.PebBaseAddress.Ldr.InMemoryOrderModuleList))
	// err = readMemory(hProc, base, dest, size)
	return err
}

func readMemory(hProc windows.Handle, start unsafe.Pointer, dest unsafe.Pointer, readLen uint32) error {
	var bytesRead uint32
	procNtReadVirtualMemory := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtReadVirtualMemory")
	ret, _, _ := procNtReadVirtualMemory.Call(
		uintptr(hProc),                      // hProcess
		uintptr(start),                      // start address
		uintptr(dest),                       // destBuffer
		uintptr(readLen),                    // bytes to read
		uintptr(unsafe.Pointer(&bytesRead)), // post-read count
	)

	code := (windows.NTStatus)(uint32(ret))
	if ret != 0 {
		return fmt.Errorf("readProcessMemory: %s", code.Errno().Error())
	}
	return nil
}
