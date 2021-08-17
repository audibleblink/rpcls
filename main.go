package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SE_PRIVILEGE_ENABLED = 0x00000002
	PID                  = 15080
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

	err = fillRemotePEB(pidHandle, &pbi)
	if err != nil {
		fmt.Printf("readRemotePEB: %s\n", err)
		os.Exit(1)
	}

	head := windows.LDR_DATA_TABLE_ENTRY{
		InMemoryOrderLinks: pbi.PebBaseAddress.Ldr.InMemoryOrderModuleList,
	}

	for {
		// read the current LIST_ENTRY  flink into a LDR_DATA_TABLE_ENTRY,
		// inherently casting it
		base := unsafe.Pointer(head.InMemoryOrderLinks.Flink)
		size := uint32(unsafe.Sizeof(head))
		dest := unsafe.Pointer(&head.InMemoryOrderLinks.Flink)
		err = readMemory(pidHandle, base, dest, size)
		if err != nil {
			fmt.Printf("could not move to next flink: %s\n", err)
			os.Exit(1)
		}

		// populate the DLL Name buffer with the remote address currently
		// stored at head.FullDllName
		dllNameUTF16 := make([]uint16, head.FullDllName.Length)
		base = unsafe.Pointer(head.FullDllName.Buffer)
		size = uint32(head.FullDllName.Length)
		dest = unsafe.Pointer(&dllNameUTF16[0])
		err = readMemory(pidHandle, base, dest, size)
		if err != nil {
			fmt.Printf("could not read dll name string: %s\n", err)
			os.Exit(1)
		}

		name := windows.UTF16ToString(dllNameUTF16)
		if name == "" {
			os.Exit(0)
		}
		fmt.Println(name)
	}
}

func handleForPid(pid int) (handle windows.Handle, err error) {
	if pid == 0 {
		handle = windows.CurrentProcess()
		return
	}
	attrs := windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
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
