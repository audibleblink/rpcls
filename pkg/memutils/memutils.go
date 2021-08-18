package memutils

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func HandleForPid(pid int) (handle windows.Handle, err error) {
	if pid == 0 {
		handle = windows.CurrentProcess()
		return
	}
	attrs := windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	handle, err = windows.OpenProcess(uint32(attrs), true, uint32(pid))
	return
}

func GetPEB(handle windows.Handle) (peb windows.PEB, err error) {
	pbi, err := ProcBasicInfo(handle)
	if err != nil {
		return
	}

	err = fillPEB(handle, &pbi)
	if err != nil {
		return
	}
	peb = *pbi.PebBaseAddress
	return
}

func ProcBasicInfo(handle windows.Handle) (pbi windows.PROCESS_BASIC_INFORMATION, err error) {
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

func ReadMemory(hProc windows.Handle, start unsafe.Pointer, dest unsafe.Pointer, readLen uint32) error {
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
		return fmt.Errorf("readMemory: %s", code.Errno().Error())
	}
	return nil
}

func fillPEB(handle windows.Handle, pbi *windows.PROCESS_BASIC_INFORMATION) error {
	// read in top level peb
	base := unsafe.Pointer(pbi.PebBaseAddress)
	pbi.PebBaseAddress = &windows.PEB{}
	size := uint32(unsafe.Sizeof(*pbi.PebBaseAddress))
	dest := unsafe.Pointer(pbi.PebBaseAddress)
	err := ReadMemory(handle, base, dest, size)
	if err != nil {
		return fmt.Errorf("fillPEB: process_basic_information: %s", err)
	}

	// with peb.Ldr populated with the remote Ldr pointer, re-read
	base = unsafe.Pointer(pbi.PebBaseAddress.Ldr)
	pbi.PebBaseAddress.Ldr = &windows.PEB_LDR_DATA{}
	size = uint32(unsafe.Sizeof(*pbi.PebBaseAddress.Ldr))
	dest = unsafe.Pointer(pbi.PebBaseAddress.Ldr)
	err = ReadMemory(handle, base, dest, size)
	if err != nil {
		return fmt.Errorf("fillPEB: peb.Ldr: %s", err)
	}

	// also fill peb with process_parameters
	base = unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters)
	pbi.PebBaseAddress.ProcessParameters = &windows.RTL_USER_PROCESS_PARAMETERS{}
	size = uint32(unsafe.Sizeof(*pbi.PebBaseAddress.ProcessParameters))
	dest = unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters)
	err = ReadMemory(handle, base, dest, size)
	if err != nil {
		return fmt.Errorf("failed to read process_parameters: %s", err)
	}
	return err
}

func PopulateStrings(pidHandle windows.Handle, ntString *windows.NTUnicodeString) (string, error) {
	dllNameUTF16 := make([]uint16, ntString.Length)
	base := unsafe.Pointer(ntString.Buffer)
	size := uint32(ntString.Length)
	dest := unsafe.Pointer(&dllNameUTF16[0])
	err := ReadMemory(pidHandle, base, dest, size)
	return windows.UTF16ToString(dllNameUTF16), err
}