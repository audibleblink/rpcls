package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getDLLs(h windows.Handle, pbi windows.PROCESS_BASIC_INFORMATION) (dlls []string, err error) {

	pInfo := uint64(uintptr(unsafe.Pointer(pbi.PebBaseAddress)))
	peb := PEB64{}

	err = NtWow64ReadVirtualMemory64(h, pInfo, windows.Pointer(unsafe.Pointer(&peb)), uint64(unsafe.Sizeof(peb)), nil)
	if err != nil {
		return dlls, fmt.Errorf("Could not get x64 module handle: NtWow64ReadVirtualMemory64(peb), %v", err)
	}

	// Read and build ldr
	ldr := PEB_LDR_DATA64{}
	err = NtWow64ReadVirtualMemory64(h, (peb.LdrData), windows.Pointer(unsafe.Pointer(&ldr)), uint64(unsafe.Sizeof(ldr)), nil)
	if err != nil {
		return dlls, fmt.Errorf("Could not get x64 module handle: NtWow64ReadVirtualMemory64(head), %v", err)
	}

	// Read and build ldr data
	head := LDR_DATA_TABLE_ENTRY64{}
	head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink

	lastEntry := peb.LdrData + 0x10
	for head.InLoadOrderLinks.Flink != lastEntry {

		err = NtWow64ReadVirtualMemory64(h, head.InLoadOrderLinks.Flink, windows.Pointer(unsafe.Pointer(&head)), uint64(unsafe.Sizeof(head)), nil)
		if err != nil {
			return dlls, fmt.Errorf("Could not get x64 module handle: NtWow64ReadVirtualMemory64(head loop), %v", err)
		}

		out := make([]byte, head.FullDllName.Length)
		for i := 0; i < len(out); i++ {
			addr := head.FullDllName.Buffer + uint64(i)
			out[i] = (byte)(uintptr(unsafe.Pointer(uintptr(addr))))
		}
		dlls = append(dlls, string(out))
	}

	return dlls, nil
}
