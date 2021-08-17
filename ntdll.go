package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const ERROR_SUCCESS syscall.Errno = 0
const ptrSize = unsafe.Sizeof(uintptr(0))

var (
	ntdll                      *windows.DLL
	ntWow64ReadVirtualMemory64 *windows.Proc
)

func init() {
	var err error
	ntdll, err = windows.LoadDLL("ntdll.dll")
	if err == nil {
		ntWow64ReadVirtualMemory64, _ = ntdll.FindProc("NtReadVirtualMemory")
	}
}

func NtWow64ReadVirtualMemory64(processHandle windows.Handle, baseAddress uint64,
	bufferData windows.Pointer, bufferSize uint64, returnSize *uint64) error {

	if ntWow64ReadVirtualMemory64 == nil {
		return fmt.Errorf("ntWow64ReadVirtualMemory64==nil")
	}

	var r1 uintptr
	var err error

	// this shouldnt ever happen
	if ptrSize == 8 {
		r1, _, err = ntWow64ReadVirtualMemory64.Call(uintptr(processHandle), uintptr(baseAddress),
			uintptr(unsafe.Pointer(bufferData)), uintptr(bufferSize), uintptr(unsafe.Pointer(returnSize)))
	} else {
		r1, _, err = ntWow64ReadVirtualMemory64.Call(uintptr(processHandle),
			uintptr(baseAddress&0xFFFFFFFF),
			uintptr(baseAddress>>32),
			uintptr(unsafe.Pointer(bufferData)),
			uintptr(bufferSize),
			uintptr(0),
			uintptr(unsafe.Pointer(returnSize)))
	}

	if int(r1) < 0 {
		if err != ERROR_SUCCESS {
			return err
		} else {
			return syscall.EINVAL
		}
	}

	return nil
}
