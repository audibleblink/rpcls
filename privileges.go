package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func sePrivEnable(privString string) (err error) {

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privString), &luid)
	if err != nil {
		return
	}

	privs := &windows.Tokenprivileges{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = uint32(SE_PRIVILEGE_ENABLED)

	var tokenH windows.Token
	windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES, &tokenH)
	defer tokenH.Close()

	prevLen := uint32(0)
	return windows.AdjustTokenPrivileges(
		tokenH,
		false,
		privs,
		uint32(unsafe.Sizeof(privs)),
		nil,
		&prevLen)
}
