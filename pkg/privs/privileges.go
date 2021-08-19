package privs

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SE_PRIVILEGE_ENABLED = 0x00000002
)

func SePrivEnable(privString string) (err error) {

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privString), &luid)
	if err != nil {
		return fmt.Errorf("sePrivEnable | %s", err)
	}

	privs := &windows.Tokenprivileges{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = uint32(SE_PRIVILEGE_ENABLED)

	var tokenH windows.Token
	windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES, &tokenH)
	defer tokenH.Close()

	err = windows.AdjustTokenPrivileges(
		tokenH,
		false,
		privs,
		uint32(unsafe.Sizeof(privs)),
		nil,
		nil)
	if err != nil {
		return fmt.Errorf("sePrivEnable | %s", err)
	}
	return
}

func TokenOwner(procH windows.Handle) (string, error) {
	var tokenH windows.Token
	windows.OpenProcessToken(procH, windows.TOKEN_QUERY, &tokenH)
	defer tokenH.Close()

	tokenUser, err := tokenH.GetTokenUser()
	if err != nil {
		err = fmt.Errorf("tokenOwner | getTokenUser | %s", err)
		return "", err
	}

	u, d, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		err = fmt.Errorf("tokenOwner | lookupSID | %s", err)
		return "", err
	}

	return fmt.Sprintf(`%s\%s`, d, u), err
}
