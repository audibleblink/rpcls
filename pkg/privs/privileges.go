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

// func HasPrivilege(hProc windows.Handle, privText string) bool {
// 	procCheckPrivilege := windows.NewLazySystemDLL("advapi32.dll").NewProc("CheckPrivilege")
// 	ret, _, _ := procCheckPrivilege.Call(
// 		uintptr(hProc),
// 		someluids,
// 		filter one or all?,
// 		*bool
// 	)
// // ADVAPI32.dll
// }

// ClientToken A handle to an access token representing a client process. This
// handle must have been obtained by opening the token of a thread impersonating
// the client. The token must be open for TOKEN_QUERY access.

// RequiredPrivileges A pointer to a PRIVILEGE_SET structure. The Privilege member
// of this structure is an array of LUID_AND_ATTRIBUTES structures. Before calling
// PrivilegeCheck, use the Privilege array to indicate the set of privileges to
// check. Set the Control member to PRIVILEGE_SET_ALL_NECESSARY if all of the
// privileges must be enabled; or set it to zero if it is sufficient that any one
// of the privileges be enabled.  When PrivilegeCheck returns, the Attributes
// member of each LUID_AND_ATTRIBUTES structure is set to
// SE_PRIVILEGE_USED_FOR_ACCESS if the corresponding privilege is enabled.

// pfResult A pointer to a value the function sets to indicate whether any or all
// of the specified privileges are enabled in the access token. If the Control
// member of the PRIVILEGE_SET structure specifies PRIVILEGE_SET_ALL_NECESSARY,
// this value is TRUE only if all the privileges are enabled; otherwise, this value
// is TRUE if any of the privileges are enabled.
