package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Binject/debug/pe"
	"github.com/audibleblink/rpcls/pkg/memutils"
	"github.com/audibleblink/rpcls/pkg/privs"
	"github.com/audibleblink/rpcls/pkg/procs"
)

const (
	RPCRT4DLL = `C:\WINDOWS\System32\RPCRT4.dll`
)

type result struct {
	Name string `json:"name"`
	Pid  int    `json:"pid"`
	Cmd  string `json:"cmd"`
	Path string `json:"path"`
	Role string `json:"role"`
}

type PebLdrDataTableEntry64 struct {
	InOrderLinks               [16]byte
	InMemoryOrderLinks         [16]byte
	InInitializationOrderLinks [16]byte
	DllBase                    uint64
	EntryPoint                 uint64
	SizeOfImage                uint64
	FullDllName                windows.NTString
	BaseDllName                windows.NTString
	Flags                      uint32
	LoadCount                  uint16 // named ObseleteLoadCount OS6.2+
	TlsIndex                   uint16
	HashLinks                  [16]byte // increase by PVOID+ULONG if <OS6.2
}

func main() {
	err := privs.SePrivEnable("SeDebugPrivilege")
	if err != nil {
		fmt.Printf("sePrivEnable: %s\n", err)
		os.Exit(1)
	}

	processes, err := procs.Processes()
	if err != nil {
		fmt.Printf("processes: %s\n", err)
		os.Exit(1)
	}

	for _, proc := range processes {
		pidHandle, err := memutils.HandleForPid(proc.Pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "handleForPid: %s\n", err)
			continue
		}

		peb, err := memutils.GetPEB(pidHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "getPEB: %s\n", err)
			continue
		}

		head := windows.LDR_DATA_TABLE_ENTRY{
			InMemoryOrderLinks: peb.Ldr.InMemoryOrderModuleList,
		}

		var selfPESize uint64
		first := true
		for {
			// read the current LIST_ENTRY flink into a LDR_DATA_TABLE_ENTRY,
			// inherently casting it
			base := unsafe.Pointer(head.InMemoryOrderLinks.Flink)
			size := uint32(unsafe.Sizeof(head))
			dest := unsafe.Pointer(&head.InMemoryOrderLinks.Flink)
			err = memutils.ReadMemory(pidHandle, base, dest, size)
			if err != nil {
				fmt.Printf("could not move to next flink: %s\n", err)
				os.Exit(1)
			}

			// populate the DLL Name buffer with the remote address currently
			// stored at head.FullDllName
			name, err := memutils.PopulateStrings(pidHandle, &head.FullDllName)
			if err != nil {
				fmt.Printf("could not read dll name string: %s\n", err)
				os.Exit(1)
			}

			if name == "" {
				break
			}

			if first {
				newLdr := (*PebLdrDataTableEntry64)(unsafe.Pointer(&head))
				selfPESize = newLdr.SizeOfImage
				first = false
			}

			isMatch := name == RPCRT4DLL

			if isMatch {

				peData := make([]byte, selfPESize)
				// err := memutils.ReadMemory(pidHandle, unsafe.Pointer(peb.ImageBaseAddress), unsafe.Pointer(&peData[0]), 1024)

				procNtReadVirtualMemory := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtReadVirtualMemory")
				t, _, _ := procNtReadVirtualMemory.Call(
					uintptr(pidHandle),                  // hProcess
					peb.ImageBaseAddress,                // start address
					uintptr(unsafe.Pointer(&peData[0])), // destBuffer
					uintptr(selfPESize),                 // bytes to read
					0,                                   // post-read count
				)

				peReader := bytes.NewReader(peData)

				peFile, err := pe.NewFileFromMemory(peReader)
				if t != 0 {
					break
				}
				imports, err := peFile.ImportedSymbols()
				if err != nil {
					panic(1)
				}

				role := getRole(imports)
				params := peb.ProcessParameters

				cmd, err := memutils.PopulateStrings(pidHandle, &params.CommandLine)
				if err != nil {
					fmt.Printf("could not read cmd string: %s\n", err)
				}
				path, err := memutils.PopulateStrings(pidHandle, &params.ImagePathName)
				if err != nil {
					fmt.Printf("could not read path string: %s\n", err)
				}

				r := result{proc.Exe, proc.Pid, cmd, path, role}

				out, err := json.Marshal(r)
				if err != nil {
					fmt.Fprintf(os.Stderr, "jsonMarshal: %s\n", err)
					break
				}
				fmt.Println(string(out))
				isMatch = false
			}
		}
	}
}

func getRole(imports []string) string {
	serverRole := "RpcServerRegister"
	clientRole := "RpcBinding"

	var isClient bool
	var isServer bool

	for _, imp := range imports {
		if strings.HasPrefix(imp, serverRole) {
			isServer = true
		}
		if strings.HasPrefix(imp, clientRole) {
			isClient = true
		}
	}

	if isClient && isServer {
		return "BOTH"
	} else if isClient {
		return "CLIENT"
	} else if isServer {
		return "SERVER"
	} else {
		return "HUH?"
	}
}
