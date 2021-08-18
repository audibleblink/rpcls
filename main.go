package main

import (
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

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

			isMatch := name == RPCRT4DLL

			if isMatch {
				params := peb.ProcessParameters

				cmd, err := memutils.PopulateStrings(pidHandle, &params.CommandLine)
				if err != nil {
					fmt.Printf("could not read cmd string: %s\n", err)
				}
				path, err := memutils.PopulateStrings(pidHandle, &params.ImagePathName)
				if err != nil {
					fmt.Printf("could not read path string: %s\n", err)
				}

				r := result{proc.Exe, proc.Pid, cmd, path}

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
