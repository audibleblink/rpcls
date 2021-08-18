package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/audibleblink/rpcls/pkg/memutils"
	"github.com/audibleblink/rpcls/pkg/privs"
	"github.com/audibleblink/rpcls/pkg/procs"
)

func main() {
	err := privs.SePrivEnable("SeDebugPrivilege")
	if err != nil {
		fmt.Printf("seDebug: %s\n", err)
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
			fmt.Printf("pidHandle: %s\n", err)
			os.Exit(1)
		}

		peb, err := memutils.GetPEB(pidHandle)
		if err != nil {
			fmt.Printf("getPEB: %s\n", err)
			os.Exit(1)
		}

		head := windows.LDR_DATA_TABLE_ENTRY{
			InMemoryOrderLinks: peb.Ldr.InMemoryOrderModuleList,
		}

		isFirst := true
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
			dllNameUTF16 := make([]uint16, head.FullDllName.Length)
			base = unsafe.Pointer(head.FullDllName.Buffer)
			size = uint32(head.FullDllName.Length)
			dest = unsafe.Pointer(&dllNameUTF16[0])
			err = memutils.ReadMemory(pidHandle, base, dest, size)
			if err != nil {
				fmt.Printf("could not read dll name string: %s\n", err)
				os.Exit(1)
			}

			name := windows.UTF16ToString(dllNameUTF16)
			if name == "" {
				break
			}

			if isFirst {
				isFirst = false
				fmt.Printf("\n%s\n", name)
			} else {
				fmt.Println(name)
			}
		}
	}
}
