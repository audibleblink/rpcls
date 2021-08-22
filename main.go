package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/audibleblink/getsystem"
	"github.com/audibleblink/rpcls/pkg/memutils"
	"github.com/audibleblink/rpcls/pkg/procs"
)

const (
	RPCRT4DLL  = `C:\WINDOWS\System32\RPCRT4.dll`
	serverRole = "RpcServerListen"
	clientRole = "RpcStringBindingCompose"
)

type Result struct {
	Pid  int    `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
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

var doSystem bool

func init() {
	flag.BoolVar(&doSystem, "system", false, "launch system prompt")
	flag.Parse()
}

func main() {

	if doSystem {
		pid := procs.PidForName("winlogon.exe")
		err := getsystem.InNewProcess(pid, "cmd.exe", false)
		if err != nil {
			fmt.Fprintln(os.Stderr, "You sure you're admin?")
		}
		os.Exit(0)
	}

	processes, err := procs.Processes()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	getsystem.DebugPriv()

	for _, proc := range processes {
		prvs := windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
		pidHandle, err := memutils.HandleForPid(proc.Pid, prvs)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		user, err := getsystem.TokenOwnerFromPid(proc.Pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s (%d) | %s\n", proc.Exe, proc.Pid, err)
			continue
		}

		peb, err := memutils.GetPEB(pidHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s (%d) | %s\n", proc.Exe, proc.Pid, err)
			continue
		}

		head := windows.LDR_DATA_TABLE_ENTRY{
			InMemoryOrderLinks: peb.Ldr.InMemoryOrderModuleList,
		}

		var selfPESize uint64
		firstRun := true
		for {
			// read the current LIST_ENTRY flink into a LDR_DATA_TABLE_ENTRY,
			// inherently casting it
			base := unsafe.Pointer(head.InMemoryOrderLinks.Flink)
			size := uint32(unsafe.Sizeof(head))
			dest := unsafe.Pointer(&head.InMemoryOrderLinks.Flink)
			err = memutils.ReadMemory(pidHandle, base, dest, size)
			if err != nil {
				fmt.Fprintf(os.Stderr, "main | next_flink | %s\n", err)
				continue
			}

			// populate the DLL Name buffer with the remote address currently
			// stored at head.FullDllName
			name, err := memutils.PopulateStrings(pidHandle, &head.FullDllName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "main | pop_dll_name | %s\n", err)
				continue
			}

			// we're at the last dll in the linked-list
			if name == "" {
				break
			}

			// the first entry in the pe list is the hosting process
			// we take SizeOfImage so we know how much to read in later
			if firstRun {
				// have to cast to this custom struct becuase the built-in
				// sys/windows one doesn't export SizeOfImage
				newLdr := (*PebLdrDataTableEntry64)(unsafe.Pointer(&head))
				selfPESize = newLdr.SizeOfImage
				firstRun = false
			}

			isMatch := name == RPCRT4DLL

			if isMatch {
				// fetch the strings located at the address indicated
				// in the peb's ProcessParameters
				params := peb.ProcessParameters
				cmd, err := memutils.PopulateStrings(pidHandle, &params.CommandLine)
				if err != nil {
					fmt.Fprintf(os.Stderr, "can't read cmd | %s (%d) | %s\n", name, proc.Pid, err)
				}
				path, err := memutils.PopulateStrings(pidHandle, &params.ImagePathName)
				if err != nil {
					fmt.Fprintf(os.Stderr, "can't read proc path | %s (%d) | %s\n", name, proc.Pid, err)
				}

				// extract the process' PE from memory
				peFile, err := memutils.CarveOutPE(pidHandle, peb, selfPESize)
				if err != nil {
					fmt.Fprintf(os.Stderr, "carveOutPE | %s (%d) | %s\n", path, proc.Pid, err)
					break
				}

				imports, err := peFile.ImportedSymbols()
				if err != nil {
					fmt.Fprintf(os.Stderr, "can't read imports | %s (%d) | %s\n", path, proc.Pid, err)
					break
				}

				// is it a server, client, both, or neither
				role := getRole(imports)
				if role == "" {
					break
				}

				result := Result{proc.Pid, proc.Exe, user, cmd, path, role}
				out, err := json.Marshal(result)
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

// searches imported functions and checks if any indicate
// the role of hosting image as being and client or server
func getRole(imports []string) string {
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
		return ""
	}
}
