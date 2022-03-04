package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/audibleblink/dllinquent"
	"github.com/audibleblink/getsystem"
	"github.com/audibleblink/memutils"
)

const (
	RPCRT4DLL  = `RPCRT4.dll`
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
		pid := memutils.PidForName("winlogon.exe")
		err := getsystem.InNewProcess(pid, "cmd.exe", false)
		if err != nil {
			fmt.Fprintln(os.Stderr, "You sure you're admin?")
		}
		os.Exit(0)
	}

	processes, err := memutils.Processes()
	bail(err, "failed to list procs")

	getsystem.DebugPriv()

	for _, proc := range processes {

		walker, err := dllinquent.NewPebWalker(proc.Pid)
		bail(err, "couldn't read peb for pid %d | %s", proc.Pid, err)

		var pe dllinquent.Dll
		for walker.Walk() {

			dll := walker.Dll()
			if pe == (dllinquent.Dll{}) {
				pe = dll
			}

			if strings.ToLower(dll.DllBaseName) != strings.ToLower(RPCRT4DLL) {
				continue
			}

			peFile, err := memutils.CarveOutPE(walker.Handle, walker.PEB, pe.LdrDataTableEntry.SizeOfImage)
			bail(err, "couldn't carve PE for pid %d | %s\n", proc.Pid, err)

			imports, err := peFile.ImportedSymbols()
			bail(err, "can't read imports (%d) | %s\n", proc.Pid, err)

			role := getRole(imports)
			if role == "" {
				continue
			}

			user, err := getsystem.TokenOwnerFromPid(proc.Pid)
			bail(err, "%s (%d) | %s\n", proc.Exe, proc.Pid, err)

			result := Result{
				Pid:  proc.Pid,
				Name: proc.Exe,
				User: user,
				Cmd:  walker.PEB.ProcessParameters.CommandLine.String(),
				Path: walker.PEB.ProcessParameters.ImagePathName.String(),
				Role: role,
			}

			out, err := json.Marshal(result)
			if err != nil {
				fmt.Fprintf(os.Stderr, "jsonMarshal: %s\n", err)
				continue
			}
			fmt.Println(string(out))
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

func bail(err error, msg string, i ...interface{}) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msg, i...)
		os.Exit(1)
	}
}
