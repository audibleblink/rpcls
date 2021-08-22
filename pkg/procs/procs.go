package procs

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const TH32CS_SNAPPROCESS uint32 = 0x00000002

type WindowsProcess struct {
	Pid  int
	Ppid int
	Exe  string
}

func Processes() ([]WindowsProcess, error) {
	handle, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("processes | create_snapshot | %s", err)
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = windows.Process32First(handle, &entry)
	if err != nil {
		return nil, fmt.Errorf("processes | process_first | %s", err)
	}

	results := make([]WindowsProcess, 0, 50)
	for {
		results = append(results, NewWindowsProcess(&entry))

		err = windows.Process32Next(handle, &entry)
		if err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			err = fmt.Errorf("processes | %s", err)
			return results, fmt.Errorf("processes | process_next | %s", err)
		}
	}
}

func NewWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		Pid:  int(e.ProcessID),
		Ppid: int(e.ParentProcessID),
		Exe:  syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func PidForName(processName string) int {
	processes, _ := Processes()
	for _, process := range processes {
		if processName == process.Exe {
			return process.Pid
		}
	}
	return 0
}
