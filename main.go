package main

import (
	"log"
	"os"
	"syscall"
)

func main() {
	log.Println(os.Args)
	switch os.Args[1] {
	case "run":
		run()
	case "child":
		child()
	default:
		panic("bad command")
	}
}

func child() {
	log.Printf("Running: %v as %d\n", os.Args[2:], os.Getpid())
	syscall.Sethostname([]byte("ubuntu"))
	syscall.Chroot("/home/denis/ubuntu-fs")
	syscall.Chdir("/")
	syscall.Mount("proc", "proc", "proc", 0, "")
	config := syscall.ProcAttr{
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
	}

	childPid, _, err := syscall.StartProcess(os.Args[2], os.Args[3:], &config)
	if err != nil {
		log.Fatalln("Error executing program", os.Args, err.Error())
	}
	syscall.Wait4(int(childPid), nil, 0, nil)
	syscall.Unmount("proc", 0)
}

func run() {
	log.Printf("Running: %v as %d\n", os.Args[2:], os.Getpid())
	config := syscall.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Cloneflags:   syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
			Unshareflags: syscall.CLONE_NEWNS,
		},
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
	}
	childPid, _, err := syscall.StartProcess("/proc/self/exe", append([]string{os.Args[0], "child"}, os.Args[2:]...), &config)
	if err != nil {
		log.Fatalln("Failed to start a child process")
	}
	syscall.Wait4(int(childPid), nil, 0, nil)
}
