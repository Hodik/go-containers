package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func generateMAC(uuid string) string {
	log.Println("len", len(uuid), uuid)
	if len(uuid) < 3 {
		return ""
	}

	segment1 := uuid[len(uuid)-3 : len(uuid)-2]
	segment2 := uuid[len(uuid)-2:]

	mac := fmt.Sprintf("%s:%s", segment1, segment2)
	return strings.ToLower(mac)
}

func generateIP(uuid string) string {
	if len(uuid) < 3 {
		return ""
	}

	lastThree := uuid[len(uuid)-3:]

	cleaned := strings.ReplaceAll(lastThree, "0", "")

  if cleaned == "1" {
    r := rand.Intn(98) + 1
    return strconv.Itoa(r)
  }
	return cleaned
}

func SetupNet(contUuid string) error {
	mac := generateMAC(contUuid)
	ip := generateIP(contUuid)

	log.Println(mac, ip)
	if err := ExecCommand("ip link show bridge0"); err == nil {
		fmt.Println("Bridge bridge0 already exists.")
	} else {
		if err := ExecCommand("ip link add name bridge0 type bridge"); err != nil {
			return err
		}
	}

  if err := ExecCommand(fmt.Sprintf("ip addr add 172.18.0.1/16 dev bridge0")); err != nil {
    log.Println("Error assigning ip to bridge0: ", err.Error(), ", continuing...")
	}

  if err := ExecCommand(fmt.Sprintf("ip link set bridge0 up")); err != nil {
		return err
	}

  if err := ExecCommand(fmt.Sprintf("ip link add dev veth_%s type veth peer name ceth_%s", contUuid, contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip link set dev veth_%s up", contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip link set veth_%s master bridge0", contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip netns add netns_%s", contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip link set ceth_%s netns netns_%s", contUuid, contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip netns exec netns_%s ip link set dev lo up", contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip netns exec netns_%s ip link set dev ceth_%s up", contUuid, contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip netns exec netns_%s ip addr add 172.18.0.%s/24 dev ceth_%s", contUuid, ip, contUuid)); err != nil {
		return err
	}

	if err := ExecCommand(fmt.Sprintf("ip netns exec netns_%s ip route add default via 172.18.0.1", contUuid)); err != nil {
		return err
	}
  
  if err := ExecCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -s 172.18.0.0/16 ! -o bridge0 -j MASQUERADE")); err != nil {
		return err
	}

	return nil
}

func CleanupNet(contUuid string) error {
	log.Println("net cleanup")
	if err := ExecCommand(fmt.Sprintf("ip link del dev veth_%s", contUuid)); err != nil {
		return err
	}
	if err := ExecCommand(fmt.Sprintf("ip netns del netns_%s", contUuid)); err != nil {
		return err
	}
	log.Println("Net cleanup complete")
	return nil
}

func EnterNetns(netns string) error {
	netnsPath := "/var/run/netns/" + netns

	netnsFile, err := os.Open(netnsPath)
	if err != nil {
		return err
	}
	defer netnsFile.Close()

	err = unix.Setns(int(netnsFile.Fd()), syscall.CLONE_NEWNET)
	if err != nil {
		return err
	}

	return nil
}

func ExecCommand(c string) error {
	log.Println(c)
	cmdSplit := strings.Split(c, " ")
	cmd := exec.Command(cmdSplit[0], cmdSplit[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Env = os.Environ()
	return cmd.Run()
}
