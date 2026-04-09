// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package socktracer

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const SO_NETNS_COOKIE = 71 // SO_NETNS_COOKIE, available since kernel 5.14

func (p *Tracer) backfillPidForSockets(pid app.PID) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)

	entries, err := os.ReadDir(fdDir)

	if err != nil {
		p.log.Debug("readdir failed", "pid", pid, "error", err)
		return
	}

	pidfd, err := unix.PidfdOpen(int(pid), 0)

	if err != nil {
		p.log.Debug("pidfd_open failed", "pid", pid, "error", err)
		return
	}

	defer unix.Close(pidfd)

	val := buildListenerPidVal(pid)
	p.log.Info("scanning sockets", "pid", pid, "pidTgid", val.PidTgid, "fds", len(entries))

	for _, entry := range entries {
		fdPath := filepath.Join(fdDir, entry.Name())

		target, err := os.Readlink(fdPath)
		if err != nil || !strings.HasPrefix(target, "socket:") {
			continue
		}

		targetFd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		dupfd, err := unix.PidfdGetfd(pidfd, targetFd, 0)
		if err != nil {
			p.log.Debug("pidfd_getfd failed", "pid", pid, "fd", targetFd, "error", err)
			continue
		}

		p.log.Debug("found socket fd", "pid", pid, "fd", targetFd, "target", target)
		p.tryBackfillFd(dupfd, val)
		unix.Close(dupfd)
	}
}

func buildListenerPidVal(pid app.PID) SocktracerSockopsListenerPidVal {
	val := SocktracerSockopsListenerPidVal{PidTgid: uint64(pid)<<32 | uint64(pid)}

	val.PidInfo.HostPid = uint32(pid)

	nsPids, err := procs.FindNamespacedPids(pid)

	if err == nil && len(nsPids) > 0 {
		userPid := uint32(nsPids[len(nsPids)-1])
		val.PidInfo.UserPid = userPid
		val.PidKey.Pid = userPid
		val.PidKey.Tid = userPid
	} else {
		// namespace info, assume root namespace
		val.PidKey.Pid = uint32(pid)
		val.PidKey.Tid = uint32(pid)
	}

	if info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid)); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			val.PidInfo.Ns = uint32(st.Ino)
			val.PidKey.Ns = uint32(st.Ino)
		}
	}

	return val
}

func (p *Tracer) tryBackfillFd(fd int, val SocktracerSockopsListenerPidVal) {
	netnsCookie, err := socketOptUint64(fd, unix.SOL_SOCKET, SO_NETNS_COOKIE)
	if err != nil {
		p.log.Debug("SO_NETNS_COOKIE failed", "fd", fd, "error", err)
		return
	}

	sa, err := unix.Getsockname(fd)
	if err != nil {
		p.log.Debug("getsockname failed", "fd", fd, "error", err)
		return
	}

	var localPort uint32

	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		localPort = uint32(a.Port)
	case *unix.SockaddrInet6:
		localPort = uint32(a.Port)
	default:
		return
	}

	key := SocktracerIngressListenerPidKey{
		NetnsCookie: netnsCookie,
		LocalPort:   localPort,
	}

	p.log.Debug("writing listener pid", "netns", netnsCookie, "port", localPort, "pidTgid", val.PidTgid)

	if err := p.ingressObjs.ListenerPidMap.Update(key, val, ebpf.UpdateAny); err != nil {
		p.log.Info("map update failed", "netns", netnsCookie, "port", localPort, "error", err)
	}
}

func socketOptUint64(fd, level, opt int) (uint64, error) {
	var val uint64
	size := uint32(unsafe.Sizeof(val))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&val)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return val, nil
}
