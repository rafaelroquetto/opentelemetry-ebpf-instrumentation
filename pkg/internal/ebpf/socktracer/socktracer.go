// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package socktracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/socktracer"

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 SocktracerEgress ../../../../bpf/socktracer/egress.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 SocktracerIngress ../../../../bpf/socktracer/ingress.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 SocktracerSockops ../../../../bpf/socktracer/sockops.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 SocktracerSockIter ../../../../bpf/socktracer/sock_iter.c -- -I../../../../bpf

type Tracer struct {
	cfg          *obi.Config
	egressObjs   SocktracerEgressObjects
	ingressObjs  SocktracerIngressObjects
	sockopsObjs  SocktracerSockopsObjects
	sockIterObjs SocktracerSockIterObjects
	closers      []io.Closer
	log          *slog.Logger
	iters        []*ebpfcommon.Iter
	pidsMu       sync.Mutex
	pids         map[app.PID]struct{}
}

func setConstant[T int32 | uint32](m map[string]any, name string, value bool) {
	if value {
		m[name] = T(1)
	} else {
		m[name] = T(0)
	}
}

func New(cfg *obi.Config) *Tracer {
	log := slog.With("component", "socktracer")

	return &Tracer{
		log:  log,
		cfg:  cfg,
		pids: make(map[app.PID]struct{}),
	}
}

func (p *Tracer) AllowPID(pid app.PID, _ uint32, _ *svc.Attrs) {
	p.pidsMu.Lock()
	defer p.pidsMu.Unlock()
	p.pids[pid] = struct{}{}
}

func (p *Tracer) BlockPID(pid app.PID, _ uint32) {
	p.pidsMu.Lock()
	defer p.pidsMu.Unlock()
	delete(p.pids, pid)
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	egressSpec, err := LoadSocktracerEgress()
	if err != nil {
		return nil, fmt.Errorf("loading egress spec: %w", err)
	}

	ingressSpec, err := LoadSocktracerIngress()
	if err != nil {
		return nil, fmt.Errorf("loading ingress spec: %w", err)
	}

	sockopsSpec, err := LoadSocktracerSockops()
	if err != nil {
		return nil, fmt.Errorf("loading sockops spec: %w", err)
	}

	sockIterSpecs, err := LoadSocktracerSockIter()
	if err != nil {
		return nil, fmt.Errorf("loading sockiter spec: %w", err)
	}

	return []*ebpfcommon.SpecBundle{
		{
			Spec:      egressSpec,
			Objects:   &p.egressObjs,
			Constants: p.egressConstants(),
		},
		{
			Spec:      ingressSpec,
			Objects:   &p.ingressObjs,
			Constants: p.ingressConstants(),
		},
		{
			Spec:      sockopsSpec,
			Objects:   &p.sockopsObjs,
			Constants: p.sockopsConstants(),
		},
		{
			Spec:      sockIterSpecs,
			Objects:   &p.sockIterObjs,
			Constants: p.iterConstants(),
		},
	}, nil
}

func (p *Tracer) injectFlags() uint32 {
	flags := uint32(0)

	if p.cfg.EBPF.ContextPropagation.HasHeaders() {
		flags |= 1 // k_inject_http_headers
	}

	if p.cfg.EBPF.ContextPropagation.HasTCP() {
		flags |= 2 // k_inject_tcp_options
	}

	return flags
}

func (p *Tracer) egressConstants() map[string]any {
	c := make(map[string]any)
	c["inject_flags"] = p.injectFlags()
	c["http_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.HTTP
	c["tcp_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.TCP
	c["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())
	c["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	setConstant[uint32](c, "track_request_headers", p.cfg.EBPF.TrackRequestHeaders)
	setConstant[uint32](c, "high_request_volume", p.cfg.EBPF.HighRequestVolume)
	setConstant[int32](c, "filter_pids", !p.cfg.Discovery.BPFPidFilterOff)
	c["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	return c
}

func (p *Tracer) ingressConstants() map[string]any {
	c := make(map[string]any)
	c["http_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.HTTP
	c["tcp_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.TCP
	c["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	setConstant[uint32](c, "high_request_volume", p.cfg.EBPF.HighRequestVolume)
	setConstant[int32](c, "filter_pids", !p.cfg.Discovery.BPFPidFilterOff)
	c["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	return c
}

func (p *Tracer) sockopsConstants() map[string]any {
	c := make(map[string]any)
	c["inject_flags"] = p.injectFlags()
	c["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	setConstant[int32](c, "filter_pids", !p.cfg.Discovery.BPFPidFilterOff)

	return c
}

func (p *Tracer) iterConstants() map[string]any {
	return map[string]any{
		"g_bpf_debug": p.cfg.EBPF.BpfDebug,
	}
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	if p.supportsTrampolines() {
		return nil
	}

	return map[string]ebpfcommon.ProbeDesc{
		"inet_csk_accept": {End: p.ingressObjs.ObiKretInetCskAccept},
	}
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return []ebpfcommon.SockMsg{
		{
			Program:  p.egressObjs.ObiSocketEgress,
			MapFD:    p.sockopsObjs.SockDir.FD(),
			AttachAs: ebpf.AttachSkMsgVerdict,
		},
		{
			Program:  p.ingressObjs.ObiSocketIngress,
			MapFD:    p.sockopsObjs.SockDir.FD(),
			AttachAs: ebpf.AttachSkSKBStreamVerdict,
		},
	}
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	//return nil
	return []ebpfcommon.SockOps{
		{
			Program:  p.sockopsObjs.ObiSockmapTracker,
			AttachAs: ebpf.AttachCGroupSockOps,
		},
	}
}

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	if p.iters != nil {
		return p.iters
	}

	major, minor := ebpfcommon.KernelVersion()

	if major < 6 || (major == 6 && minor < 4) {
		p.log.Warn("TCP socket iterator disabled: kernel versions < 6.4 have a locking bug " +
			"in iter/tcp + sockhash that can cause an RCU stall and kernel panic. " +
			"Existing connections at startup will not be tracked for context propagation.")
		p.iters = []*ebpfcommon.Iter{}
		return p.iters
	}

	p.iters = []*ebpfcommon.Iter{{Program: p.sockIterObjs.ObiSkIterTcp}}

	return p.iters
}

func (p *Tracer) supportsTrampolines() bool {
	// BPF trampolines (fexit) are not supported on arm64 kernels < 6.0.
	major, minor := ebpfcommon.KernelVersion()
	return !(runtime.GOARCH == "arm64" && (major < 6 || (major == 6 && minor == 0)))
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing {
	if !p.supportsTrampolines() {
		return nil
	}

	return []*ebpfcommon.Tracing{
		{
			Program:  p.ingressObjs.ObiInetCskAccept,
			AttachAs: ebpf.AttachTraceFExit,
		},
	}
}

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) runItersForPids() {
	iters := p.Iters()
	if len(iters) == 0 {
		return
	}

	p.pidsMu.Lock()
	pids := make([]app.PID, 0, len(p.pids))
	for pid := range p.pids {
		pids = append(pids, pid)
	}
	p.pidsMu.Unlock()

	seen := make(map[uint64]struct{})

	for _, pid := range pids {
		info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err != nil {
			p.log.Debug("netns stat failed", "pid", pid, "error", err)
			continue
		}

		inode := info.Sys().(*syscall.Stat_t).Ino
		if _, ok := seen[inode]; ok {
			continue
		}
		seen[inode] = struct{}{}

		for _, it := range iters {
			if err := netns.WithNetNS(int(pid), func() error {
				return it.Run(p.log)
			}); err != nil {
				p.log.Error("error running iterator in netns", "pid", pid, "error", err)
			}
		}
	}
}

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("socktracer started")

	p.runItersForPids()

	<-ctx.Done()

	p.egressObjs.Close()
	p.ingressObjs.Close()
	p.sockopsObjs.Close()
	p.sockIterObjs.Close()

	p.log.Debug("socktracer terminated")
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return ebpfcommon.CapSocketTracing }

func (p *Tracer) Required() bool {
	return false
}
