// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 TpinjectorEgress ../../../../bpf/tpinjector/egress.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 TpinjectorIngress ../../../../bpf/tpinjector/ingress.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 TpinjectorSockops ../../../../bpf/tpinjector/sockops.c -- -I../../../../bpf

func setConstant[T int32 | uint32](m map[string]any, name string, value bool) {
	if value {
		m[name] = T(1)
	} else {
		m[name] = T(0)
	}
}

type Tracer struct {
	cfg         *obi.Config
	egressObjs  TpinjectorEgressObjects
	ingressObjs TpinjectorIngressObjects
	sockopsObjs TpinjectorSockopsObjects
	closers     []io.Closer
	log         *slog.Logger
}

func New(cfg *obi.Config) *Tracer {
	log := slog.With("component", "tpinjector")

	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func (p *Tracer) AllowPID(app.PID, uint32, *svc.Attrs) {}

func (p *Tracer) BlockPID(app.PID, uint32) {}

func (p *Tracer) LoadSpecs() ([]*ebpf.CollectionSpec, error) {
	egressSpec, err := LoadTpinjectorEgress()
	if err != nil {
		return nil, fmt.Errorf("loading egress spec: %w", err)
	}

	ingressSpec, err := LoadTpinjectorIngress()
	if err != nil {
		return nil, fmt.Errorf("loading ingress spec: %w", err)
	}

	sockopsSpec, err := LoadTpinjectorSockops()
	if err != nil {
		return nil, fmt.Errorf("loading sockops spec: %w", err)
	}

	return []*ebpf.CollectionSpec{egressSpec, ingressSpec, sockopsSpec}, nil
}

func (p *Tracer) SetupTailCalls() {
}

func (p *Tracer) Constants() []map[string]any {
	// Injection flags helper
	injectFlags := func() uint32 {
		flags := uint32(0)
		if p.cfg.EBPF.ContextPropagation.HasHeaders() {
			flags |= 1 // k_inject_http_headers
		}
		if p.cfg.EBPF.ContextPropagation.HasTCP() {
			flags |= 2 // k_inject_tcp_options
		}
		return flags
	}

	// Egress constants (spec 0)
	// Has: inject_flags, track_request_headers, high_request_volume,
	//      http_buffer_size, max_transaction_time, g_bpf_debug
	egressConsts := make(map[string]any)
	egressConsts["inject_flags"] = injectFlags()
	setConstant[uint32](egressConsts, "track_request_headers", p.cfg.EBPF.TrackRequestHeaders)
	setConstant[uint32](egressConsts, "high_request_volume", p.cfg.EBPF.HighRequestVolume)
	egressConsts["http_buffer_size"] = p.cfg.EBPF.BufferSizes.HTTP
	egressConsts["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())
	egressConsts["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	// Ingress constants (spec 1)
	// Has: high_request_volume, http_buffer_size, max_transaction_time, g_bpf_debug
	ingressConsts := make(map[string]any)
	setConstant[uint32](ingressConsts, "high_request_volume", p.cfg.EBPF.HighRequestVolume)
	ingressConsts["http_buffer_size"] = p.cfg.EBPF.BufferSizes.HTTP
	ingressConsts["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())
	ingressConsts["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	// Sockops constants (spec 2)
	// Has: inject_flags, filter_pids, g_bpf_debug
	sockopsConsts := make(map[string]any)
	sockopsConsts["inject_flags"] = injectFlags()
	setConstant[int32](sockopsConsts, "filter_pids", !p.cfg.Discovery.BPFPidFilterOff)
	sockopsConsts["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	return []map[string]any{egressConsts, ingressConsts, sockopsConsts}
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) BpfObjects() []any {
	return []any{&p.egressObjs, &p.ingressObjs, &p.sockopsObjs}
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
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
	return nil
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing {
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

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("tpinjector started")

	<-ctx.Done()

	p.egressObjs.Close()
	p.ingressObjs.Close()
	p.sockopsObjs.Close()

	p.log.Debug("tpinjector terminated")
}

func (p *Tracer) Required() bool {
	return false
}
