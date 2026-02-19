// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"bytes"
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

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 ObiEgress ../../../../bpf/tpinjector/egress.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 ObiIngress ../../../../bpf/tpinjector/ingress.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 ObiSockOps ../../../../bpf/tpinjector/sockops.c -- -I../../../../bpf -I../../../../bpf

func setConstant[T int32 | uint32](m map[string]any, name string, value bool) {
	if value {
		m[name] = T(1)
	} else {
		m[name] = T(0)
	}
}

type MergedObjects struct {
	ObiEgressPrograms
	ObiEgressMaps
	ObiEgressVariables
	ObiIngressPrograms
	ObiIngressMaps
	ObiIngressVariables
	ObiSockOpsPrograms
	ObiSockOpsMaps
	ObiSockOpsVariables
}

func (o *MergedObjects) Close() error {
	if err := _ObiEgressClose(&o.ObiEgressPrograms, &o.ObiEgressMaps); err != nil {
		return err
	}
	if err := _ObiIngressClose(&o.ObiIngressPrograms, &o.ObiIngressMaps); err != nil {
		return err
	}
	return _ObiSockOpsClose(&o.ObiSockOpsPrograms, &o.ObiSockOpsMaps)
}

type Tracer struct {
	cfg        *obi.Config
	bpfObjects MergedObjects
	closers    []io.Closer
	log        *slog.Logger
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

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	var spec *ebpf.CollectionSpec
	var err error

	if err = mergeSpec(&spec, _ObiEgressBytes); err != nil {
		return nil, err
	}
	if err = mergeSpec(&spec, _ObiIngressBytes); err != nil {
		return nil, err
	}
	if err = mergeSpec(&spec, _ObiSockOpsBytes); err != nil {
		return nil, err
	}

	return spec, nil
}

func mergeSpec(target **ebpf.CollectionSpec, objBytes []byte) error {
	reader := bytes.NewReader(objBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return fmt.Errorf("failed to load spec: %w", err)
	}

	if *target == nil {
		*target = spec
		return nil
	}

	for name, mapSpec := range spec.Maps {
		if existing, exists := (*target).Maps[name]; exists {
			if !mapsCompatible(existing, mapSpec) {
				return fmt.Errorf("incompatible map specs for shared map: %s", name)
			}
		} else {
			(*target).Maps[name] = mapSpec
		}
	}

	for name, progSpec := range spec.Programs {
		if _, exists := (*target).Programs[name]; exists {
			return fmt.Errorf("duplicate program name: %s", name)
		}
		(*target).Programs[name] = progSpec
	}

	for name, varSpec := range spec.Variables {
		if existing, exists := (*target).Variables[name]; exists {
			if !variablesCompatible(existing, varSpec) {
				return fmt.Errorf("incompatible variable specs for shared variable: %s", name)
			}
		} else {
			(*target).Variables[name] = varSpec
		}
	}

	return nil
}

func mapsCompatible(a, b *ebpf.MapSpec) bool {
	return a.Type == b.Type &&
		a.KeySize == b.KeySize &&
		a.ValueSize == b.ValueSize &&
		a.MaxEntries == b.MaxEntries
}

func variablesCompatible(a, b *ebpf.VariableSpec) bool {
	return a.Size() == b.Size()
}

func (p *Tracer) SetupTailCalls() {
}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 3)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpfltr.go, otherwise we get partial events in userspace.
	setConstant[int32](m, "filter_pids", !p.cfg.Discovery.BPFPidFilterOff)

	m["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())

	// Set injection flags based on context propagation configuration
	flags := uint32(0)
	if p.cfg.EBPF.ContextPropagation.HasHeaders() {
		flags |= 1 // k_inject_http_headers
	}
	if p.cfg.EBPF.ContextPropagation.HasTCP() {
		flags |= 2 // k_inject_tcp_options
	}
	m["inject_flags"] = flags
	m["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	setConstant[uint32](m, "high_request_volume", p.cfg.EBPF.HighRequestVolume)
	setConstant[uint32](m, "track_request_headers", p.cfg.EBPF.TrackRequestHeaders)

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
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
			Program:  p.bpfObjects.ObiSocketEgress,
			MapFD:    p.bpfObjects.SockDir.FD(),
			AttachAs: ebpf.AttachSkMsgVerdict,
		},
		{
			Program:  p.bpfObjects.ObiSocketIngress,
			MapFD:    p.bpfObjects.SockDir.FD(),
			AttachAs: ebpf.AttachSkSKBStreamVerdict,
		},
	}
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return []ebpfcommon.SockOps{
		{
			Program:  p.bpfObjects.ObiSockmapTracker,
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
			Program:  p.bpfObjects.ObiInetCskAccept,
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

	p.bpfObjects.Close()

	p.log.Debug("tpinjector terminated")
}

func (p *Tracer) Required() bool {
	return false
}
