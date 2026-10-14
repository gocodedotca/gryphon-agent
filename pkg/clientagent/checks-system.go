package clientagent

import (
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
)

// The four system checks are sensors: each reports a number and says nothing
// about whether it is good or bad. The thresholds live on the server, per host
// service, so that one node that legitimately runs hot can be tuned without
// moving every other node's bands with it — and so that tuning it does not mean
// redeploying an agent.
//
// Each reports in the units its threshold is expressed in: a percentage for
// disk, memory and CPU, and load per core for load. Normalising here rather
// than on the server is deliberate, because the core count is a fact about this
// machine.

func checkDisk(path string) result {
	if path == "" {
		path = "/"
	}
	u, err := disk.Usage(path)
	if err != nil {
		return unknownResult(err)
	}

	// A filesystem fills two ways and the block count only sees one of them.
	// Image-layer churn on a container host exhausts inodes long before it
	// exhausts bytes, and a check reading only blocks reports healthy while
	// nothing can be written — which is exactly the failure mode a node agent
	// exists to catch. The reading is whichever is worse, so one threshold
	// covers both, and the message names which one it was.
	value := u.UsedPercent
	inodes := u.InodesTotal > 0 && u.InodesUsedPercent > u.UsedPercent
	if inodes {
		value = u.InodesUsedPercent
	}

	msg := phrase.T("{path}: {pct} used, {free} free of {total}",
		"path", path, "pct", percent(u.UsedPercent), "free", humanBytes(u.Free), "total", humanBytes(u.Total))
	if inodes {
		msg = phrase.T("{path}: inodes {pct} used (blocks {blocks}, {free} free of {total})",
			"path", path, "pct", percent(u.InodesUsedPercent), "blocks", percent(u.UsedPercent),
			"free", humanBytes(u.Free), "total", humanBytes(u.Total))
	}

	return measured(value, msg, fmt.Sprintf("%d|%d", u.Free/(1<<20), u.Total/(1<<20)))
}

func checkMemory() result {
	m, err := mem.VirtualMemory()
	if err != nil {
		return unknownResult(err)
	}
	return measured(
		m.UsedPercent,
		phrase.T("memory: {pct} used, {available} available of {total}",
			"pct", percent(m.UsedPercent), "available", humanBytes(m.Available), "total", humanBytes(m.Total)),
		fmt.Sprintf("%d|%d|%d", m.Total/1024, m.Used/1024, m.Free/1024))
}

// cpuSample is the last CPU reading and when it was taken. A reading is a
// one-second sample, so several CPU checks arriving together -- a host with
// a check per container, or a server rechecking -- would each block a
// second and each measure the same second. One sample answers all of them
// for cpuSampleFor.
var cpuSample struct {
	mu    sync.Mutex
	at    time.Time
	value float64
}

const cpuSampleFor = 5 * time.Second

// sampleCPU is the CPU sample to report now. The sampler is a variable so a
// test can replace it.
var sampleCPU = func() (float64, error) {
	// A one-second sample; percent-since-boot (interval 0 on a fresh process)
	// says nothing about how the machine is doing right now.
	pct, err := cpu.Percent(time.Second, false)
	if err != nil {
		return 0, err
	}
	if len(pct) == 0 {
		return 0, phrase.Errorf("no cpu sample")
	}
	return pct[0], nil
}

func checkCPU() result {
	cpuSample.mu.Lock()
	defer cpuSample.mu.Unlock()
	if time.Since(cpuSample.at) > cpuSampleFor {
		value, err := sampleCPU()
		if err != nil {
			return unknownResult(err)
		}
		cpuSample.at, cpuSample.value = time.Now(), value
	}
	n, err := cpu.Counts(true)
	if err != nil || n == 0 {
		n = 1
	}
	msg := phrase.T("CPU: {pct} average across {n} cpus", "pct", percent(cpuSample.value), "n", n)
	if n == 1 {
		msg = phrase.T("CPU: {pct} average across 1 cpu", "pct", percent(cpuSample.value))
	}
	return measured(cpuSample.value, msg, "")
}

func checkLoad() result {
	avg, err := load.Avg()
	if err != nil {
		return unknownResult(err)
	}
	n, err := cpu.Counts(true)
	if err != nil || n == 0 {
		n = 1
	}
	perCPU := avg.Load1 / float64(n)
	two := func(f float64) string { return fmt.Sprintf("%.2f", f) }
	msg := phrase.T("load: {one}, {five}, {fifteen} across {n} cpus ({per} per cpu)",
		"one", two(avg.Load1), "five", two(avg.Load5), "fifteen", two(avg.Load15), "n", n, "per", two(perCPU))
	if n == 1 {
		msg = phrase.T("load: {one}, {five}, {fifteen} across 1 cpu ({per} per cpu)",
			"one", two(avg.Load1), "five", two(avg.Load5), "fifteen", two(avg.Load15), "per", two(perCPU))
	}
	return measured(perCPU, msg, "")
}

// percent is a percentage as a message carries it: one decimal, and the sign
// with it, so that a reader's language can space it its own way.
func percent(f float64) string { return fmt.Sprintf("%.1f%%", f) }

// humanBytes renders a byte count at a sensible scale.
func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
