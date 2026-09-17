// Package cook: macOS support. Reuses the same flat "Key: Value" capture
// format windows.go introduced and its generic parser directly -- the
// format itself was never actually Windows-specific, that's just where
// the pattern was first written. One capture file, system.txt, produced
// entirely by agent/macos/muster-agent.sh via `sw_vers`/`sysctl`/
// `uname`/`uptime` -- no parsing on the agent side, same division of
// labor as every other platform.
package cook

import (
	"path/filepath"
	"strconv"
)

// CookDarwin reads a macOS raw capture directory and returns a flat map
// of system-summary facts, sharing field names with CookLinux/
// CookWindows wherever the concept maps cleanly -- see windows.go's own
// doc comment for why that matters (the web UI's card layout works
// unmodified across platforms this way, no per-platform display logic).
func CookDarwin(rawDir string) (map[string]any, error) {
	summary := map[string]any{}

	kv, ok, err := parseWindowsKV(filepath.Join(rawDir, "system.txt"))
	if err != nil {
		return nil, err
	}
	if !ok {
		return summary, nil
	}

	summary["os"] = "Darwin"
	kvString(kv, "CPUBrand", summary, "cpu_model")
	kvInt(kv, "NumCPUs", summary, "num_cpus")
	if v, ok := kv["MemoryBytes"]; ok {
		if b, err := strconv.ParseInt(v, 10, 64); err == nil && b > 0 {
			summary["memory_mb"] = int(b / (1024 * 1024))
		}
	}
	kvString(kv, "ProductName", summary, "distribution")
	kvString(kv, "ProductVersion", summary, "distribution_version")
	kvString(kv, "KernelVersion", summary, "kernel_version")
	kvString(kv, "Uptime", summary, "uptime")

	return summary, nil
}

// CookDarwinCategories mirrors CookLinuxCategories/CookWindowsCategories'
// shape (category name -> fact data) for the cook pipeline, even though
// macOS only has system_summary today. Extending it to the newer feed
// categories (disk usage, installed software, ...) is a natural next
// step, not done here -- there's no macOS fleet in this project to
// build or test that against yet, the same honesty standard the
// Kubernetes chart and the Windows agent held themselves to before
// real-world verification caught up.
func CookDarwinCategories(rawDir string) (map[string]map[string]any, error) {
	summary, err := CookDarwin(rawDir)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	if len(summary) > 0 {
		out["system_summary"] = summary
	}
	return out, nil
}
