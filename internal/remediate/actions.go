/*******************************************************************************
 * @file         actions.go
 * @brief        Package remediate is Muster's allow-list for self-healing/remediation actions: the small, fixed set of verbs an operator can queue for a host and an agent script is actually willing to execute.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package remediate is Muster's allow-list for self-healing/remediation
// actions: the small, fixed set of verbs an operator can queue for a
// host and an agent script is actually willing to execute.
//
// This exists specifically to keep "self-healing" from becoming
// "unauthenticated remote code execution" -- see internal/ingest's auth
// check (a prerequisite, not decoration: internal/api's handleQueueAction
// refuses to queue anything at all unless the server was started with
// -auth-token). Even a bug that let someone queue an arbitrary verb
// couldn't do anything real: the agent scripts only implement case
// branches for the verbs listed here, never a generic "run this string"
// path -- Arg is a single allow-listed-shape value (a service name),
// never a command line.
package remediate

import (
	"fmt"
	"regexp"
)

var serviceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}$`)

// Verb describes one allow-listed remediation action.
type Verb struct {
	Name        string
	Description string
	NeedsArg    bool
	Platforms   map[string]bool // platform name -> supported
	Implemented bool            // false: allow-listed for the shape of the feature, agents report "unsupported" today
}

// Verbs is the full allow-list. Adding a capability here is a deliberate,
// reviewed code change -- never data-driven from the network.
var Verbs = map[string]Verb{
	"restart-service": {
		Name:        "restart-service",
		Description: "Restart a named service (systemd unit on Linux, Windows service on Windows). Arg is the service name.",
		NeedsArg:    true,
		Platforms:   map[string]bool{"linux": true, "windows": true},
		Implemented: true,
	},
	"apply-updates": {
		Name:        "apply-updates",
		Description: "Apply pending OS package updates. No argument.",
		NeedsArg:    false,
		Platforms:   map[string]bool{"linux": true, "windows": true},
		// Allow-listed for the shape of the feature (queuing, delivery,
		// and result reporting all already work end to end for it), but
		// deliberately not wired up to actually run anything yet --
		// unattended package upgrades on someone's real box is a bigger
		// decision than a demo remediation action should make silently.
		// Agents recognize this verb and report "unsupported" rather
		// than silently no-op-ing or guessing what "apply updates"
		// should mean on their platform.
		Implemented: false,
	},
}

// Validate checks verb/arg against the allow-list and a target platform,
// returning an error safe to hand back over the API as-is.
func Validate(platform, verb, arg string) error {
	v, ok := Verbs[verb]
	if !ok {
		return fmt.Errorf("unknown action verb %q", verb)
	}
	if !v.Platforms[platform] {
		return fmt.Errorf("action %q is not supported on platform %q", verb, platform)
	}
	if v.NeedsArg && arg == "" {
		return fmt.Errorf("action %q requires an argument", verb)
	}
	if v.NeedsArg && !serviceName.MatchString(arg) {
		return fmt.Errorf("service name must be 1–128 letters, digits, '.', '_', '@' or '-', starting with a letter or digit")
	}
	if !v.NeedsArg && arg != "" {
		return fmt.Errorf("action %q does not take an argument", verb)
	}
	return nil
}
