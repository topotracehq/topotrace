/*******************************************************************************
 * @file         main.go
 * @brief        Command fakeplugin is a minimal test-only plugin used by pluginhost_test.go to exercise the manager against a real subprocess: handshake, Describe, HandleHTTP, Shutdown.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command fakeplugin is a minimal test-only plugin used by
// pluginhost_test.go to exercise the manager against a real
// subprocess: handshake, Describe, HandleHTTP, Shutdown.
package main

import (
	"topotrace/internal/pluginhost"
)

type impl struct{}

func (impl) Describe(struct{}, *pluginhost.PluginInfo) error { return nil }

func (impl) HandleHTTP(req pluginhost.PluginHTTPRequest, reply *pluginhost.PluginHTTPResponse) error {
	reply.Status = 418
	reply.Headers = map[string][]string{"X-Echo-Path": {req.Path}}
	reply.Body = []byte("method=" + req.Method + " body=" + string(req.Body))
	return nil
}

func (impl) Shutdown(struct{}, *struct{}) error { return nil }

func main() {
	p := &describingImpl{impl{}}
	done, err := pluginhost.ServePlugin(p)
	if err != nil {
		panic(err)
	}
	<-done
}

// describingImpl fills in Describe with fixed test values -- name
// "fakeplugin" matches the binary's basename, which is how the test
// verifies List()/Mount() wiring end to end.
type describingImpl struct{ impl }

func (describingImpl) Describe(args struct{}, reply *pluginhost.PluginInfo) error {
	*reply = pluginhost.PluginInfo{
		Name:        "fakeplugin",
		Version:     "0.0.1-test",
		MountPrefix: "fakeplugin",
		Description: "test-only fake plugin",
	}
	return nil
}
