// SPDX-License-Identifier: Apache-2.0
package main

import (
	incoming "example.com/probe/gen/qqq/http/incoming-handler"
	"go.bytecodealliance.org/cm"
	"strings"
)

func init() {
	incoming.Exports.Handle = func(req incoming.Request) cm.Result[incoming.ResponseShape, incoming.Response, incoming.HTTPError] {
		status, body := uint16(200), []byte("ok")
		switch {
		case strings.HasSuffix(req.URL, "/echo") && req.Method == 2:
			body = nil
			if req.Body.Some() != nil {
				body = req.Body.Some().Slice()
			}
		case strings.HasSuffix(req.URL, "/unicode"):
			body = []byte("Hello, 世界 👋")
		case !strings.HasSuffix(req.URL, "/"):
			status, body = 404, []byte("not found")
		}
		return cm.OK[cm.Result[incoming.ResponseShape, incoming.Response, incoming.HTTPError]](incoming.Response{Status: status, Body: cm.ToList(body)})
	}
}
func main() {}
