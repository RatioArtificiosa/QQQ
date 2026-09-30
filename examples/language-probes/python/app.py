# SPDX-License-Identifier: Apache-2.0
from wit_world import exports
from wit_world.imports.http import Method, Response


class IncomingHandler(exports.IncomingHandler):
    def handle(self, req):
        if req.url.endswith('/echo') and req.method == Method.POST:
            return Response(200, [], req.body or b'')
        if req.url.endswith('/unicode'):
            return Response(200, [], 'Hello, 世界 👋'.encode())
        if not req.url.endswith('/'):
            return Response(404, [], b'not found')
        return Response(200, [], b'ok')
