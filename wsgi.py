# 
# FastCGI library
# 
# Copyright (c) Project Nayuki. (MIT License)
# https://www.nayuki.io/
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.
# 

from __future__ import annotations
import io, os, pathlib, socket
from typing import Callable, Iterable
import fastcgi


_WriteType = Callable[[bytes],None]
_StartResponseType = Callable[[str,list[tuple[str,str]]],_WriteType]
_ApplicationType = Callable[[dict[str,object],_StartResponseType],Iterable[bytes]]


class WsgiServer:
	
	_application: _ApplicationType
	_server_socket: socket.socket
	
	
	def __init__(self, app: _ApplicationType, bindaddr: str, umask: int):
		self._application = app
		
		pathlib.Path(bindaddr).unlink(True)
		self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		oldmask: int = os.umask(umask)
		try:
			self._server_socket.bind(bindaddr)
		finally:
			os.umask(oldmask)
		self._server_socket.listen()
	
	
	def run(self) -> None:
		try:
			while True:
				sock, _ = self._server_socket.accept()
				self._handle_client_socket(sock)
		finally:
			self._server_socket.close()
	
	
	def _handle_client_socket(self, sock: socket.socket) -> None:
		try:
			req: _Request|None = None
			while True:
				rc: fastcgi.Record|None = fastcgi.Record.read_from_socket(sock)
				if rc is None:
					if req is not None:
						raise EOFError()
					break
				elif rc.get_request_id() == 0:
					raise ValueError("Unknown management record type")
				elif isinstance(rc, fastcgi.BeginRequestRecord):
					if req is not None:
						raise ValueError("Concurrent request")
					req = _Request(self._application, sock, rc)
				elif (req is None) or (rc.get_request_id() != req.get_id()):
					raise ValueError("Missing request")
				else:
					if not req.handle_record(rc):
						break
		finally:
			sock.close()



class _Request:
	
	# Immutable
	_application: _ApplicationType
	_socket: socket.socket
	_id: int
	_keep_conn: bool
	
	# Mutable
	_params: io.BytesIO
	_stdin: io.BytesIO
	_stdout: io.BytesIO
	_stdout_length: int
	
	
	def __init__(self, app: _ApplicationType, sock: socket.socket, rc: fastcgi.BeginRequestRecord):
		self._application = app
		self._socket = sock
		self._id = rc.get_request_id()
		self._keep_conn = rc.get_keep_conn()
		self._params = io.BytesIO()
		self._stdin = io.BytesIO()
		self._stdout = io.BytesIO()
		self._stdout_length = 0
	
	
	def get_id(self) -> int:
		return self._id
	
	
	def handle_record(self, rc: fastcgi.Record) -> bool:
		if isinstance(rc, fastcgi.ParamsRecord):
			self._params.write(rc.get_content())
			return True
		elif isinstance(rc, fastcgi.StdinRecord):
			b: bytes = rc.get_content()
			self._stdin.write(b)
			if len(b) == 0:
				self._process()
				return self._keep_conn
			return True
		else:
			raise ValueError("Unknown request record type")
	
	
	def _process(self) -> None:
		environ: dict[str,object] = {
			"wsgi.version": (1, 0),
			"wsgi.url_scheme": "http",
			"wsgi.input": io.BytesIO(self._stdin.getvalue()),
			"wsgi.errors": io.StringIO(),
			"wsgi.multithread": True,
			"wsgi.multiprocess": False,
			"wsgi.run_once": False,
		}
		environ.update(fastcgi.name_values_to_dict(self._params.getvalue()))
		
		def start_response(status: str, respheaders: list[tuple[str,str]], excinfo: object = None) -> _WriteType:
			headers: list[str] = ["HTTP/1.0 " + status] + [": ".join(kv) for kv in respheaders] + ["", ""]
			self._write_stdout("\r\n".join(headers).encode("UTF-8"))
			def write(b: bytes) -> None:
				raise NotImplementedError()
			return write
		
		result: Iterable[bytes] = self._application(environ, start_response)
		try:
			for b in result:
				self._write_stdout(b)
			if self._stdout_length > 0:
				self._send(fastcgi.StdoutRecord(self._id, self._stdout.getvalue()))
			self._send(fastcgi.StdoutRecord(self._id, b""))
			self._send(fastcgi.EndRequestRecord(self._id, 0, fastcgi.EndRequestRecord.ProtocolStatus.REQUEST_COMPLETE))
		finally:
			if hasattr(result, "close"):
				result.close()
	
	
	def _write_stdout(self, b: bytes) -> None:
		off: int = 0
		while off < len(b):
			if (self._stdout_length == 0) and (len(b) - off >= _Request._RECORD_MAX_DATA_LENGTH):
				n: int = _Request._RECORD_MAX_DATA_LENGTH
				self._send(fastcgi.StdoutRecord(self._id, b[off : off + n]))
				off += n
			else:
				n = min(len(b) - off, _Request._RECORD_MAX_DATA_LENGTH - self._stdout_length)
				self._stdout.write(b[off : off + n])
				self._stdout_length += n
				off += n
				if self._stdout_length == _Request._RECORD_MAX_DATA_LENGTH:
					self._send(fastcgi.StdoutRecord(self._id, self._stdout.getvalue()))
					self._stdout = io.BytesIO()
					self._stdout_length = 0
	
	
	def _send(self, rc: fastcgi.Record) -> None:
		rc.send_to_socket(self._socket)
	
	
	_RECORD_MAX_DATA_LENGTH: int = 2**16 - 1
