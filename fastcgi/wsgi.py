# 
# FastCGI library
# 
# Copyright (c) Project Nayuki. (MIT License)
# https://www.nayuki.io/page/fastcgi-library
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
import collections, io, os, pathlib, socket, threading, time
from typing import Callable, Iterable
from . import record


_WriteType = Callable[[bytes],None]
_StartResponseType = Callable[[str,list[tuple[str,str]]],_WriteType]
_ApplicationType = Callable[[dict[str,object],_StartResponseType],Iterable[bytes]]


class Server:
	
	_application: _ApplicationType
	_server_socket: socket.socket
	_executor: ThreadPoolExecutor
	
	
	def __init__(self, app: _ApplicationType, bindaddr: str, *, umask: int|None = None, listen_backlog: int = 1000, executor: ThreadPoolExecutor|None = None):
		self._application = app
		
		pathlib.Path(bindaddr).unlink(True)
		self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		
		if umask is None:
			self._server_socket.bind(bindaddr)
		else:
			oldmask: int = os.umask(umask)
			try:
				self._server_socket.bind(bindaddr)
			finally:
				os.umask(oldmask)
		
		self._server_socket.listen(listen_backlog)
		self._executor = ThreadPoolExecutor() if (executor is None) else executor
	
	
	def run(self) -> None:
		with self._server_socket:
			while True:
				sock, _ = self._server_socket.accept()
				self._executor.submit(self._make_task(sock))
	
	
	def _make_task(self, sock: socket.socket) -> Callable[[],None]:
		def run() -> None:
			with sock:
				try:
					req: _Request|None = None
					while True:
						rc: record.Record|None = record.Record.read_from_socket(sock)
						if rc is None:
							if req is not None:
								raise EOFError()
							break
						elif rc.get_request_id() == 0:
							raise ValueError("Unknown management record type")
						elif isinstance(rc, record.BeginRequestRecord):
							if req is not None:
								raise ValueError("Concurrent request")
							req = _Request(self._application, sock, rc)
						elif (req is None) or (rc.get_request_id() != req.get_id()):
							raise ValueError("Missing request")
						elif isinstance(rc, record.ParamsRecord):
							req._params.write(rc.get_content())
						elif isinstance(rc, record.StdinRecord):
							b: bytes = rc.get_content()
							req._stdin.write(b)
							if len(b) == 0:
								req._process()
								keepconn: bool = req._keep_conn
								req = None
								if not keepconn:
									break
						else:
							raise ValueError("Unknown request record type")
				except BrokenPipeError:
					pass
		
		return run



class ThreadPoolExecutor:
	
	_min_workers: int
	_max_workers: int
	_lock: threading.Lock
	_queue_nonempty: threading.Condition
	_queue: collections.deque[Callable[[],None]|None]
	_num_workers: int
	_num_idle_workers: int
	_cleanable: threading.Condition
	
	
	def __init__(self, minworkers: int|None = None, maxworkers: int = 100):
		if minworkers is None:
			minworkers = os.cpu_count()
			if minworkers is None:
				minworkers = 1
		maxworkers = max(minworkers, maxworkers)
		self._min_workers = minworkers
		self._max_workers = maxworkers
		
		self._lock = threading.Lock()
		self._queue_nonempty = threading.Condition(self._lock)
		self._queue = collections.deque()
		self._num_workers = 0
		self._num_idle_workers = 0
		
		self._cleanable = threading.Condition(self._lock)
		threading.Thread(target=self._cleaner).start()
	
	
	def _worker(self) -> None:
		try:
			while True:
				with self._lock:
					self._num_idle_workers += 1
					if self._num_workers > self._min_workers:
						self._cleanable.notify()
					try:
						while len(self._queue) == 0:
							self._queue_nonempty.wait()
						item: Callable[[],None]|None = self._queue.popleft()
					finally:
						self._num_idle_workers -= 1
				if item is None:
					break
				else:
					item()
		finally:
			with self._lock:
				self._num_workers -= 1
	
	
	def submit(self, task: Callable[[],None]) -> None:
		with self._lock:
			self._queue.append(task)
			if self._num_idle_workers > 0:
				self._queue_nonempty.notify()
			elif self._num_workers < self._max_workers:
				threading.Thread(target=self._worker).start()
				self._num_workers += 1
	
	
	def _cleaner(self) -> None:
		while True:
			time.sleep(10)
			with self._lock:
				if (self._num_workers > self._min_workers) and (self._num_idle_workers > 0):
					self._queue.append(None)
					self._queue_nonempty.notify()
				else:
					self._cleanable.wait()



class _Request:
	
	# Immutable
	_application: _ApplicationType
	_socket: socket.socket
	_id: int
	_keep_conn: bool
	
	# Mutable
	_params: io.BytesIO
	_stdin: io.BytesIO
	_headers: list[str]
	_headers_written: bool
	
	
	def __init__(self, app: _ApplicationType, sock: socket.socket, rc: record.BeginRequestRecord):
		self._application = app
		self._socket = sock
		self._id = rc.get_request_id()
		self._keep_conn = rc.get_keep_conn()
		self._params = io.BytesIO()
		self._stdin = io.BytesIO()
		self._headers = []
		self._headers_written = False
	
	
	def get_id(self) -> int:
		return self._id
	
	
	def _process(self) -> None:
		self._stdin.seek(0)
		environ: dict[str,object] = {
			"wsgi.version": (1, 0),
			"wsgi.input": self._stdin,
			"wsgi.errors": io.StringIO(),
			"wsgi.multithread": True,
			"wsgi.multiprocess": False,
			"wsgi.run_once": False,
		}
		environ.update(record.name_values_to_dict(self._params.getvalue()))
		environ["wsgi.url_scheme"] = environ["REQUEST_SCHEME"]
		
		result: Iterable[bytes] = self._application(environ, self._start_response)
		try:
			for b in result:
				self._write_stdout(b)
			self._write_headers()
			self._send(record.StdoutRecord(self._id, b""))
			self._send(record.EndRequestRecord(self._id, 0, record.EndRequestRecord.ProtocolStatus.REQUEST_COMPLETE))
		finally:
			if hasattr(result, "close"):
				result.close()
	
	
	def _start_response(self, status: str, respheaders: list[tuple[str,str]], excinfo: object = None) -> _WriteType:
		if self._headers_written:
			raise ValueError("Headers already written")
		if (len(self._headers) > 0) and (excinfo is None):
			raise ValueError("Headers already set")
		self._headers = ["HTTP/1.0 " + status] + [": ".join(kv) for kv in respheaders] + ["", ""]
		return self._write_stdout
	
	
	def _write_stdout(self, b: bytes) -> None:
		off: int = 0
		while off < len(b):
			self._write_headers()
			n: int = min(len(b) - off, _Request._RECORD_MAX_DATA_LENGTH)
			self._send(record.StdoutRecord(self._id,
				b if (n == len(b)) else b[off : off + n]))
			off += n
	
	
	def _write_headers(self) -> None:  # Idempotent
		if self._headers_written:
			return
		elif len(self._headers) == 0:
			raise ValueError("Headers not set")
		else:
			self._headers_written = True
			self._write_stdout("\r\n".join(self._headers).encode("ISO-8859-1"))
			self._headers = []
	
	
	def _send(self, rc: record.Record) -> None:
		rc.send_to_socket(self._socket)
	
	
	_RECORD_MAX_DATA_LENGTH: int = 2**16 - 1
