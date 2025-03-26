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
import enum, socket, struct


# ---- Record class hierarchy ----

class Record:  # Abstract
	
	_VERSION: int = 1
	_HEADER_FORMAT: str = ">BBHHBx"
	
	
	@staticmethod
	def read_from_socket(sock: socket.socket) -> Record|None:
		def recvall(n: int) -> bytes:
			if n < 0:
				raise ValueError("Negative read length")
			segs: list[bytes] = []
			while n > 0:
				b: bytes = sock.recv(n)
				if len(b) == 0:
					raise EOFError()
				segs.append(b)
				n -= len(b)
			return b"".join(segs)
		
		temp: bytes = sock.recv(struct.calcsize(Record._HEADER_FORMAT))
		if len(temp) == 0:
			return None
		header: bytes = temp + recvall(struct.calcsize(Record._HEADER_FORMAT) - len(temp))
		version, type, reqid, contentlen, padlen = struct.unpack(Record._HEADER_FORMAT, header)
		if version != Record._VERSION:
			raise ValueError("Unknown record version")
		content: bytes = recvall(contentlen)
		recvall(padlen)
		
		match type:
			case BeginRequestRecord   .TYPE:  return BeginRequestRecord   .parse_content(reqid, content, padlen)
			case AbortRequestRecord   .TYPE:  return AbortRequestRecord   .parse_content(reqid, content, padlen)
			case EndRequestRecord     .TYPE:  return EndRequestRecord     .parse_content(reqid, content, padlen)
			case ParamsRecord         .TYPE:  return ParamsRecord                       (reqid, content, padlen)
			case StdinRecord          .TYPE:  return StdinRecord                        (reqid, content, padlen)
			case StdoutRecord         .TYPE:  return StdoutRecord                       (reqid, content, padlen)
			case StderrRecord         .TYPE:  return StderrRecord                       (reqid, content, padlen)
			case DataRecord           .TYPE:  return DataRecord                         (reqid, content, padlen)
			case GetValuesRecord      .TYPE:  return GetValuesRecord      .parse_content(reqid, content, padlen)
			case GetValuesResultRecord.TYPE:  return GetValuesResultRecord.parse_content(reqid, content, padlen)
			case UnknownTypeRecord    .TYPE:  return UnknownTypeRecord    .parse_content(reqid, content, padlen)
			case _                         :  return CustomRecord                 (type, reqid, content, padlen)
	
	
	_request_id: int
	_padding_length: int
	
	
	def __init__(self, reqid: int, padlen: int):
		if reqid >> 16 != 0:
			raise ValueError("Request ID too large")
		self._request_id = reqid
		
		if padlen >> 8 != 0:
			raise ValueError("Padding length too large")
		self._padding_length = padlen
	
	
	def get_type(self) -> int:
		raise NotImplementedError()
	
	def get_request_id(self) -> int:
		return self._request_id
	
	def get_content(self) -> bytes:
		raise NotImplementedError()
	
	def get_padding_length(self) -> int:
		return self._padding_length
	
	
	def to_bytes(self) -> bytes:
		type: int = self.get_type()
		if type >> 8 != 0:
			raise ValueError("Type too large")
		
		content: bytes = self.get_content()
		if len(content) >> 16 != 0:
			raise ValueError("Content too long")
		
		return struct.pack(Record._HEADER_FORMAT, Record._VERSION, type, self._request_id, len(content), self._padding_length) \
			+ content + (b"\0" * self._padding_length)
	
	
	def send_to_socket(self, sock: socket.socket) -> None:
		sock.sendall(self.to_bytes())



class BeginRequestRecord(Record):
	
	TYPE: int = 1
	_FORMAT: str = ">HB5x"
	_FLAG_KEEP_CONN: int = 1 << 0
	
	
	@staticmethod
	def parse_content(reqid: int, content: bytes, padlen: int) -> BeginRequestRecord:
		roleint, flagsint = struct.unpack(BeginRequestRecord._FORMAT, content)
		for member0 in BeginRequestRecord.Role:
			if member0.value == roleint:
				role: BeginRequestRecord.Role = member0
				break
		else:
			raise ValueError(f"Unrecognized role: {roleint}")
		keepconn: bool = flagsint & BeginRequestRecord._FLAG_KEEP_CONN != 0
		flagsint &= ~BeginRequestRecord._FLAG_KEEP_CONN
		if flagsint != 0:
			raise ValueError("Unrecognized flag")
		return BeginRequestRecord(reqid, role, keepconn, padlen)
	
	
	_role: BeginRequestRecord.Role
	_keep_conn: bool
	
	
	def __init__(self, reqid: int, role: BeginRequestRecord.Role, keepconn: bool, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, padlen)
		self._role = role
		self._keep_conn = keepconn
	
	
	def get_role(self) -> BeginRequestRecord.Role:
		return self._role
	
	def get_keep_conn(self) -> bool:
		return self._keep_conn
	
	def get_type(self) -> int:
		return BeginRequestRecord.TYPE
	
	def get_content(self) -> bytes:
		return struct.pack(BeginRequestRecord._FORMAT, self._role.value, (BeginRequestRecord._FLAG_KEEP_CONN if self._keep_conn else 0))
	
	def __repr__(self) -> str:
		return f"BeginRequestRecord(reqid={self._request_id}, role={self._role}, keepconn={self._keep_conn}, padlen={self._padding_length})"
	
	
	class Role(enum.Enum):
		RESPONDER: int = 1
		AUTHORIZER: int = 2
		FILTER: int = 3



class AbortRequestRecord(Record):
	
	TYPE: int = 2
	_FORMAT: str = ">"
	
	
	@staticmethod
	def parse_content(reqid: int, content: bytes, padlen: int) -> AbortRequestRecord:
		struct.unpack(AbortRequestRecord._FORMAT, content)
		return AbortRequestRecord(reqid, padlen)
	
	
	def __init__(self, reqid: int, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, padlen)
	
	
	def get_type(self) -> int:
		return AbortRequestRecord.TYPE
	
	def get_content(self) -> bytes:
		return struct.pack(AbortRequestRecord._FORMAT)
	
	def __repr__(self) -> str:
		return f"AbortRequestRecord(reqid={self._request_id}, padlen={self._padding_length})"



class EndRequestRecord(Record):
	
	TYPE: int = 3
	_FORMAT: str = ">IB3x"
	
	
	@staticmethod
	def parse_content(reqid: int, content: bytes, padlen: int) -> EndRequestRecord:
		appstat, protostatint = struct.unpack(EndRequestRecord._FORMAT, content)
		for member in EndRequestRecord.ProtocolStatus:
			if member.value == protostatint:
				protostat: EndRequestRecord.ProtocolStatus = member
				break
		else:
			raise ValueError(f"Unrecognized protocol status: {protostatint}")
		return EndRequestRecord(reqid, appstat, protostat, padlen)
	
	
	_application_status: int
	_protocol_status: EndRequestRecord.ProtocolStatus
	
	
	def __init__(self, reqid: int, appstat: int, protostat: ProtocolStatus, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, padlen)
		if appstat >> 32 != 0:
			raise ValueError("Application status too large")
		self._application_status = appstat
		self._protocol_status = protostat
	
	
	def get_application_status(self) -> int:
		return self._application_status
	
	def get_protocol_status(self) -> EndRequestRecord.ProtocolStatus:
		return self._protocol_status
	
	def get_type(self) -> int:
		return EndRequestRecord.TYPE
	
	def get_content(self) -> bytes:
		return struct.pack(EndRequestRecord._FORMAT, self._application_status, self._protocol_status.value)
	
	def __repr__(self) -> str:
		return f"EndRequestRecord(reqid={self._request_id}, appstatus={self._application_status}, protocolstatus={self._protocol_status}, padlen={self._padding_length})"
	
	
	class ProtocolStatus(enum.Enum):
		REQUEST_COMPLETE: int = 0
		CANT_MPX_CONN: int = 1
		OVERLOADED: int = 2
		UNKNOWN_ROLE: int = 3



class _SimpleRecord(Record):  # Abstract
	_content: bytes
	
	def __init__(self, reqid: int, content: bytes, padlen: int):
		super().__init__(reqid, padlen)
		if len(content) >> 16 != 0:
			raise ValueError("Content too long")
		self._content = content
	
	def get_content(self) -> bytes:
		return self._content
	
	def __repr__(self) -> str:
		return f"{type(self).__name__}(reqid={self._request_id}, contentlen={len(self._content)}, padlen={self._padding_length})"



class ParamsRecord(_SimpleRecord):
	TYPE: int = 4
	
	def __init__(self, reqid: int, content: bytes, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, content, padlen)
	
	def get_type(self) -> int:
		return ParamsRecord.TYPE



class StdinRecord(_SimpleRecord):
	TYPE: int = 5
	
	def __init__(self, reqid: int, content: bytes, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, content, padlen)
	
	def get_type(self) -> int:
		return StdinRecord.TYPE



class StdoutRecord(_SimpleRecord):
	TYPE: int = 6
	
	def __init__(self, reqid: int, content: bytes, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, content, padlen)
	
	def get_type(self) -> int:
		return StdoutRecord.TYPE



class StderrRecord(_SimpleRecord):
	TYPE: int = 7
	
	def __init__(self, reqid: int, content: bytes, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, content, padlen)
	
	def get_type(self) -> int:
		return StderrRecord.TYPE



class DataRecord(_SimpleRecord):
	TYPE: int = 8
	
	def __init__(self, reqid: int, content: bytes, padlen: int = 0):
		if reqid == 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, content, padlen)
	
	def get_type(self) -> int:
		return DataRecord.TYPE



class GetValuesRecord(Record):
	
	TYPE: int = 9
	
	
	@staticmethod
	def parse_content(reqid: int, content: bytes, padlen: int) -> GetValuesRecord:
		pairs: dict[str,str] = name_values_to_dict(content)
		if any(v != "" for v in pairs.values()):
			raise ValueError("Non-empty value")
		return GetValuesRecord(reqid, set(pairs.keys()), padlen)
	
	
	_names: set[str]
	
	
	def __init__(self, reqid: int, names: set[str], padlen: int = 0):
		if reqid != 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, padlen)
		self._names = set(names)
	
	
	def get_names(self) -> set[str]:
		return self._names
	
	def get_type(self) -> int:
		return GetValuesRecord.TYPE
	
	def get_content(self) -> bytes:
		return dict_to_name_values({k: "" for k in self._names})
	
	def __repr__(self) -> str:
		return f"GetValuesRecord(reqid={self._request_id}, names={self._names}, padlen={self._padding_length})"



class GetValuesResultRecord(Record):
	
	TYPE: int = 10
	
	
	@staticmethod
	def parse_content(reqid: int, content: bytes, padlen: int) -> GetValuesResultRecord:
		return GetValuesResultRecord(reqid, name_values_to_dict(content), padlen)
	
	
	_pairs: dict[str,str]
	
	
	def __init__(self, reqid: int, pairs: dict[str,str], padlen: int = 0):
		if reqid != 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, padlen)
		self._pairs = dict(pairs)
	
	
	def get_pairs(self) -> dict[str,str]:
		return self._pairs
	
	def get_type(self) -> int:
		return GetValuesResultRecord.TYPE
	
	def get_content(self) -> bytes:
		return dict_to_name_values(self._pairs)
	
	def __repr__(self) -> str:
		return f"GetValuesResultRecord(reqid={self._request_id}, pairs={self._pairs}, padlen={self._padding_length})"



class UnknownTypeRecord(Record):
	
	TYPE: int = 11
	_FORMAT: str = ">B7x"
	
	
	@staticmethod
	def parse_content(reqid: int, content: bytes, padlen: int) -> UnknownTypeRecord:
		unknowntype, = struct.unpack(UnknownTypeRecord._FORMAT, content)
		return UnknownTypeRecord(reqid, unknowntype, padlen)
	
	
	_unknown_type: int
	
	
	def __init__(self, reqid: int, unknowntype: int, padlen: int = 0):
		if reqid != 0:
			raise ValueError("Invalid request ID")
		super().__init__(reqid, padlen)
		if unknowntype >> 32 != 0:
			raise ValueError("Application status too large")
		self._unknown_type = unknowntype
	
	
	def get_unknown_type(self) -> int:
		return self._unknown_type
	
	def get_type(self) -> int:
		return UnknownTypeRecord.TYPE
	
	def get_content(self) -> bytes:
		return struct.pack(UnknownTypeRecord._FORMAT, self._unknown_type)
	
	def __repr__(self) -> str:
		return f"UnknownTypeRecord(reqid={self._request_id}, unknowntype={self._unknown_type}, padlen={self._padding_length})"



class CustomRecord(_SimpleRecord):
	_type: int
	
	def __init__(self, type: int, reqid: int, content: bytes, padlen: int = 0):
		if type >> 8 != 0:
			raise ValueError("Type too large")
		self._type = type
		super().__init__(reqid, content, padlen)
	
	def get_type(self) -> int:
		return self._type
	
	def __repr__(self) -> str:
		return f"CustomRecord(type={self._type}, reqid={self._request_id}, contentlen={len(self._content)}, padlen={self._padding_length})"



# ---- Name-value pairs ----

def name_values_to_dict(b: bytes) -> dict[str,str]:
	result: dict[str,str] = {}
	i: int = 0
	while i < len(b):
		lens: list[int] = []
		for _ in range(2):
			n: int = b[i]
			if n < 128:
				i += 1
			else:
				n = struct.unpack(">I", b[i : i + 4])[0] ^ (1 << 31)
				i += 4
			lens.append(n)
		keyb: bytes = b[i : i + lens[0]]
		i += lens[0]
		valb: bytes = b[i : i + lens[1]]
		i += lens[1]
		if i > len(b):
			raise EOFError()
		result[keyb.decode("UTF-8")] = valb.decode("UTF-8")
	return result


def dict_to_name_values(d: dict[str,str]) -> bytes:
	segs: list[bytes] = []
	for (key, val) in d.items():
		keyb: bytes = key.encode("UTF-8")
		valb: bytes = val.encode("UTF-8")
		for n in (len(keyb), len(valb)):
			segs.append(struct.pack(">B", n) if (n < 128)
				else struct.pack(">I", n | (1 << 31)))
		segs.append(keyb)
		segs.append(valb)
	return b"".join(segs)
