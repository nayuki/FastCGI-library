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
import io, random, unittest
from record import *


class RecordTest(unittest.TestCase):
	
	def test_read_from_stream(self) -> None:
		CASES: list[tuple[str,Record|None]] = [
			("", None),
			("01 01 31DA 0008 00 00 0002010000000000", BeginRequestRecord(0x31DA, BeginRequestRecord.Role.AUTHORIZER, True, 0)),
			("01 02 70AE 0000 00 00", AbortRequestRecord(0x70AE, 0)),
			("01 03 4438 0008 00 00 1E30DB1201000000", EndRequestRecord(0x4438, 0x1E30DB12, EndRequestRecord.ProtocolStatus.CANT_MPX_CONN, 0)),
			("01 04 A8E4 0000 00 00", ParamsRecord(0xA8E4, b"", 0)),
			("01 05 D79C 0002 00 00 1E25", StdinRecord(0xD79C, b"\x1E\x25", 0)),
			("01 06 5090 0003 00 00 1F9501", StdoutRecord(0x5090, b"\x1F\x95\x01", 0)),
			("01 07 14EE 0004 00 00 F89CD8FD", StderrRecord(0x14EE, b"\xF8\x9C\xD8\xFD", 0)),
			("01 08 9904 0001 00 00 98", DataRecord(0x9904, b"\x98", 0)),
			("01 09 0000 0013 00 00 058000000044454C54418000000400414C4641", GetValuesRecord({"DELTA","ALFA"}, 0)),
			("01 0A 0000 001F 00 00 800000050544454C5441627261766F0480000007414C4641436861724C6965", GetValuesResultRecord({"DELTA":"bravo","ALFA":"CharLie"}, 0)),
			("01 0B 0000 0008 00 00 FF00000000000000", UnknownTypeRecord(255, 0)),
			("01 FE CA04 0005 03 00 F0E31CF2C6 000000", CustomRecord(254, 0xCA04, b"\xF0\xE3\x1C\xF2\xC6", 3)),
		]
		for (inhex, expect) in CASES:
			inhex = inhex.replace(" ", "")
			b: bytes = bytes.fromhex(inhex)
			inp: io.BufferedIOBase = io.BytesIO(b)
			actual: Record|None = Record.read_from_stream(inp)
			self.assertEqual(actual, expect)
	
	
	def test_construct_request_id_non_zero(self) -> None:
		CASES: list[int] = [
			1,
			300,
			65535,
			random.randint(1, 65535),
			random.randint(1, 65535),
			random.randint(1, 65535),
		]
		for reqid in CASES:
			BeginRequestRecord(reqid, BeginRequestRecord.Role.RESPONDER, False)
			AbortRequestRecord(reqid)
			EndRequestRecord(reqid, 0, EndRequestRecord.ProtocolStatus.REQUEST_COMPLETE)
			ParamsRecord(reqid, b"")
			StdinRecord(reqid, b"")
			StdoutRecord(reqid, b"")
			StderrRecord(reqid, b"")
			DataRecord(reqid, b"")
			CustomRecord(0, reqid, b"")
	
	
	def test_construct_request_id_zero(self) -> None:
		reqid: int = 0
		self.assertRaises(ValueError, lambda: BeginRequestRecord(reqid, BeginRequestRecord.Role.RESPONDER, False))
		self.assertRaises(ValueError, lambda: AbortRequestRecord(reqid))
		self.assertRaises(ValueError, lambda: EndRequestRecord(reqid, 0, EndRequestRecord.ProtocolStatus.REQUEST_COMPLETE))
		self.assertRaises(ValueError, lambda: ParamsRecord(reqid, b""))
		self.assertRaises(ValueError, lambda: StdinRecord(reqid, b""))
		self.assertRaises(ValueError, lambda: StdoutRecord(reqid, b""))
		self.assertRaises(ValueError, lambda: StderrRecord(reqid, b""))
		self.assertRaises(ValueError, lambda: DataRecord(reqid, b""))
		CustomRecord(0, reqid, b"")
	
	
	def test_construct_request_id_out_of_range(self) -> None:
		CASES: list[int] = [
			-99,
			-1,
			65536,
			100000,
		]
		for reqid in CASES:
			self.assertRaises(ValueError, lambda: CustomRecord(0, reqid, b""))
	
	
	def test_construct_padding_length(self) -> None:
		CASES: list[int] = [
			0,
			1,
			10,
			254,
			255,
			random.randrange(256),
			random.randrange(256),
			random.randrange(256),
		]
		for padlen in CASES:
			BeginRequestRecord(1, BeginRequestRecord.Role.RESPONDER, False, padlen)
			AbortRequestRecord(1, padlen)
			EndRequestRecord(1, 0, EndRequestRecord.ProtocolStatus.REQUEST_COMPLETE, padlen)
			ParamsRecord(1, b"", padlen)
			StdinRecord(1, b"", padlen)
			StdoutRecord(1, b"", padlen)
			StderrRecord(1, b"", padlen)
			DataRecord(1, b"", padlen)
			GetValuesRecord(set(), padlen),
			GetValuesResultRecord({}, padlen),
			UnknownTypeRecord(0, padlen),
			CustomRecord(0, 1, b"", padlen)
	
	
	def test_construct_padding_length_out_of_range(self) -> None:
		CASES: list[int] = [
			-99,
			-1,
			256,
			1000,
		]
		for padlen in CASES:
			self.assertRaises(ValueError, lambda: CustomRecord(0, 0, b"", padlen))
	
	
	def test_get_type(self) -> None:
		CASES: list[tuple[int,Record]] = [
			(1, BeginRequestRecord(1, BeginRequestRecord.Role.RESPONDER, False)),
			(2, AbortRequestRecord(1)),
			(3, EndRequestRecord(1, 0, EndRequestRecord.ProtocolStatus.REQUEST_COMPLETE)),
			(4, ParamsRecord(1, b"")),
			(5, StdinRecord(1, b"")),
			(6, StdoutRecord(1, b"")),
			(7, StderrRecord(1, b"")),
			(8, DataRecord(1, b"")),
			(9, GetValuesRecord(set())),
			(10, GetValuesResultRecord({})),
			(11, UnknownTypeRecord(0)),
			(224, CustomRecord(224, 1, b"")),
		]
		for (type, rec) in CASES:
			self.assertEqual(rec.get_type(), type)
	
	
	def test_get_request_id(self) -> None:
		CASES: list[tuple[int,Record]] = [
			(0x67D9, AbortRequestRecord(0x67D9)),
			(0x27E7, DataRecord(0x27E7, b"")),
			(0xBF2D, CustomRecord(0, 0xBF2D, b"")),
			(0, GetValuesRecord(set())),
			(0, GetValuesResultRecord({})),
			(0, UnknownTypeRecord(0)),
		]
		for (reqid, rec) in CASES:
			self.assertEqual(rec.get_request_id(), reqid)
	
	
	def test_get_content(self) -> None:
		CASES: list[tuple[str,Record]] = [
			("0002010000000000", BeginRequestRecord(0x31DA, BeginRequestRecord.Role.AUTHORIZER, True)),
			("", AbortRequestRecord(0x70AE, 0)),
			("1E30DB1201000000", EndRequestRecord(0x4438, 0x1E30DB12, EndRequestRecord.ProtocolStatus.CANT_MPX_CONN)),
			("", ParamsRecord(0xA8E4, b"")),
			("1E25", StdinRecord(0xD79C, b"\x1E\x25")),
			("1F9501", StdoutRecord(0x5090, b"\x1F\x95\x01")),
			("F89CD8FD", StderrRecord(0x14EE, b"\xF8\x9C\xD8\xFD")),
			("98", DataRecord(0x9904, b"\x98")),
			("FF00000000000000", UnknownTypeRecord(255)),
			("F0E31CF2C6", CustomRecord(254, 0xCA04, b"\xF0\xE3\x1C\xF2\xC6")),
		]
		for (outhex, rec) in CASES:
			outhex = outhex.replace(" ", "")
			b: bytes = bytes.fromhex(outhex)
			self.assertEqual(rec.get_content(), b)
	
	
	def test_get_content_random(self) -> None:
		TRIALS: int = 1000
		for _ in range(TRIALS):
			len: int = random.randrange(17)
			if len > 0:
				len = 2**(len - 1)
				len += random.randrange(len)
			b: bytes = random.randbytes(len)
			rec: Record
			match random.randrange(6):
				case 0:  rec = ParamsRecord(1, b)
				case 1:  rec = StdinRecord (1, b)
				case 2:  rec = StdoutRecord(1, b)
				case 3:  rec = StderrRecord(1, b)
				case 4:  rec = DataRecord  (1, b)
				case 5:  rec = CustomRecord(random.randrange(2**8), random.randrange(2**16), b)
				case _:  raise AssertionError()
			self.assertEqual(rec.get_content(), b)
	
	
	def test_get_padding_length(self) -> None:
		CASES: list[tuple[int,Record]] = [
			(3, EndRequestRecord(1, 0, EndRequestRecord.ProtocolStatus.REQUEST_COMPLETE, 3)),
			(0, StdinRecord(1, b"", 0)),
			(255, StdoutRecord(1, b"", 255)),
			(128, StderrRecord(1, b"", 128)),
			(57, GetValuesResultRecord({}, 57)),
			(1, CustomRecord(0, 0, b"", 1)),
		]
		for (padlen, rec) in CASES:
			self.assertEqual(rec.get_padding_length(), padlen)
	
	
	def test_to_bytes(self) -> None:
		CASES: list[tuple[str,Record]] = [
			("01 01 31DA 0008 00 00 0002010000000000", BeginRequestRecord(0x31DA, BeginRequestRecord.Role.AUTHORIZER, True, 0)),
			("01 02 70AE 0000 00 00", AbortRequestRecord(0x70AE, 0)),
			("01 03 4438 0008 00 00 1E30DB1201000000", EndRequestRecord(0x4438, 0x1E30DB12, EndRequestRecord.ProtocolStatus.CANT_MPX_CONN, 0)),
			("01 04 A8E4 0000 00 00", ParamsRecord(0xA8E4, b"", 0)),
			("01 05 D79C 0002 00 00 1E25", StdinRecord(0xD79C, b"\x1E\x25", 0)),
			("01 06 5090 0003 00 00 1F9501", StdoutRecord(0x5090, b"\x1F\x95\x01", 0)),
			("01 07 14EE 0004 00 00 F89CD8FD", StderrRecord(0x14EE, b"\xF8\x9C\xD8\xFD", 0)),
			("01 08 9904 0001 00 00 98", DataRecord(0x9904, b"\x98", 0)),
			("01 0B 0000 0008 00 00 FF00000000000000", UnknownTypeRecord(255, 0)),
			("01 FE CA04 0005 03 00 F0E31CF2C6 000000", CustomRecord(254, 0xCA04, b"\xF0\xE3\x1C\xF2\xC6", 3)),
		]
		for (outhex, rec) in CASES:
			outhex = outhex.replace(" ", "")
			b: bytes = bytes.fromhex(outhex)
			self.assertEqual(rec.to_bytes(), b)



if __name__ == "__main__":
	unittest.main()
