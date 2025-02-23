#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from py65emu.cpu import CPU
from py65emu.mmu import MMU
from py65emu.operands import *

from collections import defaultdict, namedtuple
import random
import sys
import struct
import os
from datetime import datetime, timedelta

SECTOR_SIZE = 128

def dump_memory_block(data,start_data=0,size=SECTOR_SIZE):
	for l in range(0,size,16):
		print('%04x: ' % (start_data+l),end='')
		for p in range(0,16):
			print('%02x ' % data[start_data + l + p],end='')
		print(' ',end='')
		for p in range(0,16):
			c = data[start_data + l + p]
			if c < 0x20 or c >= 0x7F:
				c = ord('.')
			print('%c' % c,end='')
		print('')

def atx_readSector(atxData, sectorNo, sectorIndex):
	offset = 0

	onTrack = (sectorNo - 1) // 18
	onSector = sectorNo - onTrack * 18

	# read file header
	header,version_number,fh_size = struct.unpack('<4sh22xl16x', atxData[offset+0:offset+0x30])
	if header != b'AT8X':
		print('File Header AT8X not found')
		return
	if fh_size != 48:
		print('File Header Size != 48 bytes')
		return
	if version_number != 1:
		print('File Header Version != 1')
		return
	offset += fh_size

	while offset < len(atxData):
		# read track header
		th_record_size,record_type,track_number,sector_count,th_size = struct.unpack('<lh2xB1xh8xl8x', atxData[offset+0:offset+0x20])
		if th_size != 32:
			print('Track Header Size != 32 bytes')
			return False
		if record_type != 0:
			print('Track Header record type != data track')
			return False
		if track_number == onTrack:
			track = atxData[offset+0:offset+th_record_size]
			# read sector list header
			record_size,record_type = struct.unpack('<lB3x', track[th_size+0:th_size+8])
			if record_type != 1:
				print('Sector List Header record type != sector list')
				return False

			# read sector list
			sectors = []
			for sectorHeaderOffset in range(th_size+8,th_size+record_size,8):
				sector_number,sector_status,sector_position,start_data = struct.unpack('<BBhl', track[sectorHeaderOffset+0:sectorHeaderOffset+8])
				if sector_number == onSector:
					sectors.append((track[start_data:start_data+SECTOR_SIZE],sector_status))
			
			if len(sectors):
				return sectors[sectorIndex % len(sectors)]

		# proceed to the next track
		offset += th_record_size

	return [0] * SECTOR_SIZE,0x80

def readSector(sectorNo, sectorIndex):
	data,status = atx_readSector(atxDiskImage, sectorNo, sectorIndex)
	if True:
		if status != 0x00:
			print('$$$ STATUS = $%02x' % status)
		#dump_memory_block(data)
	return data,status

def readBootFile(cpu):
	global showOutput
	global bootSectorAdr
	global bootSectorCount

	showOutput += 1
	bootSectorData,sectorStatus = readSector(1, 0)
	for i in range(0,0x80): # copy to boot sector the PAGE 4
		cpu.mmu.write(0x400+i, bootSectorData[i])
	bootSectorAdr = bootSectorData[2] | (bootSectorData[3]<<8)
	bootContinue = bootSectorData[4] | (bootSectorData[5]<<8)
	cpu.JSR(bootSectorAdr + 6) # init
	cpu.mmu.write(0x101 + cpu.r.s, (bootContinue - 1) & 0xFF)
	cpu.mmu.write(0x102 + cpu.r.s, (bootContinue - 1) >> 8)
	bootSectorCount = bootSectorData[1]
	if bootSectorCount == 0:
		bootSectorCount = 256
	bdata = bytearray()
	badr = bootSectorAdr
	for sector in range(1, bootSectorCount+1):
		dsk_offset = (sector - 1) * SECTOR_SIZE + 16 # 16 bytes header
		if showROMAccess:
			print('$$$ READ SECTOR ADDR:$%04x BYTES:$%04x SECTOR:%3d [DSK OFFSET:$%08x]' % (badr,SECTOR_SIZE,sector, dsk_offset))
		sectorData,sectorStatus = readSector(sector, 0)
		bdata += sectorData
		for r in range(0,SECTOR_SIZE):
			cpu.mmu.write(badr + r, sectorData[r])
		badr += SECTOR_SIZE
	showOutput -= 1

def addr_mode_in(opcode, *modes):
	if isinstance(opcode, dict):
		src = opcode['src']
		dst = opcode['dst']
	else:
		src = opcode.src
		dst = opcode.dst

	return (src in modes) or (dst in modes)

def Op(**kwargs):
	size = 1

	if addr_mode_in(kwargs, M_ADDR, M_ABS, M_ABSX, M_ABSY, M_AIND):
		size += 2
	elif addr_mode_in(kwargs, M_IMM, M_INDX, M_INDY, M_REL, M_ZERO, M_ZERX, M_ZERY):
		size += 1

	kwargs['size'] = size

	Opcode = namedtuple('Opcode', 'mnemonic src dst cycles size')
	return Opcode(**kwargs)

def formatAddress(addr,readMode=True,size=4):
	SYMBOLS = [
		{ 'ADR':0x0008, 'LABEL':'WARMST' },
		{ 'ADR':0x0009, 'LABEL':'BOOT?' },
		{ 'ADR':0x000A, 'LABEL':'DOSVEC', 'SIZE':2 },
		{ 'ADR':0x000C, 'LABEL':'DOSINI', 'SIZE':2 },
		{ 'ADR':0x0012, 'LABEL':'RTCLOK', 'SIZE':3 },
		{ 'ADR':0x0041, 'LABEL':'SOUNDR' },
		{ 'ADR':0x004D, 'LABEL':'ATRACT' },

		{ 'ADR':0x0100, 'LABEL':'STACK', 'SIZE':256 },

		{ 'ADR':0x0200, 'LABEL':'VDSLST', 'SIZE':2 },
		{ 'ADR':0x0202, 'LABEL':'VPRCED', 'SIZE':2 },
		{ 'ADR':0x0204, 'LABEL':'VINTER', 'SIZE':2 },
		{ 'ADR':0x0206, 'LABEL':'VBREAK', 'SIZE':2 },
		{ 'ADR':0x0208, 'LABEL':'VKEYBD', 'SIZE':2 },
		{ 'ADR':0x020A, 'LABEL':'VSERIN', 'SIZE':2 },
		{ 'ADR':0x020C, 'LABEL':'VSEROR', 'SIZE':2 },
		{ 'ADR':0x020E, 'LABEL':'VSEROC', 'SIZE':2 },
		{ 'ADR':0x0210, 'LABEL':'VTIMR1', 'SIZE':2 },
		{ 'ADR':0x0212, 'LABEL':'VTIMR2', 'SIZE':2 },
		{ 'ADR':0x0214, 'LABEL':'VTIMR4', 'SIZE':2 },
		{ 'ADR':0x0216, 'LABEL':'VIMIRQ', 'SIZE':2 },
		{ 'ADR':0x0218, 'LABEL':'CDTMV1', 'SIZE':2 },
		{ 'ADR':0x021A, 'LABEL':'CDTMV2', 'SIZE':2 },
		{ 'ADR':0x021C, 'LABEL':'CDTMV3', 'SIZE':2 },
		{ 'ADR':0x021E, 'LABEL':'CDTMV4', 'SIZE':2 },
		{ 'ADR':0x0220, 'LABEL':'CDTMV5', 'SIZE':2 },
		{ 'ADR':0x0222, 'LABEL':'VVBLKI', 'SIZE':2 },
		{ 'ADR':0x0224, 'LABEL':'VVBLKD', 'SIZE':2 },
		{ 'ADR':0x0226, 'LABEL':'CDTMA1', 'SIZE':2 },
		{ 'ADR':0x0228, 'LABEL':'CDTMA2', 'SIZE':2 },
		{ 'ADR':0x022A, 'LABEL':'CDTMA3' },
		{ 'ADR':0x022B, 'LABEL':'SRTIMR' },
		{ 'ADR':0x022C, 'LABEL':'CDTMF4' },
		{ 'ADR':0x022D, 'LABEL':'INTEMP' },
		{ 'ADR':0x022E, 'LABEL':'CDTMF5' },
		{ 'ADR':0x022F, 'LABEL':'SDMCTL' },
		{ 'ADR':0x0230, 'LABEL':'SDLSTL' },
		{ 'ADR':0x0231, 'LABEL':'SDLSTH' },
		{ 'ADR':0x0240, 'LABEL':'DFLAGS' },
		{ 'ADR':0x0241, 'LABEL':'DBSECT' },
		{ 'ADR':0x0242, 'LABEL':'BOOTAD', 'SIZE':2 },
		{ 'ADR':0x0244, 'LABEL':'COLDST' },
		{ 'ADR':0x02C0, 'LABEL':'PCOLR0' },
		{ 'ADR':0x02C1, 'LABEL':'PCOLR1' },
		{ 'ADR':0x02C2, 'LABEL':'PCOLR2' },
		{ 'ADR':0x02C3, 'LABEL':'PCOLR3' },
		{ 'ADR':0x02C4, 'LABEL':'COLOR0' },
		{ 'ADR':0x02C5, 'LABEL':'COLOR1' },
		{ 'ADR':0x02C6, 'LABEL':'COLOR2' },
		{ 'ADR':0x02C7, 'LABEL':'COLOR3' },
		{ 'ADR':0x02C8, 'LABEL':'COLOR4' },

		{ 'ADR':0x0300, 'LABEL':'DDEVIC' },
		{ 'ADR':0x0301, 'LABEL':'DUNIT' },
		{ 'ADR':0x0302, 'LABEL':'DCOMND' },
		{ 'ADR':0x0303, 'LABEL':'DSTATS' },
		{ 'ADR':0x0304, 'LABEL':'DBUFLO' },
		{ 'ADR':0x0305, 'LABEL':'DBUFHI' },
		{ 'ADR':0x0306, 'LABEL':'DTIMLO' },
		{ 'ADR':0x0307, 'LABEL':'DUNUSE' },
		{ 'ADR':0x0308, 'LABEL':'DBYTLO' },
		{ 'ADR':0x0309, 'LABEL':'DBYTHI' },
		{ 'ADR':0x030a, 'LABEL':'DAUX1' },
		{ 'ADR':0x030b, 'LABEL':'DAUX2' },
		{ 'ADR':0x031a, 'LABEL':'HATABS', 'SIZE':6 },
		{ 'ADR':0x03c0, 'LABEL':'PRNBUF', 'SIZE':40 },

		# GTIA
		{ 'ADR':0xD000, 'LABEL':'M0PF', 'WLABEL':'HPOSP0' },
		{ 'ADR':0xD001, 'LABEL':'M1PF', 'WLABEL':'HPOSP1' },
		{ 'ADR':0xD002, 'LABEL':'M2PF', 'WLABEL':'HPOSP2' },
		{ 'ADR':0xD003, 'LABEL':'M3PF', 'WLABEL':'HPOSP3' },

		{ 'ADR':0xD004, 'LABEL':'P0PF', 'WLABEL':'HPOSM0' },
		{ 'ADR':0xD005, 'LABEL':'P1PF', 'WLABEL':'HPOSM1' },
		{ 'ADR':0xD006, 'LABEL':'P2PF', 'WLABEL':'HPOSM2' },
		{ 'ADR':0xD007, 'LABEL':'P3PF', 'WLABEL':'HPOSM3' },

		{ 'ADR':0xD008, 'LABEL':'M0PL', 'WLABEL':'SIZEP0' },
		{ 'ADR':0xD009, 'LABEL':'M1PL', 'WLABEL':'SIZEP1' },
		{ 'ADR':0xD00a, 'LABEL':'M2PL', 'WLABEL':'SIZEP2' },
		{ 'ADR':0xD00b, 'LABEL':'M3PL', 'WLABEL':'SIZEP3' },

		{ 'ADR':0xD00c, 'LABEL':'P0PL', 'WLABEL':'SIZEM' },
		{ 'ADR':0xD00d, 'LABEL':'P1PL', 'WLABEL':'GRAFP0' },
		{ 'ADR':0xD00e, 'LABEL':'P2PL', 'WLABEL':'GRAFP1' },
		{ 'ADR':0xD00f, 'LABEL':'P3PL', 'WLABEL':'GRAFP2' },
		{ 'ADR':0xD010, 'LABEL':'TRIG0', 'WLABEL':'GRAFP3' },
		{ 'ADR':0xD011, 'LABEL':'TRIG1', 'WLABEL':'GRAFM' },
		{ 'ADR':0xD012, 'LABEL':'TRIG2', 'WLABEL':'COLPM0' },
		{ 'ADR':0xD013, 'LABEL':'TRIG3', 'WLABEL':'COLPM1' },
		{ 'ADR':0xD014, 'LABEL':'PAL', 'WLABEL':'COLPM2' },
		{ 'ADR':0xD015, 'WLABEL':'COLPM3' },

		{ 'ADR':0xD016, 'WLABEL':'COLPF0' },
		{ 'ADR':0xD017, 'WLABEL':'COLPF1' },
		{ 'ADR':0xD018, 'WLABEL':'COLPF1' },
		{ 'ADR':0xD019, 'WLABEL':'COLPF2' },
		{ 'ADR':0xD01a, 'WLABEL':'COLBK' },
		{ 'ADR':0xD01b, 'WLABEL':'PRIOR' },
		{ 'ADR':0xD01c, 'WLABEL':'VDELAY' },
		{ 'ADR':0xD01d, 'WLABEL':'GRACTL' },
		{ 'ADR':0xD01e, 'WLABEL':'HITCLR' },
		{ 'ADR':0xD01f, 'LABEL':'CONSOL' },

		# POKEY
		{ 'ADR':0xD200, 'LABEL':'POT0', 'WLABEL':'AUDF1' },
		{ 'ADR':0xD201, 'LABEL':'POT1', 'WLABEL':'AUDC1' },
		{ 'ADR':0xD202, 'LABEL':'POT2', 'WLABEL':'AUDF2' },
		{ 'ADR':0xD203, 'LABEL':'POT3', 'WLABEL':'AUDC2' },
		{ 'ADR':0xD204, 'LABEL':'POT4', 'WLABEL':'AUDF3' },
		{ 'ADR':0xD205, 'LABEL':'POT5', 'WLABEL':'AUDC3' },
		{ 'ADR':0xD206, 'LABEL':'POT6', 'WLABEL':'AUDF4' },
		{ 'ADR':0xD207, 'LABEL':'POT7', 'WLABEL':'AUDC4' },
		{ 'ADR':0xD208, 'LABEL':'ALLPOT', 'WLABEL':'AUDCTL' },
		{ 'ADR':0xD209, 'LABEL':'KBCODE', 'WLABEL':'STIMER' },
		{ 'ADR':0xD20A, 'LABEL':'RANDOM', 'WLABEL':'SKREST' },
		{ 'ADR':0xD20B, 'WLABEL':'POTGO' },
		{ 'ADR':0xD20D, 'LABEL':'SERIN', 'WLABEL':'SEROUT' },
		{ 'ADR':0xD20E, 'LABEL':'IRQST', 'WLABEL':'IRQEN' },
		{ 'ADR':0xD20F, 'LABEL':'SKSTAT', 'WLABEL':'SKCTL' },

		# ANTIC
		{ 'ADR':0xD400, 'WLABEL':'DMACTL' },
		{ 'ADR':0xD401, 'WLABEL':'CHACTL' },
		{ 'ADR':0xD402, 'WLABEL':'DISTL' },
		{ 'ADR':0xD403, 'WLABEL':'DISTH' },
		{ 'ADR':0xD404, 'WLABEL':'HSCROL' },
		{ 'ADR':0xD405, 'WLABEL':'VSCROL' },
		{ 'ADR':0xD407, 'WLABEL':'PMBASE' },
		{ 'ADR':0xD409, 'WLABEL':'CHBASE' },
		{ 'ADR':0xD40A, 'WLABEL':'WSYNC' },
		{ 'ADR':0xD40B, 'LABEL':'VCOUNT' },
		{ 'ADR':0xD40C, 'LABEL':'PENH' },
		{ 'ADR':0xD40D, 'LABEL':'PENV' },
		{ 'ADR':0xD40E, 'WLABEL':'NMIEN' },
		{ 'ADR':0xD40F, 'LABEL':'NMIST', 'WLABEL':'NMIRES' },

		{ 'ADR':0xE456, 'LABEL':'CIOV', 'SIZE':3 },
		{ 'ADR':0xE459, 'LABEL':'SIOV', 'SIZE':3 },
		{ 'ADR':0xE465, 'LABEL':'SIOINV', 'SIZE':3 },
		{ 'ADR':0xE474, 'LABEL':'WARMSV', 'SIZE':3 },
		{ 'ADR':0xE477, 'LABEL':'COLDSV', 'SIZE':3 },
	]
	for sym in SYMBOLS:
		sadr = sym['ADR']
		if addr < sadr:
			continue
		if 'SIZE' in sym:
			ssize = sym['SIZE']
		else:
			ssize = 1
		if addr >= sadr + ssize:
			continue
		label = None
		if 'LABEL' in sym:
			label = sym['LABEL']
		if readMode == False or label == None:
			if 'WLABEL' in sym:
				label = sym['WLABEL']
		if not label: # label for read not available => print address
			break
		if sadr == addr:
			return '%s[$%04x]' % (label,addr)
		else:
			return '%s+%d[$%04x]' % (label,addr-sadr,addr)
	if size == 2:
		return '$%02x' % addr
	else:
		return '$%04x' % addr

class DebugMMU(MMU):
	random = 0x00

	def __init__(self, blocks):
		self.reads = set()
		self.writes = set()
		MMU.__init__(self, blocks)

	def addr_visible(self, addr):
		if addr >= 0x06FA and addr <= 0x06FD: # rest of the RAM
			return True
		return False
		if addr >= 0x0300 and addr <= 0x030b: # Disk DCB
			return False
		if addr >= 0x0400 and addr <= 0x047F: # Encrypted sector buffer A
			return False
		if addr >= 0x0480 and addr <= 0xBFFF: # rest of the RAM
			return False
		if addr >= 0xC000 and addr <= 0xCFFF: # Unused
			return False
		if addr >= 0xD000 and addr <= 0xD7FF: # Hardware 1/0 decodes
			return True
		if addr >= 0xD800 and addr <= 0xDFFF: # Floating Point Package (OS)
			return False
		if addr >= 0xE000 and addr <= 0xFFFF: # Resident Operating System ROM
			return True
		if addr >= 0x0480 and addr <= 0xBFFF: # rest of the RAM
			return False
		return True

	def write(self, addr, value):
		self.writes.add(addr)
		super().write(addr, value)
		global showOutput
		if self.addr_visible(addr) and showOutput == 0:
			print('### W %s <= $%02x' % (self.addr_label(addr,readMode=False), value))
		if False and addr >= 0x00F0 and addr < 0x0200: # print variables and stack
			showOutput += 1
			LINEWIDTH = 16
			for r in range(0x00F0,0x0200,LINEWIDTH):
				print('$%04x: ' % r,end='')
				for r2 in range(0,LINEWIDTH):
					print('%02x ' % self.read(r + r2),end='')
				print()
			print()
			showOutput -= 1

	def read(self, addr):
		self.reads.add(addr)
		value = super().read(addr)
		if addr == 0xD20A: # RANDOM
			value = self.random#random.randint(0,255)
			# generate not random, but predictable changing values
			self.random = (self.random + 1) & 0xFF
		global showOutput
		if self.addr_visible(addr) and showOutput == 0:
			print('### R %s => $%02x' % (self.addr_label(addr), value))
		return value

	def get_word(self, addr):
		return (self.read(addr+1) << 8) + self.read(addr)

	def addr_label(self, addr, size=4, readMode=True):
		addr &= 0xFFFF
		return formatAddress(addr,readMode=True,size=size)

def printCPUStatus(cpu):

	def dis_instruction(cpu,addr):
		class RegisterBase(object):
			def __init__(self, **kwargs):
				pass

			def __repr__(self):
				return self.name

			def __str__(self):
				return ''

			def __eq__(self, other):
				return isinstance(other, RegisterBase) and self.name == other.name

		class M_AC(RegisterBase):
			name = 'A'

		class M_XR(RegisterBase):
			name = 'X'

		class M_YR(RegisterBase):
			name = 'Y'

		class M_PC(RegisterBase):
			name = 'PC'

		class M_SP(RegisterBase):
			name = 'SP'

		class M_SR(RegisterBase):
			name = 'SR'

		class FlagBase(object):
			def __init__(self, **kwargs):
				pass

			def __repr__(self):
				return self.name

			def __str__(self):
				return ''

		class M_FC(FlagBase):
			name = 'C'

		class M_FD(FlagBase):
			name = 'D'

		class M_FI(FlagBase):
			name = 'I'

		class M_FV(FlagBase):
			name = 'V'

		class M_IMM(object):
			def __init__(self, **kwargs):
				self.immed = kwargs['immed']

			def __repr__(self):
				return str(self)

			def __str__(self):
				return '#$%02X' % self.immed

		class M_INDX(object):
			def __init__(self, **kwargs):
				self.offset = kwargs['offset']

			def __repr__(self):
				return str(self)

			def __str__(self):
				return '($%02X, X)' % self.offset

		class M_INDY(object):
			def __init__(self, **kwargs):
				self.offset = kwargs['offset']

			def __repr__(self):
				return str(self)

			def __str__(self):
				return '($%02X),Y' % self.offset

		class M_NONE(object):
			def __init__(self, **kwargs):
				pass

			def __eq__(self, other):
				return isinstance(other, M_NONE)

			def __repr__(self):
				return '_'

			def __str__(self):
				return ''

		class M_REL(object):
			def __init__(self, **kwargs):
				self.offset = kwargs['offset']

				if self.offset >= 128:
					self.offset -= 256

			def __repr__(self):
				return '.%+d' % self.offset

			def to_string(self, addr, cpu):
				addr += self.offset + 2
				return cpu.mmu.addr_label(addr)

		class AddrBase(object):
			def __init__(self, **kwargs):
				self.addr = kwargs['addr']

			def __repr__(self):
				fmt = '$%%0%dX' % self.size

				return fmt % self.addr

			def to_string(self, addr, cpu):
				return cpu.mmu.addr_label(self.addr, size=self.size)

		class M_ABS(AddrBase):
			size = 4

		class M_ABSX(AddrBase):
			size = 4

			def __repr__(self):
				s = super(M_ABSX, self).__repr__()

				return s + ',X'

			def to_string(self, addr, cpu):
				s = super(M_ABSX, self).to_string(addr, cpu)

				return s + ',X'

		class M_ABSY(AddrBase):
			size = 4

			def __repr__(self):
				s = super(M_ABSY, self).__repr__()

				return s + ',Y'

			def to_string(self, addr, cpu):
				s = super(M_ABSY, self).to_string(addr, cpu)

				return s + ',Y'

		class M_ADDR(AddrBase):
			size = 4

		class M_ZERO(AddrBase):
			size = 2

		class M_ZERX(AddrBase):
			size = 2

			def to_string(self, addr, cpu):
				return super(M_ZERX, self).to_string(addr, cpu) + ',X'

		class M_ZERY(AddrBase):
			size = 2

			def to_string(self, addr, cpu):
				return super(M_ZERY, self).to_string(addr, cpu) + ',Y'

		class M_AIND(AddrBase):
			"""JMP ($00A2)"""
			size = 4

			def to_string(self, addr, cpu):
				return '(%s)' % super(M_AIND, self).to_string(addr, cpu)

		TABLE = {
			0x00: Op(mnemonic="BRK", src=M_NONE, dst=M_PC, cycles=7),
			0x01: Op(mnemonic="ORA", src=M_INDX, dst=M_AC, cycles=6),
			0x04: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x05: Op(mnemonic="ORA", src=M_ZERO, dst=M_AC, cycles=3),
			0x06: Op(mnemonic="ASL", src=M_ZERO, dst=M_ZERO, cycles=5),
			0x08: Op(mnemonic="PHP", src=M_SR, dst=M_NONE, cycles=3),
			0x09: Op(mnemonic="ORA", src=M_IMM, dst=M_AC, cycles=2),
			0x0a: Op(mnemonic="ASL", src=M_AC, dst=M_AC, cycles=2),
			0x0c: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x0d: Op(mnemonic="ORA", src=M_ABS, dst=M_AC, cycles=4),
			0x0e: Op(mnemonic="ASL", src=M_ABS, dst=M_ABS, cycles=6),
			0x10: Op(mnemonic="BPL", src=M_REL, dst=M_NONE, cycles=2),
			0x11: Op(mnemonic="ORA", src=M_INDY, dst=M_AC, cycles=5),
			0x14: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x15: Op(mnemonic="ORA", src=M_ZERX, dst=M_AC, cycles=4),
			0x16: Op(mnemonic="ASL", src=M_ZERX, dst=M_ZERX, cycles=6),
			0x18: Op(mnemonic="CLC", src=M_NONE, dst=M_FC, cycles=2),
			0x19: Op(mnemonic="ORA", src=M_ABSY, dst=M_AC, cycles=4),
			0x1a: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x1c: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x1d: Op(mnemonic="ORA", src=M_ABSX, dst=M_AC, cycles=4),
			0x1e: Op(mnemonic="ASL", src=M_ABSX, dst=M_ABSX, cycles=7),
			0x20: Op(mnemonic="JSR", src=M_ADDR, dst=M_PC, cycles=6),
			0x21: Op(mnemonic="AND", src=M_INDX, dst=M_AC, cycles=6),
			0x24: Op(mnemonic="BIT", src=M_ZERO, dst=M_NONE, cycles=3),
			0x25: Op(mnemonic="AND", src=M_ZERO, dst=M_AC, cycles=3),
			0x26: Op(mnemonic="ROL", src=M_ZERO, dst=M_ZERO, cycles=5),
			0x28: Op(mnemonic="PLP", src=M_NONE, dst=M_SR, cycles=4),
			0x29: Op(mnemonic="AND", src=M_IMM, dst=M_AC, cycles=2),
			0x2a: Op(mnemonic="ROL", src=M_AC, dst=M_AC, cycles=2),
			0x2c: Op(mnemonic="BIT", src=M_ABS, dst=M_NONE, cycles=4),
			0x2d: Op(mnemonic="AND", src=M_ABS, dst=M_AC, cycles=4),
			0x2e: Op(mnemonic="ROL", src=M_ABS, dst=M_ABS, cycles=6),
			0x30: Op(mnemonic="BMI", src=M_REL, dst=M_NONE, cycles=2),
			0x31: Op(mnemonic="AND", src=M_INDY, dst=M_AC, cycles=5),
			0x34: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x35: Op(mnemonic="AND", src=M_ZERX, dst=M_AC, cycles=4),
			0x36: Op(mnemonic="ROL", src=M_ZERX, dst=M_ZERX, cycles=6),
			0x38: Op(mnemonic="SEC", src=M_NONE, dst=M_FC, cycles=2),
			0x39: Op(mnemonic="AND", src=M_ABSY, dst=M_AC, cycles=4),
			0x3a: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x3c: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x3d: Op(mnemonic="AND", src=M_ABSX, dst=M_AC, cycles=4),
			0x3e: Op(mnemonic="ROL", src=M_ABSX, dst=M_ABSX, cycles=7),
			0x40: Op(mnemonic="RTI", src=M_NONE, dst=M_PC, cycles=6),
			0x41: Op(mnemonic="EOR", src=M_INDX, dst=M_AC, cycles=6),
			0x44: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x45: Op(mnemonic="EOR", src=M_ZERO, dst=M_AC, cycles=3),
			0x46: Op(mnemonic="LSR", src=M_ZERO, dst=M_ZERO, cycles=5),
			0x48: Op(mnemonic="PHA", src=M_AC, dst=M_NONE, cycles=3),
			0x49: Op(mnemonic="EOR", src=M_IMM, dst=M_AC, cycles=2),
			0x4a: Op(mnemonic="LSR", src=M_AC, dst=M_AC, cycles=2),
			0x4c: Op(mnemonic="JMP", src=M_ADDR, dst=M_PC, cycles=3),
			0x4d: Op(mnemonic="EOR", src=M_ABS, dst=M_AC, cycles=4),
			0x4e: Op(mnemonic="LSR", src=M_ABS, dst=M_ABS, cycles=6),
			0x4f: Op(mnemonic="SRE", src=M_ABS, dst=M_AC, cycles=6),
			0x50: Op(mnemonic="BVC", src=M_REL, dst=M_NONE, cycles=2),
			0x51: Op(mnemonic="EOR", src=M_INDY, dst=M_AC, cycles=5),
			0x54: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x55: Op(mnemonic="EOR", src=M_ZERX, dst=M_AC, cycles=4),
			0x56: Op(mnemonic="LSR", src=M_ZERX, dst=M_ZERX, cycles=6),
			0x58: Op(mnemonic="CLI", src=M_NONE, dst=M_FI, cycles=2),
			0x59: Op(mnemonic="EOR", src=M_ABSY, dst=M_AC, cycles=4),
			0x5a: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x5c: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x5d: Op(mnemonic="EOR", src=M_ABSX, dst=M_AC, cycles=4),
			0x5e: Op(mnemonic="LSR", src=M_ABSX, dst=M_ABSX, cycles=7),
			0x60: Op(mnemonic="RTS", src=M_NONE, dst=M_PC, cycles=6),
			0x61: Op(mnemonic="ADC", src=M_INDX, dst=M_AC, cycles=6),
			0x64: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x65: Op(mnemonic="ADC", src=M_ZERO, dst=M_AC, cycles=3),
			0x66: Op(mnemonic="ROR", src=M_ZERO, dst=M_ZERO, cycles=5),
			0x68: Op(mnemonic="PLA", src=M_NONE, dst=M_AC, cycles=4),
			0x69: Op(mnemonic="ADC", src=M_IMM, dst=M_AC, cycles=2),
			0x6a: Op(mnemonic="ROR", src=M_AC, dst=M_AC, cycles=2),
			0x6c: Op(mnemonic="JMP", src=M_AIND, dst=M_PC, cycles=5),
			0x6d: Op(mnemonic="ADC", src=M_ABS, dst=M_AC, cycles=4),
			0x6e: Op(mnemonic="ROR", src=M_ABS, dst=M_ABS, cycles=6),
			0x70: Op(mnemonic="BVS", src=M_REL, dst=M_NONE, cycles=2),
			0x71: Op(mnemonic="ADC", src=M_INDY, dst=M_AC, cycles=5),
			0x74: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x75: Op(mnemonic="ADC", src=M_ZERX, dst=M_AC, cycles=4),
			0x76: Op(mnemonic="ROR", src=M_ZERX, dst=M_ZERX, cycles=6),
			0x78: Op(mnemonic="SEI", src=M_NONE, dst=M_FI, cycles=2),
			0x79: Op(mnemonic="ADC", src=M_ABSY, dst=M_AC, cycles=4),
			0x7a: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x7c: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x7d: Op(mnemonic="ADC", src=M_ABSX, dst=M_AC, cycles=4),
			0x7e: Op(mnemonic="ROR", src=M_ABSX, dst=M_ABSX, cycles=7),
			0x80: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x81: Op(mnemonic="STA", src=M_AC, dst=M_INDX, cycles=6),
			0x82: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x84: Op(mnemonic="STY", src=M_YR, dst=M_ZERO, cycles=3),
			0x85: Op(mnemonic="STA", src=M_AC, dst=M_ZERO, cycles=3),
			0x86: Op(mnemonic="STX", src=M_XR, dst=M_ZERO, cycles=3),
			0x88: Op(mnemonic="DEY", src=M_YR, dst=M_YR, cycles=2),
			0x89: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0x8a: Op(mnemonic="TXA", src=M_XR, dst=M_AC, cycles=2),
			0x8c: Op(mnemonic="STY", src=M_YR, dst=M_ABS, cycles=4),
			0x8d: Op(mnemonic="STA", src=M_AC, dst=M_ABS, cycles=4),
			0x8e: Op(mnemonic="STX", src=M_XR, dst=M_ABS, cycles=4),
			0x90: Op(mnemonic="BCC", src=M_REL, dst=M_NONE, cycles=2),
			0x91: Op(mnemonic="STA", src=M_AC, dst=M_INDY, cycles=6),
			0x94: Op(mnemonic="STY", src=M_YR, dst=M_ZERX, cycles=4),
			0x95: Op(mnemonic="STA", src=M_AC, dst=M_ZERX, cycles=4),
			0x96: Op(mnemonic="STX", src=M_XR, dst=M_ZERY, cycles=4),
			0x98: Op(mnemonic="TYA", src=M_YR, dst=M_AC, cycles=2),
			0x99: Op(mnemonic="STA", src=M_AC, dst=M_ABSY, cycles=5),
			0x9a: Op(mnemonic="TXS", src=M_XR, dst=M_SP, cycles=2),
			0x9d: Op(mnemonic="STA", src=M_AC, dst=M_ABSX, cycles=5),
			0xa0: Op(mnemonic="LDY", src=M_IMM, dst=M_YR, cycles=2),
			0xa1: Op(mnemonic="LDA", src=M_INDX, dst=M_AC, cycles=6),
			0xa2: Op(mnemonic="LDX", src=M_IMM, dst=M_XR, cycles=2),
			0xa4: Op(mnemonic="LDY", src=M_ZERO, dst=M_YR, cycles=3),
			0xa5: Op(mnemonic="LDA", src=M_ZERO, dst=M_AC, cycles=3),
			0xa6: Op(mnemonic="LDX", src=M_ZERO, dst=M_XR, cycles=3),
			0xa8: Op(mnemonic="TAY", src=M_AC, dst=M_YR, cycles=2),
			0xa9: Op(mnemonic="LDA", src=M_IMM, dst=M_AC, cycles=2),
			0xaa: Op(mnemonic="TAX", src=M_AC, dst=M_XR, cycles=2),
			0xac: Op(mnemonic="LDY", src=M_ABS, dst=M_YR, cycles=4),
			0xad: Op(mnemonic="LDA", src=M_ABS, dst=M_AC, cycles=4),
			0xae: Op(mnemonic="LDX", src=M_ABS, dst=M_XR, cycles=4),
			0xb0: Op(mnemonic="BCS", src=M_REL, dst=M_NONE, cycles=2),
			0xb1: Op(mnemonic="LDA", src=M_INDY, dst=M_AC, cycles=5),
			0xb4: Op(mnemonic="LDY", src=M_ZERX, dst=M_YR, cycles=4),
			0xb5: Op(mnemonic="LDA", src=M_ZERX, dst=M_AC, cycles=4),
			0xb6: Op(mnemonic="LDX", src=M_ZERY, dst=M_XR, cycles=4),
			0xb8: Op(mnemonic="CLV", src=M_NONE, dst=M_FV, cycles=2),
			0xb9: Op(mnemonic="LDA", src=M_ABSY, dst=M_AC, cycles=4),
			0xba: Op(mnemonic="TSX", src=M_SP, dst=M_XR, cycles=2),
			0xbc: Op(mnemonic="LDY", src=M_ABSX, dst=M_YR, cycles=4),
			0xbd: Op(mnemonic="LDA", src=M_ABSX, dst=M_AC, cycles=4),
			0xbe: Op(mnemonic="LDX", src=M_ABSY, dst=M_XR, cycles=4),
			0xc0: Op(mnemonic="CPY", src=M_IMM, dst=M_NONE, cycles=2),
			0xc1: Op(mnemonic="CMP", src=M_INDX, dst=M_NONE, cycles=6),
			0xc2: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xc4: Op(mnemonic="CPY", src=M_ZERO, dst=M_NONE, cycles=3),
			0xc5: Op(mnemonic="CMP", src=M_ZERO, dst=M_NONE, cycles=3),
			0xc6: Op(mnemonic="DEC", src=M_ZERO, dst=M_ZERO, cycles=5),
			0xc8: Op(mnemonic="INY", src=M_YR, dst=M_YR, cycles=2),
			0xc9: Op(mnemonic="CMP", src=M_IMM, dst=M_NONE, cycles=2),
			0xca: Op(mnemonic="DEX", src=M_XR, dst=M_XR, cycles=2),
			0xcc: Op(mnemonic="CPY", src=M_ABS, dst=M_NONE, cycles=4),
			0xcd: Op(mnemonic="CMP", src=M_ABS, dst=M_NONE, cycles=4),
			0xce: Op(mnemonic="DEC", src=M_ABS, dst=M_ABS, cycles=6),
			0xd0: Op(mnemonic="BNE", src=M_REL, dst=M_NONE, cycles=2),
			0xd1: Op(mnemonic="CMP", src=M_INDY, dst=M_NONE, cycles=5),
			0xd4: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xd5: Op(mnemonic="CMP", src=M_ZERX, dst=M_NONE, cycles=4),
			0xd6: Op(mnemonic="DEC", src=M_ZERX, dst=M_ZERX, cycles=6),
			0xd8: Op(mnemonic="CLD", src=M_NONE, dst=M_FD, cycles=2),
			0xd9: Op(mnemonic="CMP", src=M_ABSY, dst=M_NONE, cycles=4),
			0xda: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xdc: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xdd: Op(mnemonic="CMP", src=M_ABSX, dst=M_NONE, cycles=4),
			0xde: Op(mnemonic="DEC", src=M_ABSX, dst=M_ABSX, cycles=7),
			0xe0: Op(mnemonic="CPX", src=M_IMM, dst=M_NONE, cycles=2),
			0xe1: Op(mnemonic="SBC", src=M_INDX, dst=M_AC, cycles=6),
			0xe2: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xe4: Op(mnemonic="CPX", src=M_ZERO, dst=M_NONE, cycles=3),
			0xe5: Op(mnemonic="SBC", src=M_ZERO, dst=M_AC, cycles=3),
			0xe6: Op(mnemonic="INC", src=M_ZERO, dst=M_ZERO, cycles=5),
			0xe8: Op(mnemonic="INX", src=M_XR, dst=M_XR, cycles=2),
			0xe9: Op(mnemonic="SBC", src=M_IMM, dst=M_AC, cycles=2),
			0xea: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xec: Op(mnemonic="CPX", src=M_ABS, dst=M_NONE, cycles=4),
			0xed: Op(mnemonic="SBC", src=M_ABS, dst=M_AC, cycles=4),
			0xee: Op(mnemonic="INC", src=M_ABS, dst=M_ABS, cycles=6),
			0xf0: Op(mnemonic="BEQ", src=M_REL, dst=M_NONE, cycles=2),
			0xf1: Op(mnemonic="SBC", src=M_INDY, dst=M_AC, cycles=5),
			0xf4: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xf5: Op(mnemonic="SBC", src=M_ZERX, dst=M_AC, cycles=4),
			0xf6: Op(mnemonic="INC", src=M_ZERX, dst=M_ZERX, cycles=6),
			0xf8: Op(mnemonic="SED", src=M_NONE, dst=M_FD, cycles=2),
			0xf9: Op(mnemonic="SBC", src=M_ABSY, dst=M_AC, cycles=4),
			0xfa: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xfc: Op(mnemonic="NOP", src=M_NONE, dst=M_NONE, cycles=2),
			0xfd: Op(mnemonic="SBC", src=M_ABSX, dst=M_AC, cycles=4),
			0xfe: Op(mnemonic="INC", src=M_ABSX, dst=M_ABSX, cycles=7),
		}

		bb = cpu.mmu.read(addr)
		opcode = TABLE[bb]

		kwargs = {}

		if addr_mode_in(opcode, M_ADDR, M_ABS, M_ABSX, M_ABSY, M_AIND):
			kwargs['addr'] = cpu.mmu.read(addr+1) | (cpu.mmu.read(addr+2) << 8)
		elif addr_mode_in(opcode, M_IMM):
			kwargs['immed'] = cpu.mmu.read(addr+1)
		elif addr_mode_in(opcode, M_INDX, M_INDY, M_REL):
			kwargs['offset'] = cpu.mmu.read(addr+1)
		elif addr_mode_in(opcode, M_ZERO, M_ZERX, M_ZERY):
			kwargs['addr'] = cpu.mmu.read(addr+1)

		Instruction = namedtuple('Instruction', 'opcode src dst')
		return Instruction(opcode=opcode, src=opcode.src(**kwargs), dst=opcode.dst(**kwargs))

	addr = cpu.r.pc
	flags = ''
	for f in ('N','V','B','D','I','Z','C'):
		if cpu.r.getFlag(f):
			flags += f
		else:
			flags += f.lower()

	print('A:$%02x X:$%02x Y:$%02x F:%s SP:$01%02x PC:$%04x: ' % (cpu.r.a, cpu.r.x, cpu.r.y, flags, cpu.r.s, cpu.r.pc), end='')

	instr = dis_instruction(cpu,addr)
	disStr = (instr.opcode.mnemonic + ' ' * 7)[:7]
	try:
		instr.src.to_string
	except AttributeError:
		src = str(instr.src)
	else:
		src = instr.src.to_string(addr, cpu)

	if src:
		disStr += src
	else:
		if instr.opcode.mnemonic in 'ADC AND ASL BIT CMP CPX CPY DEC EOR INC JMP LDA LDX LDY LSR ORA ROL ROR SBC STA STX STY':
			stringer = repr
		else:
			stringer = str

		try:
			instr.dst.to_string
		except AttributeError:
			dst = stringer(instr.dst)
			if dst == 'A':
				dst = ''
		else:
			dst = instr.dst.to_string(addr, cpu)

		disStr += dst
	print('%s' % disStr)

def emulateROMfunction(cpu):
	global showOutput
	global showROMAccess
	global sectorIndex
	global memoryWithSectors

	romCalls = {
		0xE450:"DISKIV",
		0xE453:"DSKINV",
		0xE456:"CIOV",
		0xE459:"SIOV",
		0xE45C:"SETVBV",
		0xE45F:"SYSVBV",
		0xE462:"XITVBV",
		0xE465:"SIOINV",
		0xE468:"SENDEV",
		0xE46B:"INTINV",
		0xE46E:"CIOINV",
		0xE471:"BLKBDV",
		0xE474:"WARMSV",
		0xE477:"COLDSV",
		0xE47D:"RBLOKV",
		0xE480:"DSOPIV",
		0xE6F3:"PIRQ",
	}
	if cpu.r.pc in romCalls:
		romCall = romCalls[cpu.r.pc]
	else:
		romCall = '$%04X' % cpu.r.pc

	showOutput += 1
	while True:
		if showROMAccess:
			print('$$$ ROM CALL ' + romCall)
		if romCall == 'SIOINV':
			cpu.RTS(0)
		elif romCall == 'SIOV' or romCall == 'DSKINV':
			device = cpu.mmu.read(0x300)
			unit = cpu.mmu.read(0x301)
			command = cpu.mmu.read(0x302)
			stats = cpu.mmu.read(0x303)
			addr = cpu.mmu.get_word(0x304)
			timlo = cpu.mmu.read(0x306)
			byte = cpu.mmu.get_word(0x308)
			sector = cpu.mmu.get_word(0x30A)
			if showROMAccess:
				#print('$$$ CALL SIOV DEVICE:$%02x UNIT:%d CMD:%c STATUS:%02x ADDR:$%04x TIMLO:%d BYTES:$%04x SECTOR:%3d' % (device,unit,chr(command),stats,addr,timlo,byte,sector))
				print('$$$ READ SECTOR ADDR:$%04x BYTES:$%04x SECTOR:%3d' % (addr,SECTOR_SIZE,sector,))
			if addr not in memoryWithSectors:
				memoryWithSectors[addr] = set()
			memoryWithSectors[addr].add(sector)
			if sector == 37:
				sectorIndex = 0
			sectorData,sectorStatus = readSector(sector, sectorIndex)
			sectorIndex += 1
			for r in range(0,SECTOR_SIZE):
				cpu.mmu.write(addr + r, sectorData[r])
			if sectorStatus == 0:
				sectorStatus = 1 # OK status
			cpu.mmu.write(0x0303, sectorStatus) # DCB.DSTATS
			cpu.r.setFlag('N', sectorStatus != 0)
			cpu.mmu.write(0x14, 7) # set RTCLOK to satisfy the timing based copy protecting (7-9 are valid for the older protection, 6- for the later ones)
			cpu.RTS(0)
		elif romCall == 'CIOV':
			CIO_CMDS = {
					3:"OPEN",
					5:"GET_RECORD",
					7:"GET_CHARACTERS",
					9:"PUT_RECORD",
					11:"PUT_CHARACTERS",
					12:"CLOSE",
					13:"GET_STATUS",
				}
			cmd = cpu.mmu.read(0x352)
			adr = cpu.mmu.get_word(0x354)
			s = ''
			while True:
				ch = cpu.mmu.read(adr) & 0x7F
				adr += 1
				if ch < 32:
					s += '\\'
					ch += 0x60
				s += chr(ch)
				if cpu.mmu.read(adr) & 0x80:
					break
			if showROMAccess:
				cmdS = 'CMD_0x%02x' % cmd
				if cmd in CIO_CMDS:
					cmdS = CIO_CMDS[cmd]
				print('$$$ CALL CIOV %04x %s [%s]' % (adr, cmdS, s))
			elif cmd in CIO_CMDS and CIO_CMDS[cmd] == 'PUT_RECORD':
				print('"%s"' % (s))
			cpu.RTS(0)
		elif romCall == 'COLDSV': # boot again
			if showROMAccess:
				print('#' * 80)
				print('# REBOOT')
				print('#' * 80)
			readBootFile(cpu)
		elif romCall == 'SETVBV':
			cpu.RTS(0)
		elif romCall == 'PIRQ':
			cpu.RTS(0)
		else:
			print("########### UNIMPLEMENTED %s" % romCall)
			sys.exit(0)
		break
	showOutput -= 1

sectorIndex = 0
memoryWithSectors = {}
def emulateAtari(filename,showOutputFlag=False,showROMAccessFlag=False):
	global atxDiskImage
	global showOutput
	global showROMAccess

	showROMAccess = showROMAccessFlag
	atxDiskImage = bytearray(open(filename,'rb').read())

	# define your blocks of memory.	 Each tuple is
	# (start_address, length, readOnly=True, value=None, valueOffset=0)
	mmu = DebugMMU([
			(0x0000, 0x0400, False, open("./Atari/atari_memdump_0000.bin", "rb")),
			(0x0400, 0xA000-0x0400, False, 0x00),
			(0xA000, 0x2000, False, 0x00), # RAM
#			(0xA000, 0x2000, True,  0x00), # ROM Cartridge
#			(0xC000, 0x1000, False, 0xff), # not mapped
			(0xD000, 0x0800, False, 0x00), # IO area
			(0xD800, 0x2800, True,  open("./Atari/ATARIOSB.ROM", "rb")), # ROM
	])

	cpu = CPU(mmu)
	if showOutputFlag:
		showOutput = 0
	else:
		showOutput = 1
	random.seed()
	rtclokCounter = 0
	readBootFile(cpu)
	timeout = datetime.now() + timedelta(seconds=60)
	while True:
		if cpu.r.pc == 0x0c03:
			showOutput -= 1
			f = open('0x0C00.bin','wb')
			d = bytearray()
			for adr in range(0x0C00,0x6000):
				d.append(cpu.mmu.read(adr))
			f.write(d)
			f.close()
			break

		if showOutput == 0:
			printCPUStatus(cpu)
			
		if True:
			if timeout < datetime.now():
				print('@@@ TIMEOUT')
				break

		# cheaply simulate RTCLOK to pass the timer delays
		rtclokCounter += 1
		if rtclokCounter >= 256:
			rtclokCounter = 0
			showOutput += 1
			mmu.write(0x14, cpu.mmu.read(0x14) + 1) # technically this should happen at 50Hz
			# Do not increment the higher bytes they are too rare:
			#mmu.write(0x13, cpu.mmu.read(0x13) + 1) # This happens every ~5 seconds
			#mmu.write(0x12, cpu.mmu.read(0x12) + 1) # This happens every ~22 minutes
			showOutput -= 1

		if cpu.r.pc >= 0xE000: # inside the ROM (The floating point math ROM part is executed normally)
			emulateROMfunction(cpu)

		cpu.step()

	# display all memory reads and writes
	if False:
		def printAddrRanges(addrSet):
			lastAddr = None
			for addr in sorted(addrSet):
				if lastAddr == None:
					print('%s' % cpu.mmu.addr_label(addr),end='')
					lastAddr = addr
				elif addr == lastAddr + 1:
					lastAddr = addr
				else:
					print('-%s' % cpu.mmu.addr_label(lastAddr))
					print('%s' % cpu.mmu.addr_label(addr),end='')
					lastAddr = addr
			print()

		print('READ:')
		printAddrRanges(mmu.reads)
		print('WRITE:')
		printAddrRanges(mmu.writes)

emulateAtari('Zorro.atx', showOutputFlag=True, showROMAccessFlag=True)
