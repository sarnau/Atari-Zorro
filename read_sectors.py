#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import struct
import os

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

	return None,SECTOR_SIZE

filename = 'Zorro.atx'
atxDiskImage = bytearray(open(filename,'rb').read())

lastTrackNo = None
for sectorNo in range(1,720):
	data,status = atx_readSector(atxDiskImage, sectorNo, 0)
	trackNo = int((sectorNo-1)/18)
	if trackNo != lastTrackNo:
		print('=' * 71)
		lastTrackNo = trackNo
	if status != 0x00:
		print("Track #%2d Sector #%3d STATUS=$%02x" % (trackNo,sectorNo,status),end='')
	else:
		print("Track #%2d Sector #%3d" % (trackNo,sectorNo),end='')
	if data:
		lc = data[0]
		for i in range(1,SECTOR_SIZE):
			if lc != data[i]:
				lc = -1
				break
		if lc >= 0:
			print(' / $%02x * %d' % (lc, SECTOR_SIZE))
		else:
			print()
			dump_memory_block(data)
	else:
		print()
