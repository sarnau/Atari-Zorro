#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import struct

def loadATX(atxFilename,selectedTrack=None):
	data = bytearray(open(atxFilename,'rb').read())
	SECTOR_SIZE = 128

	offset = 0

	# read file header
	header,version_number,fh_size = struct.unpack('<4sh22xl16x', data[offset+0:offset+0x30])
	if header != b'AT8X':
		print('File Header AT8X not found')
		return False
	if fh_size != 48:
		print('File Header Size != 48 bytes')
		return False
	if version_number != 1:
		print('File Header Version != 1')
		return False
	offset += fh_size

	while offset < len(data):
		# read track header
		th_record_size,record_type,track_number,sector_count,th_size = struct.unpack('<lh2xB1xh8xl8x', data[offset+0:offset+0x20])
		if th_size != 32:
			print('Track Header Size != 32 bytes')
			return False
		if record_type != 0:
			print('Track Header record type != data track')
			return False
		if not selectedTrack or (selectedTrack and selectedTrack == track_number):
			track = data[offset+0:offset+th_record_size]
			sector_lookup = {}

			# read sector list header
			record_size,record_type = struct.unpack('<lB3x', track[th_size+0:th_size+8])
			if record_type != 1:
				print('Sector List Header record type != sector list')
				return False

			# read sector list
			for sectorHeaderOffset in range(th_size+8,th_size+record_size,8):
				sector_number,sector_status,sector_position,start_data = struct.unpack('<BBhl', track[sectorHeaderOffset+0:sectorHeaderOffset+8])

				status = []
				if sector_status == 0x00:
					status.append('OK')
				else:
					if sector_status & 0x80: # NOT READY - not valid/useful in the file
						status.append('Reserved:80')
					if sector_status & 0x40:
						status.append('EXTND DATA')
					if sector_status & 0x20:
						status.append('deleted DAM')
					if sector_status & 0x10:
						status.append('RECORD NOT FOUND')
					if sector_status & 0x08:
						status.append('CRC ERROR')
					if sector_status & 0x04:
						status.append('LOST DATA')
					if sector_status & 0x02: # DRQ - not valid/useful in the file
						status.append('Reserved:02')
					if sector_status & 0x01: # BUSY - not valid/useful in the file
						status.append('Reserved:01')
				sstr = ','.join(status)

				# read sector data as well
				sno = track_number * 18 + sector_number
				spos = sector_position / 26042
				print('Sector @ $%04x #%3d, Track #%2d Sector #%2d / %s / %7.3f%%' % (start_data, sno, track_number, sector_number,sstr,spos),end='')

				if True:
					sdata = track[start_data:start_data+SECTOR_SIZE]
					lc = sdata[0]
					for i in range(1,SECTOR_SIZE):
						if lc != sdata[i]:
							lc = -1
							break
					if lc >= 0:
						print(' / $%02x * %d' % (lc, SECTOR_SIZE))
					else:
						foundDup = False
						for sd_start in sector_lookup:
							if sector_lookup[sd_start] == sdata:
								print(' / sector copy @ $%04x' % (sd_start))
								foundDup = True
								break
						sector_lookup[start_data] = sdata
						if not foundDup:
							print()
							for l in range(0,SECTOR_SIZE,16):
								print('%02x: ' % l,end='')
								for p in range(0,16):
									print('%02x ' % sdata[l + p],end='')
								print(' ',end='')
								for p in range(0,16):
									c = sdata[l + p]
									if c < 0x20 or c >= 0x7F:
										c = ord('.')
									print('%c' % c,end='')
								print()
				else:
					print()

			print('=' * 40)
		# proceed to the next track
		offset += th_record_size

	return True

loadATX('Zorro.atx')
