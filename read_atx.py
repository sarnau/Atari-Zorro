#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct


def parseATX(atxFilename):
	data = bytearray(open(atxFilename,'rb').read())

	CREATOR = {
		0x01:'TX_CR_FX7',
		0x02:'ATX_CR_FX8',
		0x03:'ATX_CR_ATR',
		0x10:'ATX_CR_WH2PC',
		0x74:'a8diskutil',
	}
	DENSITY = ['SINGLE','MEDIUM','DOUBLE']

	fh_header,fh_version,fh_min_version,fh_creator,fh_creator_version,fh_flags,fh_image_type,fh_density,fh_start,fh_end = struct.unpack('<4shhhhLhB9xll12x', data[:0x30])
	fh_header = fh_header.decode('ascii')
#	print('$%08x : FILE HEADER %s VERSION:%d CREATOR:%s,VERSION:%d FLAGS:$%08x IMAGE_TYPE:$%04x DENSITY:%s / $%08x-$%08x' % (0, fh_header,fh_version,CREATOR[fh_creator],fh_creator_version,fh_flags,fh_image_type,DENSITY[fh_density],fh_start,fh_end))
	if fh_header != 'AT8X':
		print('File Header AT8X not found')
		return False
	if fh_version != 1:
		print('File Header Version != 1')
		return False

	
	if fh_density == 0: # single density (FM encoding)
		SECTOR_SIZE = 128
		SECTOR_COUNT = 18
	elif fh_density == 1: # medium density (MFM encoding)
		SECTOR_SIZE = 128
		SECTOR_COUNT = 26
	elif fh_density == 2: # double density (MFM encoding)
		SECTOR_SIZE = 256
		SECTOR_COUNT = 18
	else:
		print('Unknown density #%d' % fh_density)
		return False

	atx_offset = fh_start
	while atx_offset < fh_end:
		# data record header
		dr_length,dr_type = struct.unpack('<lh2x', data[atx_offset:atx_offset+8])
#		print('$%08x : DATA RECORD HEADER $%08x / $%04x' % (atx_offset, dr_length,dr_type))
		if dr_type == 0x0100: # host data record
			pass # ignored
		elif dr_type == 0x0000: # track data record
			th_track_number,th_sector_count,th_rate,th_flags,th_header_size = struct.unpack('<B1xhh2xll8x', data[atx_offset+8:atx_offset+8+24])
#			print('$%08x : TRACK DATA RECORD TRACK:%2d SECTOR_COUNT:%2d RATE:%d FLAGS:$%08x HEADER_SIZE:$%08x' % (atx_offset+8, th_track_number,th_sector_count,th_rate,th_flags,th_header_size))

			sector_lookup = {} # find duplicate sectors
			
			coffset = atx_offset+th_header_size
			while coffset < atx_offset+dr_length:
				chunk_length,chunk_type,chunk_sector_index,chunk_header_data = struct.unpack('<lBBH', data[coffset:coffset+8])
				if chunk_length == 0: # chunk list terminator
					break
				chunk_data = data[coffset+8:coffset+chunk_length]
#				print('$%08x : CHUNK RECORD LENGTH:$%08x TYPE:$%02x SECTOR_INDEX:%2d HEADER_DATA:$%04x' % (coffset, chunk_length,chunk_type,chunk_sector_index,chunk_header_data))
				if chunk_type == 0x00: # Sector data
					sector_data = chunk_data # content of the sector data itself
				elif chunk_type == 0x01: # Sector list
					for soffset in range(coffset+8, coffset+chunk_length,8):
						sl_sector_number,sl_sector_status,sl_sector_position,sl_start_data = struct.unpack('<BBHL', data[soffset:soffset+8])

						status = []
						if sl_sector_status == 0x00:
							status.append('OK')
						else:
							if sl_sector_status & 0x80: # NOT READY - not valid/useful in the file
								status.append('Reserved:80')
							if sl_sector_status & 0x40:
								status.append('EXTENDED DATA')
							if sl_sector_status & 0x20:
								status.append('deleted DAM')
							if sl_sector_status & 0x10:
								status.append('RECORD NOT FOUND')
							if sl_sector_status & 0x08:
								status.append('CRC ERROR')
							if sl_sector_status & 0x04:
								status.append('LOST DATA')
							if sl_sector_status & 0x02: # DRQ - not valid/useful in the file
								status.append('Reserved:02')
							if sl_sector_status & 0x01: # BUSY - not valid/useful in the file
								status.append('Reserved:01')
						status_str = ','.join(status)

#						print('$%08x : SECTOR HEADER NUMBER:%2d STATUS:%s POSITION:$%04x START:$%08x' % (soffset, sl_sector_number,status_str,sl_sector_position,sl_start_data))

						# read sector data as well
						sno = th_track_number * SECTOR_COUNT + sl_sector_number
						spos = sl_sector_position / 26042
						print('SECTOR @ $%08x #%3d, Track #%2d Sector #%2d / %s / %7.3f%%' % (sl_start_data, sno, th_track_number, sl_sector_number,status_str,spos),end='')

						if (sl_sector_status & 0x04) == 0x00: # data actually present?
							sl_data = data[atx_offset+sl_start_data:atx_offset+sl_start_data+SECTOR_SIZE]
							lc = sl_data[0]
							for i in range(1,SECTOR_SIZE):
								if lc != sl_data[i]:
									lc = -1
									break
							if lc >= 0:
								print(' / $%02x * %d' % (lc, SECTOR_SIZE))
							else:
								foundDup = False
								for sd_start in sector_lookup:
									if sector_lookup[sd_start] == sl_data:
										print(' / sector copy @ $%04x' % (sd_start))
										foundDup = True
										break
								sector_lookup[sl_start_data] = sl_data
								if not foundDup:
									print()
									if False:
										for l in range(0,SECTOR_SIZE,16):
											print('%02x: ' % l,end='')
											for p in range(0,16):
												print('%02x ' % sl_data[l + p],end='')
											print(' ',end='')
											for p in range(0,16):
												c = sl_data[l + p]
												if c < 0x20 or c >= 0x7F:
													c = ord('.')
												print('%c' % c,end='')
											print()
						else:
							print()

					pass
				elif chunk_type == 0x10: # Weak sector data
					print('WEAK_SECTOR #%2d STARTING_AT:$%02x' % (chunk_sector_index,chunk_header_data))
				elif chunk_type == 0x11: # Extended sector data
					print('LONG_SECTOR #%2d SECTOR_SIZE:%d' % (chunk_sector_index,128 << chunk_header_data))
				else:
					print('### UNKNOWN CHUNK TYPE $%02x' % chunk_type)
					pass
				coffset += chunk_length
				
		print('=' * 40)
		# proceed to the next track
		atx_offset += dr_length

	return True


parseATX('Zorro.atx')
