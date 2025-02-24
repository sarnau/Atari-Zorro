#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct,os,sys

# Return an ASCII hex dump
def dump(src, length=16):
    result = []
    digits = 2
    for i in range(0, len(src), length):
       s = src[i:i+length]
       hexa = ' '.join(["%02X" % (x) for x in s])
       text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.'  for x in s])
       result.append("%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return '\n'.join(result)

def parseCAS(thePath):
	print("Parsing %s" % (thePath))
	f = open(thePath, "rb") # notice the b for binary mode
	buffer = f.read()
	f.close()
#	print(dump(buffer))

	fileOffset = 0
	fileLength = len(buffer)
	file_index = 0
	baseaddr = None
	data = bytes()
	while fileOffset < fileLength:

		chunk_type = buffer[fileOffset:fileOffset+4].decode('ascii')
		chunk_length,param = struct.unpack_from("<HH", buffer[fileOffset+4:fileOffset+8], 0)
		chunk_data = buffer[fileOffset+8:fileOffset+8+chunk_length]
		#print(dump(chunk_data))
		if chunk_type == 'baud':
			#print('BAUD: %d baud' % param)
			pass
		elif chunk_type == 'data':
			print('DATA: LEN=$%04x PARAM=$%04x' % (chunk_length,param))
			#print(dump(chunk_data))
			csum = 0x00
			if chunk_length > 0:
				for i in range(0,chunk_length-1):
					csum += chunk_data[i]
					if csum >= 0x100:
						csum = (csum & 0xFF) + (csum >> 8)
			if len(chunk_data) >= 4 and chunk_data[0] == 0x55 and chunk_data[1] == 0x55:
				if chunk_data[2] == 0xFC or chunk_data[2] == 0xFD or chunk_data[2] == 0xFE or chunk_data[2] == 0xFA:
					if csum != chunk_data[-1]:
						print('CHECKSUM $%02x $%02x' % (csum,chunk_data[-1]))
					else:
						if chunk_data[2] == 0xFE:
							f = open(thePath+'_0.xex', "wb")
							f.write(data)
							f.close()
							data = bytes()
							file_index += 1
						else:
							if file_index == 0:
								data += chunk_data[3:-1]
							else:
								data = chunk_data[3:-1] + data
				else:
					print('RECORD $%02x $%s' % (chunk_data[2],dump(chunk_data)))
			else:
				print('MARKER $%s' % (dump(chunk_data)))
				f = open(thePath+'_1_0600.bin', "wb")
				f.write(data)
				f.close()
				print(dump(data))
				
				def writeChunk(baseaddr,mem):
					endAdr = baseaddr + len(mem) - 1
					f.write(bytearray([0xFF,0xFF,baseaddr & 0xFF,baseaddr >> 8,endAdr & 0xFF,endAdr >> 8]))
					f.write(mem)
				
				f.close()


		elif chunk_type == 'FUJI' or chunk_type == 'fsk ':
			pass
		else:
			print('%s $%04x $%04x' % (chunk_type,chunk_length,param))
		fileOffset += 8 + chunk_length

parseCAS("Zorro.cas")
