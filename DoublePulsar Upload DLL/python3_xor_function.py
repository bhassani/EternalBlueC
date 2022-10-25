#Found on: https://github.com/9emin1/charlotte/blob/main/charlotte.py
#can be useful for Python3 XOR for DoublePulsar payload

def xor(data, key):
    
    #replaced with our DoublePulsar key in parameter
    #key = get_random_string()
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x) # handle data being bytes not string
        output_str += chr(o(current) ^ ord(current_key))

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext #, key
  
  '''
Old python function

def xor_data(org_data , key):
	newdata = ""
	for i in range(len(org_data)):
		newdata += chr(ord(org_data[i]) ^ ord(key[i%len(key)]))
	return newdata
  '''
