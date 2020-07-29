/*
This TRANS2 packet was found in the UploadDLL-x64 python script.

This is being dissected to see what it does
*/

SMB_LENGTH			    //Length
xFF\x53\x4D\x42			//SMB1
x32				        // SMB Command: Trans2
x00\x00\x00\x00			//NT STATUS
x18				        //Flags1
x07\xC0				  //Flags2
x00\x00			 	  //PID hi
x00\x00\x00\x00\x00\x00\x00\x00 //signature
x00\x00			 	  //Reserved
x00\x08				  //TreeID
xFF\xFE				  //ProcessID
x00\x08				  //UserID
x42\x00				  //MultipleID

x0F				        //Word count	
x0C\x00				    //TotalParamCount
TOTAL_DATA_COUNT  //TOTAL_DATA_COUNT ( x00\x00 )
x01\x00				    //Max Param Count
x00\x00				    //Max Data Count
x00				        //Max Setup Count
x00				        //Reserved
x00\x00 			    //Flags
xF0\xCC\x0C\x00		//Timeout
x00\x00 	 		    //Reserved
x0C\x00           //Parameter Count
x42\x00          //Parameter Offset
TOTAL_DATA_COUNT  //DATA COUNT -> Appears to be same value as TOTAL_DATA_COUNT near the top( x00\x00 )
x4E\x00          //Data Offset
x01              //Setup Count
x00               //Reserved
x0E\x00          //Subcommand: SESSION_SETUP
byteCount         //byteCount ( x00\x00 )
x00               //NO IDEA
