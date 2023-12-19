# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
# importing "array" for array creations
import array as arr


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    DisplayFormat = ChoicesSetting(
        label='Display Format',
        choices=('Dec', 'Hex')
    )

    DisplayLevel = ChoicesSetting(
        label='Outputs',
        choices=('Data', 'All')
    )

    HCIChannel = NumberSetting(label='HCI Channel', min_value=-1, max_value=3)


    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'USB': {'format': '{{data.pid}}({{data.addr}},{{data.endpoint}},{{data.ack}}) {{data.data}}'},
        'USB Text': {'format': '{{data.pid}}({{data.addr}},{{data.endpoint}}) "{{data.text}}"'},

    }
    #--------------------------------------------------------------------------
    # Define tables 
    #--------------------------------------------------------------------------
    s_l2cap_commands = {
        0x01:"L2CMD_COMMAND_REJECT",        
        0x02:"L2CMD_CONNECTION_REQUEST",    
        0x03:"L2CMD_CONNECTION_RESPONSE",   
        0x04:"L2CMD_CONFIG_REQUEST",        
        0x05:"L2CMD_CONFIG_RESPONSE",       
        0x06:"L2CMD_DISCONNECT_REQUEST",    
        0x07:"L2CMD_DISCONNECT_RESPONSE",   
        0x0A:"L2CMD_INFORMATION_REQUEST",   
        0x0B:"L2CMD_INFORMATION_RESPONSE"
    }  
    s_sdp_commands = {
        0x01: " SDP_ErrorResponse",
        0x02: " SDP_ServiceSearchRequest",
        0x03: " SDP_ServiceSearchResponse",
        0x04: " SDP_ServiceAttributeRequest",
        0x05: " SDP_ServiceAttributeResponse",
        0x06: " SDP_ServiceSearchAttributeRequest",
        0x07: " SDP_ServiceSearchAttributeResponse"
    }  

    s_HIDP_msg_types = {
        0X1: "HID_CONTROL",
        0X4: "GET_REPORT",
        0X5: "SET_REPORT",
        0X6: "GET_PROTOCOL",
        0X7: "SET_PROTOCOL",
        0X8: "GET_IDLE [DEPRECATED]",
        0X9: "SET_IDLE [DEPRECATED]",
        0XA: "DATA",
        0XB: "DATC [DEPRECATED]"
    }

    s_sdp_data_element_types = {
        0x0: "(Nil)",
        0x1: "(UINT)",
        0x2: "(INT)",
        0x3: "(UUID)",
        0x4: "(STR)",
        0x5: "(BOOL)",
        0x6: "(SEQ)",
        0x7: "(ALT)",
        0x8: "(URL)"
    }
    s_psm_names = {
        0x01: "(SDP)",
        0x11: "(CTRL)",
        0x13: "(INT)"
    }


    #--------------------------------------------------------------------------
    # Class Init function 
    #--------------------------------------------------------------------------
    def __init__(self):
        '''
        Initialize HLA.
        '''
        self.base = 10 # commands choose. 
        if self.DisplayFormat == 'Hex':
            self.base = 16
        elif self.DisplayFormat == 'Dec':
            self.base = 10
        self.HCIChannelFixed = int(self.HCIChannel)
        self.addr = None
        self.endpoint = None
        self.frame_start_time = None
        self.frame_end_time = None
        self.data_packet_save = None
        self.text_save = None
        self.frame_ack_nak = None
        self.processing_report_data = False
        #self.frame_data = {'pid':'', 'pid2':''}
        self.frame_data = {'pid':''}
        self.first_packet_start_time = None;
        #print("Settings:", self.my_string_setting,
        #      self.my_number_setting, self.my_choices_setting)
        self.parse_data = None
        self.parse_level_bytes_left = arr.array('l')
        self.parse_str = ""
        self.map_CID_to_usage = {}
 
    # returns, token Type, Size (bytes used), and value
    def get_next_token(self, index, cb_left):
        element = self.parse_data[index]
        element_type = element >> 3
        element_size = element & 7;

        print("GNT: ", index, ",", cb_left, ", ", hex(element), "(", element_type, ",", element_size, ")" )
        index += 1
        try:
            if (element == 0): # nil
                element_size = 1
                element_value = None
            # type = 1 un signed
            elif (element == 0x08): # unsigned one byte
                element_size = 2
                element_value = self.parse_data[index]
            elif (element == 0x09): # unsigned 2  byte
                element_size = 3
                element_value = int.from_bytes(self.parse_data[index:index+2],'big', signed=False)
            elif (element == 0x0A): # unsigned 4  byte
                element_size = 5
                element_value = int.from_bytes(self.parse_data[index:index+4],'big', signed=False)
            elif (element == 0x0B): # unsigned 8  byte
                element_size = 9
                element_value = int.from_bytes(self.parse_data[index:index+8],'big', signed=False)
            # type = 2 signed
            elif (element == 0x10): # unsigned one byte
                element_size = 2
                element_value = int.from_bytes(self.parse_data[index:index+1],'big', signed=True)
            elif (element == 0x11): # unsigned 2  byte
                element_size = 3
                element_value = int.from_bytes(self.parse_data[index:index+2],'big', signed=True)
            elif (element == 0x12): # unsigned 4  byte
                element_size = 5
                element_value = int.from_bytes(self.parse_data[index:index+4],'big', signed=True)
            elif (element == 0x13): # unsigned 8  byte
                element_size = 9
                element_value = int.from_bytes(self.parse_data[index:index+8],'big', signed=True)
            # type = 3 uuid
            elif (element == 0x18): # unsigned one byte
                element_size = 2
                element_value = self.parse_data[index] 
            elif (element == 0x19): # unsigned 2  byte
                element_size = 3
                element_value = int.from_bytes(self.parse_data[index:index+2],'big', signed=False)
            elif (element == 0x1A): # unsigned 4  byte
                element_size = 5
                element_value = int.from_bytes(self.parse_data[index:index+4],'big', signed=False)
            # type = 4 String
            elif (element == 0x25):
                str_size = self.parse_data[index];
                index += 1
                element_size = str_size + 2
                if (cb_left >= element_size):
                    try:
                        element_value = self.parse_data[index:index+str_size].decode('utf-8')
                    except:
                        element_value = "<str parse error>"
                        count_out = 0
                        for i in range(index, index+str_size):
                            element_value += ' ' + hex(self.parse_data[i])
                            count_out += 1
                            if (count_out > 32):
                                element_value += "..."
                                break;

            elif (element == 0x26):
                str_size = (self.parse_data[index] << 8) + self.parse_data[index + 1] ;
                index += 2
                element_size = str_size + 3
                if (cb_left >= element_size):
                    try:
                        element_value = self.parse_data[index:index+str_size].decode('utf-8')
                    except:
                        element_value = "<str parse error>"
                        count_out = 0
                        for i in range(index, index+str_size):
                            element_value += ' ' + hex(self.parse_data[i])
                            count_out += 1
                            if (count_out > 64):
                                element_value += "..."
                                break;
            # type = 5 Bool
            elif (element == 0x28): # unsigned one byte
                element_size = 2
                element_value = self.parse_data[index] 

            # type = 6 Data element sequence
            elif (element == 0x35): 
                sequence_size = str_size = self.parse_data[index]
                element_size = 2
                element_value = sequence_size
            elif (element == 0x36):
                sequence_size = (self.parse_data[index] << 8) + self.parse_data[index + 1] ;
                element_size = 3
                element_value = sequence_size
            elif (element == 0x37):
                sequence_size = int.from_bytes(self.parse_data[index:index+4],'big', signed=False) ;
                element_size = 5
                element_value = sequence_size
            # type = 7 Data element sequence
            elif (element == 0x3D): 
                sequence_size = str_size = self.parse_data[index]
                element_size = 2
                element_value = sequence_size
            elif (element == 0x3E):
                sequence_size = (self.parse_data[index] << 8) + self.parse_data[index + 1] ;
                element_size = 3
                element_value = sequence_size
            elif (element == 0x3F):
                sequence_size = int.from_bytes(self.parse_data[index:index+4],'big', signed=False) ;
                element_size = 5
                element_value = sequence_size
            else:
                print("### DECODE Failed 0x", hex(element))
                return element_type, 1, None
        
            # and return it.
            if (cb_left < element_size):
                print("<<<<<<<<<<<<<<<<<<<< split >>>>>>>>>>>>>>>>>>>>>>>>>>")
                return -1, -1, None

            return element_type, element_size, element_value
        except:
            # maybe not enough data left
            print("<<<<<<<<<<<<<<<<<<<< Except >>>>>>>>>>>>>>>>>>>>>>>>>>")
            return -1, -1, None


    def decode_SDP_Attribute_results(self, frame: AnalyzerFrame, start_index):
        print("DSDP:", end="")
        for i in range(len(self.data_packet_save)):
            if (i == start_index):
                print("*", end='')
            else:    
                print(" ", end='')
            print(hex(self.data_packet_save[i]), end="")
        print("")
        # example:
        # (0)0x47 0x20 0x34 0x0 0x30 0x0 0x40 0x0 
        # (8)0x7 0x0 0x0 0x0 0x2b 
        # (12)0x0 0x26
        # 0x36 0x3 0xad 0x36 0x0 0x8e 0x9 0x0 0x0 0xa 0x0 0x0 0x0 0x0 0x9 0x0 0x1 0x35 0x3 0x19 0x10 0x0 0x9 0x0 0x4 0x35 0xd 0x35 0x6 0x19 0x1 0x0 0x9 0x0 0x1 0x35 0x3 0x19 0x2 0x0 0x26
        cb = (self.data_packet_save[start_index] << 8) + self.data_packet_save[start_index + 1]

        # lets move the data to the parse_data 
        index = start_index + 2
        if (self.parse_data == None):
            self.parse_data = self.data_packet_save[index:index+cb]
        else:
            self.parse_data += self.data_packet_save[index:index+cb]
            
        print("Parse data:", end="")
        for i in range(len(self.parse_data)):
            print(" ", end='')
            print(hex(self.parse_data[i]), end="")
        print("")
        cb = len(self.parse_data)
        index = 0
        # first pass print out in structure way...
        while (cb > 0):
            element_type, element_size, element_value = self.get_next_token(index, cb)
            if (element_type == -1):
                break;
            print(";;;;", end="") # put in text area
            for i in range(len(self.parse_level_bytes_left)):
                #decrement the bytes left in each level
                self.parse_level_bytes_left[i] -= element_size
                print("  ", end="")

            print("(", str(element_type), ",", str(element_size), ")", end='')
            if (element_type in [6,7]): 
                self.parse_level_bytes_left.append(element_value) # new collection level
                print("{ (", element_value, ")", end='')
                if (element_type == 6):
                    self.parse_str += " {C"
                else:
                    self.parse_str += " {A"
            else:
                print(element_value, end='')
                self.parse_str += " "
                if  element_type in self.s_sdp_data_element_types:
                    self.parse_str += self.s_sdp_data_element_types[element_type]
                else:
                    self.parse_str = '(0x' + hex(element_type ) + ')'

                if (element_type == 4):
                    self.parse_str += element_value
                elif self.base == 10:
                    self.parse_str += str(element_value)
                else:
                    self.parse_str += hex(element_value)


            # now see if any of the sequnce levels has completed
            i = len(self.parse_level_bytes_left) - 1
            output_parse_str = False
            while (i >= 0):
                if (self.parse_level_bytes_left[i] <= 0):
                    self.parse_level_bytes_left.pop() # remove that item
                    print(" }", end="")
                    self.parse_str += " }"
                    if (i <= 2):
                        output_parse_str = True
                i -= 1
            cb -= element_size
            index += element_size
            print('') #output end of line    
            if output_parse_str:
                print("===== ", self.parse_str)
                self.parse_str = "" 
        
        # see if we exited with cb > 0
        if (cb <= 0):
            self.parse_data = None
        else:
            del(self.parse_data[0:index])
            print("<<<<<< Carry over  >>> :", end="") 
            for i in range(len(self.parse_data)):
                print(" ", end='')
                print(hex(self.parse_data[i]), end="")
            print("")

    def cid_name_to_str(self, cid):
        return_string = hex(cid)
        if cid in self.map_CID_to_usage:
            cid_map = self.map_CID_to_usage[cid]
            return_string += "=" + cid_map["SORD"] + self.s_psm_names[cid_map["PSM"]]
        return return_string


    def parse_l2cap_commands(self, frame: AnalyzerFrame, cmd):
        # get the command name:
        if cmd in self.s_l2cap_commands:
            text_str = self.s_l2cap_commands[cmd]

            # then see if we want to add additional information
            if cmd == 0x02: # "L2CMD_CONNECTION_REQUEST" (8)0x2 0x3 0x4 0x0 0x1 0x0 0x40 0x0
                try:
                    PSM = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                    SCID = self.data_packet_save[14] + (self.data_packet_save[15] << 8)
                    text_str += " PSM: 0x" + hex(PSM)
                    if PSM in self.s_psm_names:
                        text_str += self.s_psm_names[PSM]
                        self.map_CID_to_usage.update({SCID:{"PSM":PSM, "SORD":"S"}} )

                    text_str += " SCID:" + hex(SCID) 
                except:
                    text_str += " (except)"

            elif cmd == 0x03: #"L2CMD_CONNECTION_RESPONSE" (8)0x3 0x3 0x8 0x0 0x42 0x0 0x40 0x0 0x0 0x0 0x0 0x0
                #try:
                DCID = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                SCID = self.data_packet_save[14] + (self.data_packet_save[15] << 8)
                scid_map = self.map_CID_to_usage[SCID]
                if scid_map != None:
                    self.map_CID_to_usage.update({DCID:{"PSM":scid_map["PSM"], "SORD":"D"}} )
                result = self.data_packet_save[16] + (self.data_packet_save[17] << 8)
                status = self.data_packet_save[18] + (self.data_packet_save[19] << 8)
                text_str += " SCID: " + self.cid_name_to_str(SCID) + " DCID: " + hex(DCID) + " RES: " + hex(result) + "Status: " + hex(status)
                #except:
                #   text_str += " (except)"
            elif cmd == 0x04: #"L2CMD_CONFIG_REQUEST" 0x4 0x4 0x4 0x0 0x42 0x0 0x0 0x0  
                try:
                    DCID = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                    flags = self.data_packet_save[14] + (self.data_packet_save[15] << 8)
                    text_str += " DCID: " + self.cid_name_to_str(DCID) + " flags: " + hex(flags)
                except:
                    text_str += " (except)"
            elif cmd == 0x05: # "L2CMD_CONFIG_RESPONSE", 0x5 0x2 0xa 0x0 0x42 0x0 0x0 0x0 0x0 0x0 0x1 0x2 0x30 0x0
                try:
                    len = self.data_packet_save[10] + (self.data_packet_save[11] << 8)
                    SCID = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                    flags = self.data_packet_save[14] + (self.data_packet_save[15] << 8)
                    result = self.data_packet_save[16] + (self.data_packet_save[17] << 8)
                    text_str += " SCID: " + self.cid_name_to_str(SCID) + " flags: " + hex(flags) + " RES: " + hex (result)
                    if len > 8:
                        config = self.data_packet_save[18] + (self.data_packet_save[19] << 8)
                        text_str += "Config: " + hex(config)
                except:
                    text_str += " (except)"

            elif cmd == 0x06: # "L2CMD_DISCONNECT_REQUEST",    
                DCID = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                SCID = self.data_packet_save[14] + (self.data_packet_save[15] << 8)
                text_str += " DCID: " + self.cid_name_to_str(DCID) + " SCID: " + self.cid_name_to_str(SCID)

            elif cmd == 0x07: # "L2CMD_DISCONNECT_RESPONSE",   
                DCID = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                SCID = self.data_packet_save[14] + (self.data_packet_save[15] << 8)
                text_str += " DCID: " + self.cid_name_to_str(DCID) + " SCID: " + self.cid_name_to_str(SCID)
            
            elif cmd == 0x0A:  # "L2CMD_INFORMATION_REQUEST"
                info_type = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                text_str += " IT: " + hex(info_type)
                if (info_type == 1):
                    text_str += "(Connectionless MTU)"
                elif (info_type == 2):
                    text_str += "(Extended fetures supported)"
                elif (info_type == 3):
                    text_str += "(Fixed channels supported)"

            elif cmd == 0x0B:  # "L2CMD_INFORMATION_RESPONSE"
                #   0x47 0x20 0x10 0x0 0xc 0x0 0x1 0x0 (8)0xb 0x1 0x8 0x0 0x2 0x0 0x0 0x0 0x80 0x2 0x0 0x0
                len = self.data_packet_save[10] + (self.data_packet_save[11] << 8)
                info_type = self.data_packet_save[12] + (self.data_packet_save[13] << 8)
                result = self.data_packet_save[14] + (self.data_packet_save[15] << 8)
                text_str += " IT: " + hex(info_type) + " result: " + hex(result)
                if (len > 4):
                    text_str += " data:"
                    for i in range(4, len): 
                        text_str += " " + hex(self.data_packet_save[12+i])


        else:
            try:
                text_str = ''.join([ '0x', hex(cmd ).upper()[2:] ])
                text_str = self.parse_l2cap_connect_request(frame)
            except:
                text_str += " (except)"
                

        return text_str

    def decode(self, frame: AnalyzerFrame):
        #if frame.type == 'frame':
        #    self.frame_start_time = frame.start_time
        #    self.frame_data = {'pid':'', 'pid2':''}
        if self.first_packet_start_time == None:
            self.first_packet_start_time = frame.start_time
        if frame.type == 'pid':
            # test below ???
            if self.frame_data != None:
                pid_type = frame.data['value']
                if pid_type == "IN":
                    self.frame_data['pid'] = "IN" 
                    self.frame_start_time = frame.start_time
                elif pid_type == "OUT":
                    self.frame_data['pid'] = "OUT" 
                    self.frame_start_time = frame.start_time
                elif pid_type == "SETUP":
                    self.frame_data['pid'] = "SETUP" 
                    self.frame_start_time = frame.start_time
                if self.data_packet_save != None:
                    if pid_type == "ACK":
                        self.frame_ack_nak = "ACK"
                    elif pid_type == "NAK":
                        self.frame_ack_nak = "NAK"

                #elif pid_type == "DATA0":
                #    self.frame_data['pid2'] = "DATA0" 
                #elif pid_type == "DATA1":
                #    self.frame_data['pid2'] = "DATA1" 
                #else:    
                #    self.frame_data['pid'] = ''.join([ '0x', hex(pid_type[0]).upper()[2:] ]) 
        elif frame.type ==  'addrendp':
            self.addr = frame.data['value']
            self.endpoint = frame.data['value2']
        elif frame.type == 'data':
            if self.data_packet_save == None:
                self.data_packet_save = bytearray()
            self.data_packet_save.extend(frame.data['data'])    
            self.frame_end_time = frame.end_time
        
        elif frame.type == 'protocol':
            self.data_packet_save = bytearray(8)
            self.data_packet_save[0] = frame.data['bmRequestType'][0]
            self.data_packet_save[1] = frame.data['bRequest'][0]

            wValue = frame.data['wValue']
            self.data_packet_save[2] = wValue[1]
            self.data_packet_save[3] = wValue[0]

            wIndex = frame.data['wIndex']   
            self.data_packet_save[4] = wIndex[1]
            self.data_packet_save[5] = wIndex[0]

            wLength = frame.data['wLength']   
            self.data_packet_save[6] = wLength[1]
            self.data_packet_save[7] = wLength[0]
            self.frame_end_time = frame.end_time
        
        elif frame.type == 'presult':
            if not self.processing_report_data:
                self.processing_report_data = True
                start_bias_time = float(self.frame_start_time - self.first_packet_start_time)
                print(str(start_bias_time), ';Result Report Start;', hex(self.endpoint[0]), ';', hex(self.addr[0]))

            if self.data_packet_save == None:
                self.data_packet_save = bytearray()
            wLength = frame.data['wLength']   
            data = frame.data['value']
            if wLength[0] == 1:
                self.data_packet_save.extend(data)
            else:
                data_rev = bytearray(2);
                data_rev[0] = data[1]
                data_rev[1] = data[0]
                self.data_packet_save.extend(data_rev)
            self.frame_end_time = frame.end_time

            data = frame.data['value']
            self.data_packet_save.extend(data)
            start_bias_time = float(frame.start_time - self.first_packet_start_time)
            print(str(start_bias_time), ';Item;', hex(self.endpoint[0]), ';', hex(self.addr[0]), ';', frame.data['text'])
            self.frame_end_time = frame.end_time

        elif (frame.type == 'wchar') or (frame.type == 'wLANGID'):
            if self.data_packet_save == None:
                self.data_packet_save = bytearray()
            data = frame.data['data']
            data_rev = bytearray(2);
            data_rev[0] = data[1]
            data_rev[1] = data[0]
            self.data_packet_save.extend(data_rev)

            text = frame.data['text']
            if text != None:
                if self.text_save == None:
                    self.text_save = ''
                self.text_save += text
            self.frame_end_time = frame.end_time

        elif frame.type == 'hiditem':
            if not self.processing_report_data:
                self.processing_report_data = True
                start_bias_time = float(self.frame_start_time - self.first_packet_start_time)
                print(str(start_bias_time), ';HID Report Start;', hex(self.endpoint[0]), ';', hex(self.addr[0]))

            if self.data_packet_save == None:
                self.data_packet_save = bytearray()
            data = frame.data['value']
            self.data_packet_save.extend(data)
            start_bias_time = float(frame.start_time - self.first_packet_start_time)
            print(str(start_bias_time), ';HID Item;', hex(self.endpoint[0]), ';', hex(self.addr[0]), ';', frame.data['text'])
            self.frame_end_time = frame.end_time
        elif frame.type == 'eop':
            if (self.data_packet_save) != None and self.frame_ack_nak != None:
                data_str = ''
                text_str = ''
                report_type = 'USB'
                #print("PID", self.pid_type, "length: ", len(self.pid_type), "Hex:", hex(self.pid_type[0]))
                if self.frame_data['pid'] == "SETUP":
                    bmRequestType = self.data_packet_save[0]
                    bmRequest = self.data_packet_save[1]
                    wValue = self.data_packet_save[2] + (self.data_packet_save[3] << 8)
                    wIndex = self.data_packet_save[4] + (self.data_packet_save[5] << 8)
                    wLength = self.data_packet_save[6] + (self.data_packet_save[7] << 8)
                    # first pass brute force
                    if bmRequestType == 0x0:
                        if bmRequest == 0x05:
                            text_str = "SET_ADDRESS"
                        elif bmRequest == 0x09:     
                            text_str = "[SET_CONFIGURATION"
                    elif bmRequestType == 0x21:
                        if bmRequest == 0x0A:
                            text_str = "[HID SET_IDLE"
                        elif bmRequest == 0x09:     
                            text_str = "[HID SET_REPORT"
                    elif bmRequestType == 0x80:
                        if bmRequest == 0x06:     
                            text_str = "[GET_DESCRIPTOR -"
                            # work off of high byte of wvalue
                            if self.data_packet_save[3] == 0x01:
                                text_str += " DEVICE #:" + str(self.data_packet_save[2]) 
                            elif self.data_packet_save[3] == 0x02:
                                text_str += " CONFIG #:" + str(self.data_packet_save[2])
                            elif self.data_packet_save[3] == 0x03:
                                text_str += " STRING #:" + str(self.data_packet_save[2])
                            elif self.data_packet_save[3] == 0x06:
                                text_str += " DEVICE_QUALIFIER #:" + str(self.data_packet_save[2])
                            else:
                                text_str += '<?? '
                    elif bmRequestType == 0x81:
                        if bmRequest == 0x06:     
                            text_str = "[GET_DESCRIPTOR - HID REPORT"
                    elif bmRequestType == 0xA1:
                        if bmRequest == 0x01:     
                            text_str = "[GET_REPORT -"
                            # work off of high byte of wvalue
                            if self.data_packet_save[3] == 0x03:
                                text_str += " FEATURE # " + str(self.data_packet_save[2]) 
                            else:
                                text_str += '?? '
                    else:
                        text_str = "[RT:" + hex(bmRequestType) + " R:" + hex(bmRequest) 

                    text_str +=' I:' + hex(wIndex) + " L:" + hex(wLength)  + "]"

                    self.frame_data['text'] = text_str
                    report_type = 'USB Text'
                elif self.HCIChannelFixed == self.endpoint[0] and len(self.data_packet_save) > 8:
                    # Try to do simple decode of L2CAP messages
                    HCIHandle = self.data_packet_save[0] + (self.data_packet_save[1] << 8)
                    HCILen = self.data_packet_save[2] + (self.data_packet_save[3] << 8)
                    L2CAPHLen = self.data_packet_save[4] + (self.data_packet_save[5] << 8)
                    Channel = self.data_packet_save[6] + (self.data_packet_save[7] << 8)
                    cmd = self.data_packet_save[8]
                    cmd_type = cmd >> 4
                    if (cmd_type == 0):
                        if (Channel >= 0x40) and (Channel <= 0x4f):
                            if  cmd in self.s_sdp_commands:
                                text_str = self.s_sdp_commands[cmd]
                            else:
                                text_str = ''.join([ '0x', hex(cmd ).upper()[2:] ])
                            #lets play with decoding some
                            if cmd == 7:
                                self.decode_SDP_Attribute_results(frame, 13) 
                            #SDP s_sdp_commands
                        else:  
                            # process l2cap commands
                            text_str = self.parse_l2cap_commands(frame, cmd)
                    else:
                        if  cmd_type in self.s_HIDP_msg_types:
                            text_str = self.s_HIDP_msg_types[cmd_type]
                        else:
                            text_str = ''.join([ '0x', hex(cmd ).upper()[2:] ])
                        text_str += "(0x" + hex(cmd & 0xf )  + ")"
                    self.frame_data['text'] = text_str

  
                elif self.text_save:
                    text_str = self.text_save
                    self.frame_data['text'] = text_str
                    self.text_save = None
                    report_type = 'USB Text'

                for i in range(len(self.data_packet_save)):
                    if self.base == 10:
                        data_str +=' ' + str(self.data_packet_save[i])
                    else:
                        data_str +=' ' + hex(self.data_packet_save[i])
                self.frame_data['data'] = data_str    
                self.frame_data['endpoint'] = self.endpoint
                self.frame_data['addr'] = self.addr
                self.frame_data['ack'] = self.frame_ack_nak
                self.data_packet_save = None
                start_bias_time = float(self.frame_start_time - self.first_packet_start_time)
                if self.base == 10:
                    print(str(start_bias_time), ';', self.frame_data['pid'], ';', str(self.endpoint[0]), ';', str(self.addr[0]), ";", self.frame_data['ack'], ';', text_str, ";",data_str)
                else:
                    print(str(start_bias_time), ';', self.frame_data['pid'], ';', hex(self.endpoint[0]), ';', hex(self.addr[0]), ";", self.frame_data['ack'], ';', text_str, ";",data_str)
                new_frame = AnalyzerFrame(report_type, self.frame_start_time, self.frame_end_time, self.frame_data)
                #self.frame_data = {'pid':'', 'pid2':''}
                self.frame_data = {'pid':''}
                self.frame_ack_nak = None
                self.processing_report_data = False
                return new_frame

        return None