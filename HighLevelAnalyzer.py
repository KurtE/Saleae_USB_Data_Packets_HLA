# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


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

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'usb': {
            #'format': '{{data.data}}'
            #'format': '{{data.pid}},{{data.pid2}}({{data.addr}},{{data.endpoint}}) {{data.data}}'
            'format': '{{data.pid}}({{data.addr}},{{data.endpoint}}) {{data.data}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''
        self.base = 10 # commands choose. 
        if self.DisplayFormat == 'Hex':
            self.base = 16
        elif self.DisplayFormat == 'Dec':
            self.base = 10

        self.addr = None
        self.endpoint = None
        self.frame_start_time = None
        self.frame_end_time = None
        self.data_packet_save = None
        #self.frame_data = {'pid':'', 'pid2':''}
        self.frame_data = {'pid':''}
        self.first_packet_start_time = None;
        #print("Settings:", self.my_string_setting,
        #      self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        #if frame.type == 'frame':
        #    self.frame_start_time = frame.start_time
        #    self.frame_data = {'pid':'', 'pid2':''}
        if self.first_packet_start_time == None:
            self.first_packet_start_time = frame.start_time
        if frame.type == 'pid':
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

        elif frame.type == 'eop':
            if (self.data_packet_save) != None:
                data_str = ''
                setup_str = ''
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
                            setup_str = "<SET_ADDRESS"
                        elif bmRequest == 0x09:     
                            setup_str = "<SET_CONFIGURATION"
                    elif bmRequestType == 0x21:
                        if bmRequest == 0x0A:
                            setup_str = "<HID SET_IDLE"
                        elif bmRequest == 0x09:     
                            setup_str = "<HID SET_REPORT"
                    elif bmRequestType == 0x80:
                        if bmRequest == 0x06:     
                            setup_str = "<GET_DESCRIPTOR -"
                            # work off of high byte of wvalue
                            if self.data_packet_save[3] == 0x01:
                                setup_str += " DEVICE #:" + str(self.data_packet_save[2]) 
                            elif self.data_packet_save[3] == 0x02:
                                setup_str += " CONFIG #:" + str(self.data_packet_save[2])
                            elif self.data_packet_save[3] == 0x03:
                                setup_str += " STRING #:" + str(self.data_packet_save[2])
                            elif self.data_packet_save[3] == 0x06:
                                setup_str += " DEVICE_QUALIFIER #:" + str(self.data_packet_save[2])
                            else:
                                setup_str += '<?? '
                    elif bmRequestType == 0x81:
                        if bmRequest == 0x06:     
                            setup_str = "<GET_DESCRIPTOR - HID REPORT"
                    elif bmRequestType == 0xA1:
                        if bmRequest == 0x01:     
                            setup_str = "<GET_REPORT -"
                            # work off of high byte of wvalue
                            if self.data_packet_save[3] == 0x03:
                                setup_str += " FEATURE # " + str(self.data_packet_save[2]) 
                            else:
                                setup_str += '?? '
                    else:
                        setup_str = "<RT:" + hex(bmRequestType) + " R:" + hex(bmRequest) 

                    setup_str +=' I:' + hex(wIndex) + " L:" + hex(wLength)  + ">"

                    self.frame_data['setup'] = setup_str

                for i in range(len(self.data_packet_save)):
                    if self.base == 10:
                        data_str +=' ' + str(self.data_packet_save[i])
                    else:
                        data_str +=' ' + hex(self.data_packet_save[i])
                self.frame_data['data'] = data_str    
                self.frame_data['endpoint'] = self.endpoint
                self.frame_data['addr'] = self.addr
                self.data_packet_save = None
                start_bias_time = float(self.frame_start_time - self.first_packet_start_time)
                if self.base == 10:
                    print(str(start_bias_time), ',', self.frame_data['pid'], ',', str(self.endpoint[0]), ',', str(self.addr[0]), ',', setup_str, ",",data_str)
                else:
                    print(str(start_bias_time), ',', self.frame_data['pid'], ',', hex(self.endpoint[0]), ',', hex(self.addr[0]), ',', setup_str, ",",data_str)
                new_frame = AnalyzerFrame("usb", self.frame_start_time, self.frame_end_time, self.frame_data)
                #self.frame_data = {'pid':'', 'pid2':''}
                self.frame_data = {'pid':''}
                return new_frame

        return None