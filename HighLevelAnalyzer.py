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
            'format': '{{data.pid}},{{data.pid2}}({{data.addr}},{{data.endpoint}}) {{data.data}}'
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
        self.frame_data = {'pid':'', 'pid2':''}
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
                pid_type = frame.data['pid']
                if pid_type[0] == 0x69:
                    self.frame_data['pid'] = "IN" 
                    self.frame_start_time = frame.start_time
                elif pid_type[0] == 0xE1:
                    self.frame_data['pid'] = "OUT" 
                    self.frame_start_time = frame.start_time
                elif pid_type[0] == 0x2D:
                    self.frame_data['pid'] = "SETUP" 
                    self.frame_start_time = frame.start_time
                elif pid_type[0] == 0xC3:
                    self.frame_data['pid2'] = "DATA0" 
                elif pid_type[0] == 0x4B:
                    self.frame_data['pid2'] = "DATA1" 
                #else:    
                #    self.frame_data['pid'] = ''.join([ '0x', hex(pid_type[0]).upper()[2:] ]) 
        elif frame.type ==  'addrendp':
            self.addr = frame.data['addr']
            self.endpoint = frame.data['endpoint']
        elif frame.type == 'data':
            if self.data_packet_save == None:
                self.data_packet_save = bytearray()
            self.data_packet_save.extend(frame.data['data'])    
            self.frame_end_time = frame.end_time

        elif frame.type == 'eop':
            if (self.data_packet_save) != None:
                #print("PID", self.pid_type, "length: ", len(self.pid_type), "Hex:", hex(self.pid_type[0]))
                data_str = ''
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
                    print(str(start_bias_time), ',', self.frame_data['pid'], ',', str(self.endpoint[0]), ',', str(self.addr[0]), ',', data_str)
                else:
                    print(str(start_bias_time), ',', self.frame_data['pid'], ',', hex(self.endpoint[0]), ',', hex(self.addr[0]), ',', data_str)
                new_frame = AnalyzerFrame("usb", self.frame_start_time, self.frame_end_time, self.frame_data)
                self.frame_data = {'pid':'', 'pid2':''}
                return new_frame

        return None