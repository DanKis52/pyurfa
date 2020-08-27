
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
import decimal

class UrfaPacket(object):

    def __init__(self, socket):
        self.version = 35
        self.code = 0
        self.len = 4
        self.iterator = 0
        self.attr = {}
        self.data = {}
        self.socket = socket
        self.sendattr = []
        self.senddata = []

    def clean(self):
        self.code = 0
        self.len = 4
        self.iterator = 0
        self.attr = {}
        self.data = {}
        self.sendattr = []
        self.senddata = []

    def read(self):
        self.code = unpack('B',self.socket.recv(1))[0]
        if self.version != unpack('B', self.socket.recv(1))[0]:
            raise Exception('Error code: {0}'.format(unpack('B',self.socket.recv(1))[0]))
        else:
            self.len = unpack('>H', self.socket.recv(2))[0]

            tmp_len = 4

            while tmp_len < self.len:
                # signed short, no reverse
                code = unpack('=h', self.socket.recv(2))[0]
                # unsigned short, reverse
                lenght = unpack('>H', self.socket.recv(2))[0]
                tmp_len = tmp_len + lenght

                if lenght == 4:
                    data = None
                else:
                    data = self.socket.recv(lenght-4)
                if code == 5:
                    self.data[self.iterator] = data
                    self.iterator += 1
                else:
                    self.attr[code] = { 'data' : data, 'len' : lenght }


    def write(self):
        data = bytes()
        data += pack('B',self.code)
        data += pack('B',self.version)
        data += pack('>H',self.len)

        for a in self.sendattr:
            data += pack('<H', a['code'])
            data += pack('>H', a['len'])
            data += a['data']

        for d in self.senddata:
            data += pack('<H',5)
            data += pack('>H', len(d) + 4)
            data += d

        self.socket.send(data)

    def DataSetInt(self, param):
        """Function OK"""
        param = int(param)
        self.senddata.append(pack('>L', param))
        self.len += 8

    def DataSetLong(self, param):
        """Function OK"""
        param = int(param)
        self.senddata.append(pack(">L",param))
        self.len += 12

    def DataSetDouble(self, param):
        """Function OK"""
        self.senddata.append(pack(">d",param))
        self.len += 12

    def DataSetString(self, s):
        if type(s) is str:
            s = s.encode()
        self.senddata.append(s)
        self.len += len(s) + 4

    def DataSetIPAddress(self, param):
        self.senddata.append(inet_aton(param))
        self.len += 8

    def AttrSetInt(self, attr, code):
        self.sendattr.append({ 'code' : code, 'data' : pack('>L',attr), 'len' : 8 })
        self.len += 8

    def AttrSetString(self, s, code):
        if type(s) is str:
            s = s.encode()
        self.sendattr.append({ 'code' :code, 'data' : s, 'len' : len(s) + 4 })
        self.len += len(s) + 4

    def AttrGetInt(self, code):
        if code in self.attr.keys():
            x = unpack('>L', self.attr[code]['data'])
            if x[0] > 2147483647:
                return x[0]-4294967296
            return x[0]
        return False


    def DataGetInt(self):
        num = self.iterator
        self.iterator += 1
        return unpack(">L", self.data[num])[0]

    def DataGetLong(self):
        num = self.iterator
        self.iterator += 1
        return unpack(">L", self.data[num])[0]

    def DataGetDouble(self):
        num = self.iterator
        self.iterator += 1
        return unpack('>d', self.data[num])[0]

    def DataGetString(self):
        num = self.iterator
        self.iterator += 1
        bstr = self.data[num]
        if bstr is None: bstr = b''
        return bstr.decode()

    def DataGetIPAddress(self):
        num = self.iterator
        self.iterator += 1
        return inet_ntoa(self.data[num])