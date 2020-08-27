import hashlib
import socket
import ssl
from packet import UrfaPacket


class UrfaClient(object):

    def __init__(self, user='init', password='init',host='127.0.0.1', port='11758', ssl=False, debug=False):
        self.user = user
        self.password = password
        self.host = host
        self.port = int(port)
        self.debug = debug
        self.ssl = ssl
        self.socket = None

    def __del__(self):
        self._closesocket()

    def _opensocket(self):
        if self.socket == None:
            s = socket.socket()
            try:
                s.connect((self.host, self.port))
                if self.debug:
                    print("Connect Ok")
                self.socket = s
            except socket.error as e:
                if self.debug:
                    print(e)
                    print('Error SSL')


    def _closesocket(self):
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except socket.error as e:
                if e.errno != 9:
                    raise
            self.socket.close()
            self.socket = None



    def login(self):
        self._opensocket()
        packet = UrfaPacket(self.socket)
        while True:
            packet.clean()
            packet.read()
            if packet.code == 192:
                if self.debug:
                    print("No SSL")
                self.urfa_auth(packet)
            if packet.code == 194:
                if self.debug:
                    print('SSL section')
                a = packet.AttrGetInt(10)
                if a:
                    if self.debug:
                        print('Sever ssl True')
                    ctx = ssl.SSLContext()
                    ctx.set_ciphers('ALL:@SECLEVEL=0')
                    ctx.verify_mode=ssl.CERT_NONE
                    ctx.load_cert_chain(certfile='admin.crt',password='netup')
                    ssl_socket = ctx.wrap_socket(self.socket)
                    self.socket = ssl_socket
                if self.debug:
                    print("OK call")
                return True
            if packet.code == 195:
                if self.debug:
                    print("False call")
                return False



    def urfa_auth(self, packet):
        digest = packet.attr[6]['data']
        m = hashlib.md5()
        m.update(digest)
        m.update(self.password.encode())
        packet.clean()
        packet.code = 193
        packet.AttrSetString(self.user, 2)
        packet.AttrSetString(digest, 8)
        packet.AttrSetString(m.digest(), 9)
        packet.AttrSetInt(4, 10)
        packet.AttrSetInt(2, 1)
        packet.write()

    def urfa_call(self, code):
        packet = UrfaPacket(self.socket)
        packet.clean()
        packet.code = 201
        packet.AttrSetInt(code, 3)
        packet.write()

        packet.clean()
        packet.read()

        if packet.code == 200:
            if packet.AttrGetInt(3) == code:
                return True
            else:
                return False


    def urfa_get_data(self):
        packet = UrfaPacket(self.socket)
        packet.clean()
        while True:
            packet.read()
            if packet.AttrGetInt(4):
                break

        if len(packet.data) == 0:
            return False
        packet.iterator = 0
        return packet

    def urfa_send_param(self, packet):
        packet.code = 200
        packet.write()

