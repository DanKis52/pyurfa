import time
import xml.etree.ElementTree as ET
import os.path
from client import UrfaClient
from packet import UrfaPacket

class Urfa:
    def __init__(self, conf):
        if 'xml' in conf.keys():
           if not os.path.exists(conf['xml']):
                raise Exception("No XML file found")
        else:
            if not os.path.exists('xml/api_53-001.xml'):
                raise Exception("No XML file found")
            else:
                conf['xml']='xml/api_53-001.xml'
        if 'user' in conf.keys():
            self.user = conf['user']
        else:
            self.user = 'init'
        if 'user' in conf.keys():
            self.password = conf['password']
        else:
            self.password = 'init'
        if 'host' in conf.keys():
            self.host = conf['host']
        else:
            self.host = '127.0.0.1'
        if 'port' in conf.keys():
            self.port = int(conf['port'])
        else:
            self.port = 11758
        if 'debug' in conf.keys():
            self.debug = bool(conf['debug'])
        else:
            self.debug = False
        self.urfa_connect=UrfaClient(self.user,self.password,self.host,self.port,self.debug)
        self.urfa_connect.login()
        self.tree = ET.parse(conf['xml'])
        self.iter_ = self.tree.iter()
        self.functions = {}
        self.error = False
        self.dataForSend = {}
        self.before=[]
        self.dataCheck={}
        self.send = False
        self.tempKey = {}
        self.dataForRet = {}
        self.ret = False
        self.parse_it()

    def retdef(self, default):
        if default == 'now()':
            return time.time()
        elif default == 'max_time()':
            return 2000000000
        elif 'size(' in default:
            return len(self.dataCheck[default.replace('size(','').replace(')','')])
        else:
            return default

    def debugPrint(self, msg):
        print(msg)

    def parse_childs(self,data,dataCheck={},result=False):
        if result is False:
            self.dataCheck=dataCheck
        for el in data:
            #try:
            if el.tag=='integer':
                if self.ret:
                    if self.tempKey:
                        self.dataForRet[dataCheck['key']][dataCheck['el']][el.attrib['name']] = self.packet.DataGetInt()
                    else:
                        self.dataForRet[el.attrib['name']] = self.packet.DataGetInt()
                elif el.attrib['name'] in dataCheck.keys():
                    self.dataForSend[el.attrib['name']]=int(dataCheck[el.attrib['name']])
                    if self.send:
                        self.packet.DataSetInt(self.dataForSend[el.attrib['name']])
                elif 'default' in el.keys():
                    self.dataForSend[el.attrib['name']] = int(self.retdef(el.attrib['default']))
                    if self.send:
                        self.packet.DataSetInt(self.dataForSend[el.attrib['name']])
                else:
                    raise Exception("No need input "+el.attrib['name'])
            elif el.tag=='string':
                if self.ret:
                    if self.tempKey:
                        self.dataForRet[dataCheck['key']][dataCheck['el']][el.attrib['name']] = self.packet.DataGetString()
                    else:
                        self.dataForRet[el.attrib['name']] = self.packet.DataGetString()
                elif el.attrib['name'] in dataCheck.keys():
                    self.dataForSend[el.attrib['name']] = str(dataCheck[el.attrib['name']])
                    if self.send:
                        self.packet.DataSetString(self.dataForSend[el.attrib['name']])

                elif 'default' in el.keys():
                    self.dataForSend[el.attrib['name']] = str(self.retdef(el.attrib['default']))
                    if self.send:
                        self.packet.DataSetString(self.dataForSend[el.attrib['name']])
                else:
                    raise Exception("No need input " + el.attrib['name'])
            elif el.tag=='long':
                if self.ret:
                    if self.tempKey:
                        self.dataForRet[dataCheck['key']][dataCheck['el']][el.attrib['name']] = self.packet.DataGetLong()
                    else:
                        self.dataForRet[el.attrib['name']] = self.packet.DataGetLong()
                elif el.attrib['name'] in dataCheck.keys():
                    self.dataForSend[el.attrib['name']] = float(dataCheck[el.attrib['name']])
                    if self.send:
                        self.packet.DataSetLong(self.dataForSend[el.attrib['name']])
                elif 'default' in el.keys():
                    self.dataForSend[el.attrib['name']] = float(self.retdef(el.attrib['default']))
                    if self.send:
                        self.packet.DataSetLong(self.dataForSend[el.attrib['name']])
                else:
                    raise Exception("No need input " + el.attrib['name'])
            elif el.tag=='double':
                if self.ret:
                    if self.tempKey:
                        self.dataForRet[dataCheck['key']][dataCheck['el']][el.attrib['name']] = self.packet.DataGetDouble()
                    else:
                        self.dataForRet[el.attrib['name']] = self.packet.DataGetDouble()
                elif el.attrib['name'] in dataCheck.keys():
                    self.dataForSend[el.attrib['name']] = float(dataCheck[el.attrib['name']])
                    if self.send:
                        self.packet.DataSetDouble(self.dataForSend[el.attrib['name']])
                elif 'default' in el.keys():
                    self.dataForSend[el.attrib['name']] = float(self.retdef(el.attrib['default']))
                    if self.send:
                        self.packet.DataSetDouble(self.dataForSend[el.attrib['name']])
                else:
                    raise Exception("No need input " + el.attrib['name'])
            elif el.tag=='ip_address':
                if self.ret:
                    if self.tempKey:
                        self.dataForRet[dataCheck['key']][dataCheck['el']][el.attrib['name']] = self.packet.DataGetIPAddress()
                    else:
                        self.dataForRet[el.attrib['name']] = self.packet.DataGetIPAddress()
                elif el.attrib['name'] in dataCheck.keys():
                    self.dataForSend[el.attrib['name']] = str(dataCheck[el.attrib['name']])
                    if self.send:
                        self.packet.DataSetIPAddress(self.dataForSend[el.attrib['name']])
                elif 'default' in el.keys():
                    self.dataForSend[el.attrib['name']] = str(self.retdef(el.attrib['default']))
                    if self.send:
                        self.packet.DataSetIPAddress(self.dataForSend[el.attrib['name']])
                else:
                    raise Exception("No need input " + el.attrib['name'])
            elif el.tag=='set':
                dst=el.attrib['dst']
                src=el.attrib['src']
                value =''
                if 'value' in el.attrib.keys():
                    value = el.attrib['value']
                if not dst:
                    break
                if self.ret:
                    if self.tempKey:
                        if src and src in self.dataForRet[dataCheck['key']][dataCheck['el']].keys():
                            value = self.dataForRet[dataCheck['key']][dataCheck['el']][src]
                    else:
                        if src and src in self.dataForRet.keys():
                            value = self.dataForRet[src]
                    self.dataForRet[dst] = value
                else:
                    if src and src in self.dataForSend.keys():
                        value = self.dataForSend[src]
                    self.dataForSend[dst] = value
            elif el.tag=='if':
                variable = el.attrib['variable']
                result_value = False
                if self.ret:
                    if self.tempKey:
                        findKeys = self.dataForRet[dataCheck['key']][dataCheck['el']]
                    else:
                        findKeys = self.dataForRet
                else:
                    findKeys=self.dataForSend
                for key in findKeys.keys():
                    if key==variable:
                        result_value = findKeys[key]
                        break
                if result_value is False:
                    for dcEl in dataCheck:
                        if dcEl['name']==variable:
                            result_value=dcEl['value']
                            break
                if result_value is False:
                    break
                if 'int' in str(type(result_value)):
                    value=int(el.attrib['value'])
                elif 'float' in str(type(result_value)):
                    value = float(el.attrib['value'])
                elif 'str' in str(type(result_value)):
                    value = str(el.attrib['value'])
                elif el.tag == 'error':
                    raise Exception(el)
                else:
                    raise Exception("Not provided an error, contact the developer " + el.attrib['name'])
                if el.attrib['condition'] == 'eq':
                    if result_value == value:
                       self.parse_childs(list(el), dataCheck,result)
                elif el.attrib['condition'] == 'ne':
                    self.parse_childs(list(el), dataCheck,result)
            elif el.tag=='for':
                if self.ret:
                    if self.tempKey:
                        self.tempKey[el.attrib['count'].replace('size(', '').replace(')', '')] = self.dataForRet[dataCheck['key']][dataCheck['el']][el.attrib['count'].replace('size(', '').replace(')', '')]
                    else:
                        self.tempKey[el.attrib['count'].replace('size(', '').replace(')', '')]=self.dataForRet[el.attrib['count'].replace('size(', '').replace(')', '')]
                    while self.tempKey[el.attrib['count'].replace('size(', '').replace(')', '')]:
                        if 'int' in str(type(self.dataForRet[el.attrib['count'].replace('size(', '').replace(')', '')])):
                            self.dataForRet[el.attrib['count'].replace('size(', '').replace(')', '')]=[{}]
                        else:
                            self.dataForRet[el.attrib['count'].replace('size(', '').replace(')', '')].append({})
                        #print({'key':el.attrib['count'].replace('size(', '').replace(')', ''),'el':len(self.dataForRet[el.attrib['count'].replace('size(', '').replace(')', '')])-1})
                        self.parse_childs(list(el), {'key':el.attrib['count'].replace('size(', '').replace(')', ''),'el':len(self.dataForRet[el.attrib['count'].replace('size(', '').replace(')', '')])-1}, True)
                        self.tempKey[el.attrib['count'].replace('size(', '').replace(')', '')]=self.tempKey[el.attrib['count'].replace('size(', '').replace(')', '')]-1
                    del self.tempKey[el.attrib['count'].replace('size(', '').replace(')', '')]
                else:
                    self.dataForSend[el.attrib['count'].replace('size(', '').replace(')', '')] = []
                    if not el.attrib['count'].replace('size(','').replace(')','') in dataCheck.keys():
                        if self.debug:
                            self.debugPrint("Not provided an error, contact the developer "+el.attrib['count'].replace('size(','').replace(')',''))
                        raise Exception("Not provided an error, contact the developer " + el.attrib['name'])
                    else:
                        for fr in dataCheck[el.attrib['count'].replace('size(','').replace(')','')]:
                            self.before.append(self.dataForSend)
                            self.dataForSend = {}
                            self.parse_childs(list(el), fr,True)
                            rovert=self.before.pop(0)
                            rovert[el.attrib['count'].replace('size(','').replace(')','')].append(self.dataForSend)
                            self.dataForSend=rovert
                            if self.debug:
                                self.debugPrint(self.dataForSend)
            elif el.tag=='error':
                raise Exception(el)
            '''except Exception:
                print("Error no need input: "+str(el.attrib['name']))
                self.error=True'''
            #self.lastChild = el

    def parse_it(self):
        for elem in self.iter_:
            inp={}
            out={}
            #print(elem.attrib)
            for fn in list(elem):
                if fn.tag=='input':
                    #self.bufer={}
                    #self.parse_childs(fn.getchildren())
                    inp=list(fn)
                if fn.tag == 'output':
                    self.bufer = {}
                    out = list(fn)
            if 'name' in elem.keys() and 'rpcf_' in elem.attrib['name']:
                self.functions[elem.attrib['name']] = {'id': elem.attrib['id'], 'input': inp,'output': out}
        #print(self.functions)

    def runner(self, attr, *args, **kwargs):
        function = attr
        if function in self.functions.keys():
            if self.debug:
                self.debugPrint(function)
            dataInp=self.functions[function]['input']
            if dataInp and not 'dict' in str(type(args[0])):
                if self.debug:
                    self.debugPrint("Not input data")
            else:
                self.parse_childs(dataInp,args[0])
                if self.error:
                    if self.debug:
                        self.debugPrint(self.dataForSend)
                        self.debugPrint('No send but input data no fun')
                else:
                    self.send=True
                    if not self.urfa_connect.urfa_call(int(self.functions[function]['id'],16)):
                        if self.debug:
                            self.debugPrint("Error calling function "+function)
                        return False
                    if dataInp:
                        self.dataForSend={}
                        if self.debug:
                            self.debugPrint('Send parametres')
                        self.packet=UrfaPacket(self.urfa_connect.socket)
                        self.parse_childs(dataInp, args[0])
                        self.urfa_connect.urfa_send_param(self.packet)
                    if self.debug:
                        self.debugPrint('Try get response')
                    self.packet = self.urfa_connect.urfa_get_data()
                    if self.packet is False:
                        if self.debug:
                            self.debugPrint('No data response')
                        return False
                    else:
                        if self.debug:
                            self.debugPrint('Data recived')
                        self.dataForRet = {}
                        self.send = False
                        self.ret = True
                        dataOut=self.functions[function]['output']
                        if dataOut:
                            self.parse_childs(dataOut)
                        self.packet.clean()
                        self.ret = False
                        self.dataForSend = {}
                        return self.dataForRet

        else:
            if self.debug:
                self.debugPrint('No function found')

    def __getattr__(self,attr):
        def wrap(*args,**kwargs):
            return self.runner(attr,*args,**kwargs)
        return wrap