from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService

import re
import json
# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API

RE=[
    '^[1-9]\d{7}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])\d{3}$|^[1-9]\d{5}[1-9]\d{3}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])\d{3}([0-9]|X)$', # SHENFENZHENG
    '^[1]([3-9])[0-9]{9}$', # TELPHONE
    '^([a-zA-z]|[0-9]){5,17}$', #PassportNumberReg
    '^([A-Z]\d{6,10}(\(\w{1}\))?)$', # Hk card
    '^\d{8}|^[a-zA-Z0-9]{10}|^\d{18}$', #TWCard
    '(^\d{15}$)|(^\d{18}$)|(^\d{17}(\d|X|x)$)',  #isAccountCard

]

class BurpExtender(IBurpExtender, IHttpListener):

    # define registerExtenderCallbacks: From IBurpExtender Interface 
    def registerExtenderCallbacks(self, callbacks):

        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks
        # obtain an extension helpers object (Burp Extensibility Feature)
        # http://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
        self._helpers = callbacks.getHelpers()
        # set our extension name that will display in Extender Tab
        self._callbacks.setExtensionName("find JSON callback")
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

    def returnjson(self,myjson):
        try:
            json_object = json.loads(myjson)
        except ValueError,e:
            return False
        
        return json_object


    def reCheck(self,strs):
        for pattern in RE:
            if re.findall(pattern,strs):
                return True
        return False

    # define processHttpMessage: From IHttpListener Interface 
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 8 or toolFlag == 4:
            # if not messageIsRequest:
            response = messageInfo.getResponse()
            if response!=None:
                analyzedResponse = self._helpers.analyzeResponse(response) # returns IResponseInfo
                response_StatusCode = analyzedResponse.getStatusCode()
                response_headers = analyzedResponse.getHeaders()
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()


                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeResponse(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()

                if response_StatusCode==200:
                    if len(response_bodys)!=0:
                        jsonObj=self.returnjson(response_bodys)
                        if jsonObj:
                            if isinstance(jsonObj,list):  # instance of list
                                for line in jsonObj:
                                    for k,v in line.items():
                                        try:
                                            s=v.encode('utf8')
                                        except Exception,e:
                                            s=str(v)
                                        if self.reCheck(s):
                                            print 'found!!!!',request_header,s
                            else:  # instance of dict
                                for k,v in jsonObj.items():
                                    try:
                                        s=v.encode('utf8')
                                    except Exception,e:
                                        s=str(v)
                                    if self.reCheck(s):
                                        print 'found!!!!',request_header,s


