from burp import IBurpExtender
from burp import IHttpListener
import re

findItem =[
    "(?:[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[1,2][0-9]|3[0,1]))-[1-4][0-9]{6}",  # 주민등록번호 검색
    "(?:[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[1,2][0-9]|3[0,1]))",                # 생년월일 앞자리
    "[1-4][0-9]{6}",                                                            # 주민번호 뒷자리
]
pattern = '|'.join(findItem)

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp Python Plugin - find item")
        callbacks.registerHttpListener(self)
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process responses
        if not messageIsRequest:
            print "process responses"

            gResponse = messageInfo.getResponse()
            print "Reciving message:"
            if re.findall(pattern, self._helpers.bytesToString(gResponse)):
                messageInfo.setComment("check info")
            print "----------------------------------------------\n\n"
            return

        # only process requests
        else:
            print "process requests"

            gRequest = messageInfo.getRequest()
            print "Sending message:"
            if re.findall(pattern, self._helpers.bytesToString(gRequest)):
                messageInfo.setComment("check info")
            print "----------------------------------------------\n\n"
            return
