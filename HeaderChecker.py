# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, IMessageEditorTab, IMessageEditorTabFactory
from java.io import PrintWriter
from javax.swing import JPanel, JScrollPane, JTextPane
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import BorderLayout, Color

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HeaderChecker")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        callbacks.registerMessageEditorTabFactory(self)

        self._stdout.println("Extension loaded successfully!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response:
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()
                results = self.checkSecurityHeaders(headers)
                messageInfo.setComment("\n".join([h[1] if h[2] else "{}: Missing".format(h[0]) for h in results]))

    def checkSecurityHeaders(self, headers):
        securityHeaders = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options"
        ]

        results = []

        for header in securityHeaders:
            header_line = next((h for h in headers if h.startswith(header)), None)
            results.append((header, header_line, header_line is not None))
        return results

    def checkInfoHeaders(self, headers):

        infoHeaders = [
            "X-Powered-By",
            "Server",
            "X-AspNet-Version",
            "X-ASpNetMvc-Version"
        ]

        results = []
        
        for header in infoHeaders:
            header_line = next((h for h in headers if h.startswith(header)), None)
            if header_line:
                header_value = header_line.split(": ", 1)[1] if ": " in header_line else header_line
                results.append((header, header_value, True))
        return results

    def createNewInstance(self, controller, editable):
        return SecurityHeadersTab(self, controller, editable)

class SecurityHeadersTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._txtInput = JTextPane()
        self._txtInput.setEditable(False)
        self._scrollPane = JScrollPane(self._txtInput)
        self._currentMessage = None

    def getTabCaption(self):
        return "HeaderChecker"

    def getUiComponent(self):
        return self._scrollPane

    def isEnabled(self, content, isRequest):
        return not isRequest

    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setText("")
        else:
            analyzedResponse = self._extender._helpers.analyzeResponse(content)
            headers = analyzedResponse.getHeaders()
            doc = self._txtInput.getStyledDocument()

            self._txtInput.setText("")

            # Security Headers
            self._appendText(doc, "Security Headers:\n\n", Color.WHITE)
            results = self._extender.checkSecurityHeaders(headers)
            for header, content, is_present in results:
                color = Color.GREEN if is_present else Color.RED
                text = u"\u2714 {}: {}\n".format(header, content) if is_present else u"\u2716 {}: Missing\n".format(header)
                self._appendText(doc, text, color)

            # Information Headers
            results = self._extender.checkInfoHeaders(headers)
            if results:
                self._appendText(doc, "\nInformation Headers:\n\n", Color.WHITE)
                for header, content, _ in results:
                    self._appendText(doc, u"\u2714 {}: {}\n".format(header, content), Color.RED)

        self._currentMessage = content

    def _appendText(self, doc, text, color):
        attr = SimpleAttributeSet()
        StyleConstants.setForeground(attr, color)
        try:
            doc.insertString(doc.getLength(), text, attr)
        except Exception as e:
            print("Error inserting text:", e)

    def getMessage(self):
        return self._currentMessage

    def isModified(self):
        return False

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
