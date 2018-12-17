# -*-coding:utf-8 -*-
import rsa
import base64
import java.lang as lang
from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from javax import swing
from java.awt import Color
from java.awt import Font


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

	def registerExtenderCallbacks(self, callbacks):
		self._title = "RSA Plugin"
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self._callbacks.setExtensionName(self._title)
		self.initGui()
		self._callbacks.addSuiteTab(self)
		self._callbacks.registerContextMenuFactory(self)
		self.typeString = ["PublicKey Encrypt ", "PublicKey Decrypt ", "PrivateKey Encrypt ", "PrivateKey Decrypt "]
		self.buttonStatus = ["Disabled", "Enabled"]
		self.autoReplaceStuts = False
		self.urlcodeEnableStuts = False
		self.PublicKey = ""
		self.PrivateKey = ""

	# ---------------------
	#       UI
	# ---------------------

	def initGui(self):
		self.tab = swing.JPanel()
		layout = swing.GroupLayout(self.tab)
		self.tab.setLayout(layout)
		self.titleLabel = swing.JLabel("RSA Plugin")
		self.titleLabel.setFont(Font("Tahoma", 1, 16))
 		self.titleLabel.setForeground(Color(235,136,0))
		self.infoLabel = swing.JLabel("Try to use eazier by use custom cotext menu button for RSA en/decode.")
		self.infoLabel.setFont(Font("Tahoma", 0, 12))
		self.attentionLabel = swing.JLabel("[!] Response auto-replace JUST SUPPORT in 'Proxy-Intercept', most time try to use 'xxx -- Request' Button.")
		self.attentionLabel.setFont(Font("Tahoma", 1, 12))
 		self.attentionLabel.setForeground(Color(255,0,0))
		self.attention2Label = swing.JLabel("[*] ONlY SUPPORT PKCS#1, you could trans PKCS#8 to PKCS#1 for use this extension.")
		self.attention2Label.setFont(Font("Tahoma", 1, 12))
 		self.attention2Label.setForeground(Color(255,0,0))
		self.keyLabel = swing.JLabel("RSA keys")
		self.keyLabel.setFont(Font("Tahoma", 1, 12))
		self.rsapublickeyLabel = swing.JLabel("PublicKey")
		self.rsapublickeyTextArea = swing.JTextArea("")
		self.rsaprivatekeyLabel = swing.JLabel("PrivateKey")
		self.rsaprivatekeyTextArea = swing.JTextArea("")
		self.setkeyButton = swing.JButton("Set", actionPerformed=self.setOptions)
		self.generateButton = swing.JButton("Generate", actionPerformed=self.generateKeys)
		self.settingLabel = swing.JLabel("Settings")
		self.settingLabel.setFont(Font("Tahoma", 1, 12))
		self.autoreplaceCheckBox = swing.JCheckBox("Auto Replace (auto replace the words selected with the RSA result)", actionPerformed=self.autoReplaceCheck)
		self.urlcodeenableCheckBox = swing.JCheckBox("Urlcode Enable (use for data has been base64 en/decoded)", actionPerformed=self.urlcodeEnableCheck)
		self.logLabel = swing.JLabel("Log")
		self.logLabel.setFont(Font("Tahoma", 1, 12))
		self.logPane = swing.JScrollPane()
		self.logArea = swing.JTextArea("RSA Log - Every action's info will be appended here.\n")
		self.logArea.setLineWrap(True)
		self.logPane.setViewportView(self.logArea)
		self.logClearButton = swing.JButton("Clear", actionPerformed=self.logClear)
		self.bar = swing.JSeparator(swing.SwingConstants.HORIZONTAL)
		self.bar2 = swing.JSeparator(swing.SwingConstants.HORIZONTAL)
		self.bar3 = swing.JSeparator(swing.SwingConstants.HORIZONTAL)
		# 设置水平布局
		layout.setHorizontalGroup(
			layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup()
				.addGap(15)
				.addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
					.addComponent(self.titleLabel)
					.addComponent(self.infoLabel)
					.addComponent(self.attentionLabel)
					.addComponent(self.attention2Label)
					.addComponent(self.bar)
					.addComponent(self.keyLabel)
					.addGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup()
							.addComponent(self.setkeyButton)
							.addComponent(self.generateButton))
						.addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(layout.createParallelGroup()
							.addComponent(self.rsapublickeyLabel)
							.addComponent(self.rsapublickeyTextArea, swing.GroupLayout.PREFERRED_SIZE, 500, swing.GroupLayout.PREFERRED_SIZE))
						.addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(layout.createParallelGroup()
							.addComponent(self.rsaprivatekeyLabel)
							.addComponent(self.rsaprivatekeyTextArea, swing.GroupLayout.PREFERRED_SIZE, 500, swing.GroupLayout.PREFERRED_SIZE)))
					.addComponent(self.bar2)
					.addGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup()
							.addComponent(self.settingLabel))
						.addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(layout.createParallelGroup()
							.addComponent(self.autoreplaceCheckBox)
							.addComponent(self.urlcodeenableCheckBox)))
					.addComponent(self.bar3)
					.addComponent(self.logLabel)
					.addGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup()
							.addComponent(self.logClearButton))
						.addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(layout.createParallelGroup()
							.addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 1100, swing.GroupLayout.PREFERRED_SIZE)))
					)))
		# 设置垂直布局
		layout.setVerticalGroup(
			layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup()
				.addGap(15)
				.addComponent(self.titleLabel)
				.addGap(10)
				.addComponent(self.infoLabel)
				.addGap(10)
				.addComponent(self.attentionLabel)
				.addGap(10)
				.addComponent(self.attention2Label)
				.addGap(10)
				.addComponent(self.bar)
				.addGap(10)
				.addComponent(self.keyLabel)
				.addGap(10)
				.addGroup(layout.createSequentialGroup()
					.addGroup(layout.createParallelGroup()
						.addComponent(self.rsapublickeyLabel)
						.addComponent(self.rsaprivatekeyLabel))
					.addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
					.addGroup(layout.createParallelGroup()
						.addGroup(layout.createSequentialGroup()
							.addComponent(self.setkeyButton)
							.addGap(20)
							.addComponent(self.generateButton))
						.addComponent(self.rsapublickeyTextArea, swing.GroupLayout.PREFERRED_SIZE, 250, swing.GroupLayout.PREFERRED_SIZE)
						.addComponent(self.rsaprivatekeyTextArea, swing.GroupLayout.PREFERRED_SIZE, 250, swing.GroupLayout.PREFERRED_SIZE)))
				.addGap(10)
				.addComponent(self.bar2)
				.addGap(10)
				.addGroup(layout.createSequentialGroup()
					.addGroup(layout.createParallelGroup()
						.addComponent(self.settingLabel))
					.addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
					.addGroup(layout.createSequentialGroup()
						.addComponent(self.autoreplaceCheckBox)
						.addGap(5)
						.addComponent(self.urlcodeenableCheckBox)))
				.addGap(10)
				.addComponent(self.bar3)
				.addGap(10)
				.addComponent(self.logLabel)
				.addGap(10)
				.addGroup(layout.createParallelGroup()
					.addComponent(self.logClearButton)
					.addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 400, swing.GroupLayout.PREFERRED_SIZE))
				))
		# 向 BURP 添加 UI 要素，getUiComponent和这个函数二选一即可
		# self._callbacks.customizeUiComponent(self.tab)
	
	# 必需，用于设置 Tab 名
	def getTabCaption(self):
		return "RSA Plugin" 

	# 用于点击 Tab 时显示 UI 界面
	def getUiComponent(self):
		return self.tab

	# ---------------------
	#       Menu
	# ---------------------

	def createMenuItems(self, invocation):
		self._invocation = invocation
		self._messages_index = self._invocation.getSelectionBounds()
		self._messages = self._invocation.getSelectedMessages()
		top_menu = swing.JMenu(self._title)
		menus = [
			swing.JMenuItem("publicKey Ecrypt    -- Request", actionPerformed=self.rasPubEnRq),
			swing.JMenuItem("publicKey Decrypt  -- Request", actionPerformed=self.rsapubdeRq),
			swing.JMenuItem("privateKey Encrypt -- Request", actionPerformed=self.rsaprienRq),
			swing.JMenuItem("privateKey Decrypt -- Request", actionPerformed=self.rsaprideRq),
			swing.JMenuItem("publicKey Ecrypt     -- Response", actionPerformed=self.rasPubEnRp),
			swing.JMenuItem("publicKey Decrypt  -- Response", actionPerformed=self.rsapubdeRp),
			swing.JMenuItem("privateKey Encrypt -- Response", actionPerformed=self.rsaprienRp),
			swing.JMenuItem("privateKey Decrypt -- Response", actionPerformed=self.rsaprideRp)
		]
		for _item in menus :
			top_menu.add(_item)
		return [top_menu]

	# ---------------------
	#       Events
	# ---------------------

	def setOptions(self, event):
		pubText = self.rsapublickeyTextArea.getText().strip('\n')
		if pubText != None and len(pubText) > 0:
			status = False
			try:
				self.PublicKey = rsa.PublicKey.load_pkcs1(pubText)
				status = True
			except:
				pass
			self.info_print(status, "set Public Key.")

		priText = self.rsaprivatekeyTextArea.getText().strip('\n')
		if priText != None and len(priText) > 0:
			status = False
			try:
				self.PrivateKey = rsa.PrivateKey.load_pkcs1(priText)
				status = True
			except:
				pass
			self.info_print(status, "set Private Key.")

	def generateKeys(self,event):
		status = False
		try:
			(pubkey, privkey) = rsa.newkeys(1024)
			self.rsapublickeyTextArea.setText(pubkey.save_pkcs1().decode())
			self.rsaprivatekeyTextArea.setText(privkey.save_pkcs1().decode())
			status = True
		except:
			pass
		self.info_print(status, "Generate Keys.")
		self.setOptions(None)

	def logClear(self, event):
		self.logArea.setText("")

	def autoReplaceCheck(self, event):
		status = False
		try:
			self.autoReplaceStuts = self.autoreplaceCheckBox.isSelected()
			status = True
		except:
			pass
		self.info_print(status, "AutoReplace is %s."%(self.buttonStatus[self.autoReplaceStuts]))
	
	def urlcodeEnableCheck(self, event):
		status = False
		try:
			self.urlcodeEnableStuts = self.urlcodeenableCheckBox.isSelected()
			status = True
		except:
			pass
		self.info_print(status, "Urlcode is %s."%(self.buttonStatus[self.urlcodeEnableStuts]))

	# ---------------------
	#       Methods
	# ---------------------

	"""
	@param method:	0 - Request
					1 - Response
	@return: String
	"""
	def getSelectedMessagesString(self, method):
		if method == 0:
			self._tmpService = self._messages[0].getRequest()
		elif method == 1:
			self._tmpService = self._messages[0].getResponse()
		self._tmpText = self._tmpService[self._messages_index[0]:self._messages_index[1]].tostring()
		return self._tmpText

	# Request button event
	def rasPubEnRq(self, event):
		self.rsa_func(0, 0)

	def rsapubdeRq(self, event):
		self.rsa_func(1, 0)
	
	def rsaprienRq(self, event):
		self.rsa_func(2, 0)

	def rsaprideRq(self, event):
		self.rsa_func(3, 0)

	# Response button event
	def rasPubEnRp(self, event):
		self.rsa_func(0, 1)

	def rsapubdeRp(self, event):
		self.rsa_func(1, 1)
	
	def rsaprienRp(self, event):
		self.rsa_func(2, 1)

	def rsaprideRp(self, event):
		self.rsa_func(3, 1)

	"""
	@param type:	0 - PublicKey Encrypt
					1 - PublicKey Decrypt
					2 - PrivateKey Encrypt
					3 - PrivateKey Decrypt
	@param servietype:	0 - Request
						1 - Response
	"""
	def rsa_func(self, type, servietype):
		status = False
		typeList = [self.PublicKey, self.PrivateKey]
		data = self.getSelectedMessagesString(servietype)
		try:
			if self.urlcodeEnableStuts is True:
				data = self._helpers.urlDecode(data).replace('\n','')
			if type == 0 or type == 2:
				data = rsa.encrypt(data.encode('utf-8'), typeList[type%2])
				data = base64.encodestring(data)
			elif type == 1 or type == 3:
				data = base64.decodestring(data.encode('utf-8'))
				data = rsa.decrypt(data, typeList[type%2]).decode()
			if self.urlcodeEnableStuts is True:
				data = self._helpers.urlEncode(data).replace('\n','')
			status = True
		except:
			pass
		data = data.replace("\n", "")
		self.info_print(status, ''.join([self.typeString[type], self._tmpText," --->>> ", data]))
		self.replaceText(data, status, servietype)

	def replaceText(self, data, status, servietype):
		if self.autoReplaceStuts is True and status is True:
			new_text = self._tmpService[:self._messages_index[0]] + self._helpers.stringToBytes(data) + self._tmpService[self._messages_index[1]:]
			if servietype == 0:
				self._messages[0].setRequest(new_text)
			elif servietype == 1:
				self._messages[0].setResponse(new_text)

	def info_print(self, status, data):
		statusList = ["[!] Failure: ", "[+] Success: "]
		message = statusList[status] + data
		self.logArea.append(message+'\n')
