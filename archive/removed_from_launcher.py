				fileslist = os.listdir(".")
				for file in fileslist:
					if file.lower().endswith(".py"):
						print(file)
				print("Enter the name of your application.")
				inp_app = input()
				app = "".join([str(appdir),str(app)])
				if os.path.isfile(app):
					appfullpath = app
					
		if os.path.getsize(configfile) == 0:
			raise ValueError("Configfile empty")
			
class Service:
	''' Manage services, command [mysqld, apache] '''
	try:
		def start(self):
			if sys.platform.startswith("win"):
				shellrun = subprocess.Popen(["net start", self.servicename])
			elif sys.platform.startswith('linux'):
				shellrun = subprocess.Popen([,"service", self.servicename,"start"])
			log("Start ", self.servicename)
		def stop(self):
			if sys.platform.startswith("win"):
				shellrun = subprocess.Popen(["net stop", self.servicename])
			elif sys.platform.startswith('linux'):
				shellrun = subprocess.Popen(["service", self.servicename,"stop"])
			log("Stop ", self.servicename)
		def restart(self):
			pass
		def status(self):
			if sys.platform.startswith("win"):
				log("Sorry this function unsupported for windows")
			elif sys.platform.startswith('linux'):
				shellrun = subprocess.Popen(["service", self.servicename,"status"])
	except OSError:
		print ("Administrator privileges are required. Run as administrator or root")

# mysqld
def start_mysqld():
	mysqld = Service()
	mysqld.servicename = "mysqld"
	mysqld.start()
def stop_mysqld():
	mysqld = Service()
	mysqld.servicename = "mysqld"
	mysqld.stop()
def restart_mysqld():
	mysqld = Service()
	mysqld.servicename = "mysqld"
	mysqld.restart()
def status_mysqld():
	mysqld = Service()
	mysqld.servicename = "mysqld"
	mysqld.status()
	
subf = Menu(m)
fl.add_cascade(label="Mysqld",menu=subf)
subf.add_command(label="Mysqld start",command=start_mysqld)
subf.add_command(label="Mysqld restart",command=restart_mysqld)
subf.add_command(label="Mysqld stop",command=stop_mysqld)
subf.add_command(label="Mysqld status",command=status_mysqld)

def check_port(address, port):
	"""" Check port is open, return True ro False"""
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#AF_INET - Socket Family (here Address Family version 4 or IPv4)
	#SOCK_STREAM - Socket type TCP connections
	#SOCK_DGRAM - Socket type UDP connections
	try:
		s.connect((address, port))
		log("".join([str(port), " port is open"]))
		s.close()
		return True
	except socket.error:
		log("".join([str(port), " port already used"]))
		return False

def TK_check_port():
	def sub_check():
		testport = port_entry.get()
		testport = int(testport)
		if check_port("127.0.0.1", testport):
			MessageBox.showinfo("Port","open")
		else:
			MessageBox.showinfo("Port","close")
	window = tk.Toplevel(root)
	tlabel = tk.Label(window, text="Type port to check")
	tlabel.pack()
	port_entry = tk.Entry(window, bd=3)
	port_entry.pack()
	ckeck_button = tk.Button(window, text="Check", command=sub_check)
	ckeck_button.pack()

def show_readme():
	""" Show README file"""
	os.chdir(appdir)
	helpfile = os.path.join(os.getcwd(), "README.txt")
	if os.path.isfile(helpfile):
		if sys.platform.startswith('win'):
			clear_log()
			show_log()
			# Show text in log area
			f = open(helpfile, "r")
			for line in f:
				text.insert('end', line)
			text.insert('end', '\n')
			f.close
		if sys.platform.startswith('lin'):
			with open(helpfile, 'r') as f:
				readme = f.read()
			f.close
			MessageBox.showinfo("Readme", readme)
	else:
		log("README file not found")
		
		
def get_pid(port=devserverport):
	"""
	Sub func. Get pid from listened port. Return int PID
	"""
	if sys.platform.startswith('win'):
		command = "{}{}".format('netstat -ano | findstr ', port)
		stdout = os.popen(command).read()
		print stdout
		if stdout:
			pid = (stdout[-5:-1]).replace(" ", "")
			return pid
	if sys.platform.startswith('lin'):
		command = "".join(["lsof -i:", str(port), " -t"])
		stdout = os.popen(command).read().split("\n")
		if stdout:
			del stdout[-1] # removes the last empty item
			return stdout

def start_app():
	""" Simple app runner. Launches the application if it is not running. """
	global runned
	os.chdir(appdir)
	if not os.path.isfile(appfullpath):
		log("App is not found. Check configfile or choose app file. (App > Choose app)")
	try:
		if runned != True:
			procapp = subprocess.Popen(["python", appfullpath])
			pid = get_pid()
			print pid
			statelabel['text'] = str(pid)
			runned = True
			log("Development server started")
	except OSError:
		print("OSError. Something wrong. Can't run application")
		log("OSError. Something wrong. Can't run application")
	except:
		print("Unexpected error:", sys.exc_info()[0])