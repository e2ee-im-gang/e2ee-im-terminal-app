import socket
import sys
import threading
import json
import sqlite3
import re
import hashlib
#possible exploit using random
#at this stage only used with salt so no exploit
import random
import string
salt_chars = ''.join([string.punctuation, string.ascii_uppercase, string.ascii_lowercase, string.digits])
salt_len = 5
db_name = 'mydb.db'
def setup_db():
	mydb = sqlite3.connect(db_name)
	db = mydb.cursor()
	#try creating tables
	#if tables already exist then this will error out
	#delete contents from Messages table when adding encryption
	try:
		db.execute("""
			create table Users
			(UserID INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			hash TEXT NOT NULL,
			client_salt TEXT NOT NULL,
			server_salt TEXT NOT NULL)
			""")
		db.execute("""
			create table Devices
			(DeviceID INTEGER PRIMARY KEY AUTOINCREMENT,
			UserID INTEGER NOT NULL,
			RSAKey TEXT NOT NULL,
			FOREIGN KEY(UserID) REFERENCES Users(UserID))
			""")
		db.execute("""
			create table Conversations
			(ConversationID INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE)
			""")
		db.execute("""
			create table UserConversationMap
			(UserConversationMapID INTEGER PRIMARY KEY AUTOINCREMENT,
			UserID INTEGER NOT NULL,
			ConversationID INTEGER NOT NULL,
			FOREIGN KEY(UserID) REFERENCES Users(UserID),
			FOREIGN KEY(ConversationID) REFERENCES Conversations(ConversationID))
			""")
		db.execute("""
			create table Messages
			(MessageID INTEGER PRIMARY KEY AUTOINCREMENT,
			SenderID INTEGER NOT NULL,
			ConversationID INTEGER NOT NULL,
			senttime INTEGER NOT NULL,
			contents TEXT NOT NULL,
			FOREIGN KEY(SenderID) REFERENCES users(USERID),
			FOREIGN KEY(ConversationID) REFERENCES Conversations(ConversationID))
			""")
		db.execute("""
			create table Digests
			(DigestID INTEGER PRIMARY KEY AUTOINCREMENT,
			MessageID INTEGER NOT NULL,
			DeviceID INTEGER NOT NULL,
			contents TEXT NOT NULL,
			FOREIGN KEY(MessageID) REFERENCES Messages(MessageID),
			FOREIGN KEY(DeviceID) REFERENCES Devices(DeviceID))
			""")
		mydb.commit()
	except:
		pass
	mydb.close()

setup_db()
port = 12981

def sendrec(conn_info, send_obj, expected_rv_keys=[]):
	"""
	Function to send json object and wait for a response
	expecting the response to be in the form of a json object.
	Args:
		conn_info: tuple of socket connection and address (address for debug/logging)
		send_obj: python dictionary to send as json object
		expected_rv_keys: keys required from the return object (empty as default)
	Returns:
		python dictionary representation of received json object
		or None if an error ocurred
	"""
	#possibly enforce string only values in objects
	connection, address = conn_info
	to_send = json.dumps(send_obj)
	connection.send(to_send.encode())
	rec_buff = connection.recv(4096**2).decode()
	if(len(rec_buff) == 0):
		connection.close()
		return
	try:
		rv = json.loads(rec_buff)
	except json.JSONDecodeError:
		print('invalid request from', address, 'closing connection')
		connection.close()
		return
	for key in expected_rv_keys:
		if key not in rv:
			print('request did not provide required return parameter({0}) from ({1})'.format(key, address))
			connection.close()
			return
	return rv

def send(conn_info, send_obj):
	"""
	Function to send json object without receiving a response
	Args:
		conn_info: tuple of socket connection and address (address for debug/logging)
		send_obj: python dictionary to send as json object
		expected_rv_keys: keys required from the return object (empty as default)
	Returns:
		None
	"""
	connection, address = conn_info
	to_send = json.dumps(send_obj)
	connection.send(to_send.encode())

def connection_thread(connection, address=None):
	"""
	Intended to be run whenever a new connection is established,
	facilitating the communication between the server and this device
	Args:
		connection: socket connection
		address: address for debug purposes associated with connection
	Returns:
		None
	"""
	#TODO:
	#wrap in a context manager for the socket connection and db connection
	mydb = sqlite3.connect(db_name)
	db = mydb.cursor()
	welcome_msg = """
Welcome to the terminal E2EE IM app
please enter a username:"""
	conn_info = (connection, address)
	to_send = {'msg':welcome_msg, 'action':'input'}
	rec_obj = sendrec(conn_info, to_send, expected_rv_keys=['input'])
	if rec_obj is None:
		mydb.commit()
		mydb.close()
		connection.close()
		return
	is_safe = True
	for c in rec_obj['input']:
		if not (c.isdigit() or c.isalpha()):
			is_safe = False
			break
	while not is_safe:
		is_safe = True
		to_send = {'msg':'Username contained non-alphanumeric characters, please re-enter', 'action':'input'}
		rec_obj = sendrec(conn_info, to_send, expected_rv_keys=['input'])
		for c in rec_obj['input']:
			if not (c.isdigit() or c.isalpha()):
				is_safe = False
				break
	username = rec_obj['input'].lower()
	db.execute("select * from Users where username=?", (username,))
	record = db.fetchone()
	if record is None:
		client_salt = ''.join(random.choice(salt_chars) for _ in range(salt_len))
		to_send = {'msg':'Creating new user: {} please enter a password:\n'.format(username), 'action':'password', 'args':[client_salt]}
		rec_obj = sendrec(conn_info, to_send, expected_rv_keys=['hash'])
		server_salt = ''.join(random.choice(salt_chars) for _ in range(salt_len))
		to_hash = rec_obj['hash'].encode() + server_salt.encode()
		pw_hash = hashlib.sha3_256(to_hash).digest()
		#convert byte string to utf-8 encodable representation
		hash_str = ''.join('{:02x}'.format(c) for c in pw_hash)
		db.execute('insert into Users (username, hash, client_salt, server_salt) values (?,?,?,?)', (username, pw_hash, client_salt, server_salt))
	else:
		authenticated = False
		msg = 'password:'
		while not authenticated:
			to_send = {'msg':msg, 'action':'password', 'args':[record[3]]}
			rec_obj = sendrec(conn_info, to_send, expected_rv_keys=['hash'])
			if rec_obj is None:
				mydb.commit()
				mydb.close()
				connection.close()
				return
			if(type(rec_obj['hash']) != str):
				print('request provided wrong datatype from ({})'.format(address))
				mydb.commit()
				mydb.close()
				connection.close()
				return
			to_hash = rec_obj['hash'].encode() + record[4].encode()
			pw_hash = hashlib.sha3_256(to_hash).digest()
			if pw_hash == record[2]:
				authenticated = True
				break
			msg = 'incorrect please re-enter your password:'
	db.execute("select UserID from Users where username=?", username)
	#will never fail as username has been verified to exist
	#possible race condition when username changing is added
	user_id = db.fetchone()[0]
	while(True):
		try:
			#issue with buffersize, will fix later
			rec_buff = connection.recv(4096**2).decode()
		except Exception as e:
			print(e)
			break
		if(len(rec_buff) == 0):
			break
		try:
			rec_obj = json.loads(rec_buff)
		except json.JSONDecodeError:
			print(e, 'from address:', address)
			send(conn_info,{'error':'invalid json'})
			continue
		if 'cmd' in rec_obj:
			if 'args' not in rec_obj:
				print('invalid request from:', address)
				send(conn_info, {'error':'missing args'})
			else:
				if rec_obj['cmd'] == 'open':
					if len(rec_obj['args'] > 0):
						#sqlite sanitises this socket no sqli possible
						db.execute("select ConversationID from Conversations where name=?",(rec_obj['args'][0],))
						record = db.fetchone()
						if record is None:
							send(conn_info, {'error':'no such conversation'})
						else:
							conversation_id = record[0]
							db.execute("select ConversationMappingID from Conversations where UserID=? and ConversationID=?", (user_id, conversation_id))
							record = db.fetchone()
							if record is None:
								send(conn_info, {'error': 'no such conversation'})
							else:
								msg = ['Opened Conversation']
								db.execute("""
									select Users.username, datetime(senttime, 'unixepoch', 'localtime'), contents
									from Messages
									where ConversationID=?
									left join Users on Users.UserID=SenderID
									""", (conversation_id,))
								record = db.fetchone()
								while(record is not None):
									msg.append('%s@%s>%s' % record)
									db.fetchone()
								msg = '\n'.join(record)
								send(conn_info, {'msg':msg})
				elif rec_obj['cmd'] == 'ls':
					db.execute("select Conversations.name from UserConversationMap where UserID=? left join Conversations on Conversations.ConverationID=ConversationID")
					msg = []
					record = db.fetchone()
					while(record is not None):
						msg.append(record[0])
						record = db.fetchone()
				elif rec_obj['cmd'] == 'refresh':
					pass
				else:
					print('unknown cmd:', rec_obj['cmd'])
					send(conn_info, {'error':'unknown cmd'})


	connection.close()
	mydb.commit()
	mydb.close()

class Threadsafe_Container:
	"""
	class used to wrap data with thread-safe primitive functionality
	"""
	def __init__(self, data):
		self.lock = threading.Lock()
		self.data = data
	def set(self, new_val):
		self.lock.acquire()
		self.data = new_val
		self.lock.release()
	def __eq__(self, other):
		self.lock.acquire()
		rv = self.data == other
		self.lock.release()
		return rv

def server_cmd_handler(close_server):
	while(close_server == False):
		args = input().split()
		if(len(args) == 0):
			continue
		cmd = args.pop(0)
		if cmd == 'exit':
			close_server.set(True)
			return
		#additional commands can be added here
		#if it gets too large, can change from if else to more efficient structure
		else:
			print('unrecognised command: {}'.format(cmd))

def connection_handler(close_server):
	"""
	Handler for connections to server
	Args:
		close_server: threadsafe datatype for checking to exit
	Return:
		None
	"""
	try:
		sock = socket.socket()
	except socket.error as err:
		print('socket creation failed with error: %s', err)
		close_server.set(True)
		return
	sock.settimeout(5)
	sock.bind(('localhost', port))
	sock.listen(5)
	#change threads to linked list later
	threads = []
	while(close_server == False):
		try:
			conn, addr = sock.accept()
		except socket.timeout:
			continue
		new_thread = threading.Thread(target=connection_thread, args=(conn,addr))
		print('new connection from:', addr)
		new_thread.start()
		threads.append(new_thread)
	for thread in threads:
		thread.join()

def main():
	close_server = Threadsafe_Container(False)
	connection_handler_thread = threading.Thread(target=connection_handler, args=(close_server,))
	server_cmd_handler_thread = threading.Thread(target=server_cmd_handler, args=(close_server,))
	connection_handler_thread.start()
	server_cmd_handler_thread.start()
	print('server started')
	connection_handler_thread.join()
	server_cmd_handler_thread.join()
	print('server exitting')


if __name__ == '__main__':
	main()