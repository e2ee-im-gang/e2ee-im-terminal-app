import socket
import sys
import threading
import json
import sqlite3
import re
import hashlib
#possible exploit using random
#at this stage only used with salt so exploit very unlikely unless precomputed rainbow tables for a 5 character salt
import random
import string
import calendar
import time
from nacl.public import PublicKey, SealedBox
salt_chars = ''.join([string.punctuation, string.ascii_uppercase, string.ascii_lowercase, string.digits])
salt_len = 5
db_name = 'mydb.db'
port = 12981

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
			keygen_salt TEXT NOT NULL,
			server_salt TEXT NOT NULL)
			""")
		db.execute("""
			create table Devices
			(DeviceID INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			UserID INTEGER NOT NULL,
			PublicKey TEXT NOT NULL,
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
	#this leads to deadlock in container == container comparison
	def __eq__(self, other):
		self.lock.acquire()
		rv = self.data == other
		self.lock.release()
		return rv

class llnode:
	"""
	class used as a node in a doubly linked list
	"""
	def __init__(self, data):
		self.data = data
		self.next = None
		self.prev = None

class ll:
	"""
	class used to implement a doubly linked list
	"""
	def __init__(self):
		self.node_set = set()
		self.root = None
		self.tail = None

	def append(self, data):
		newnode = llnode(data)
		if self.root is None:
			self.root = newnode
			self.tail = newnode
		else:
			self.tail.next = newnode
			newnode.prev = self.tail
			self.tail = newnode
		self.node_set.add(newnode)

	def remove(self, node):
		if not isinstance(node, llnode):
			raise TypeError("Cannot remove %s datatype" % type(node))
		if node not in self.node_set:
			raise ValueError("Node not in linked list")
		self.node_set.remove(node)
		if node == self.root:
			self.root = node.next
		else:
			node.prev.next = node.next
		if node == self.tail:
			self.tail = node.prev
		else:
			node.next.prev = node.prev
	def __iter__(self):
		node = self.root
		while(node is not None):
			yield node
			node = node.next

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

def _exec_cmd_open(conn_info, user_info, rec_obj, db_info):
	conn, address = conn_info
	user_id, device_id = user_info
	mydb, db = db_info
	if len(rec_obj['args']) == 0:
		send(conn_info, {'error', 'argument length incorrect'})
		return
	db.execute("select ConversationID from Conversations where name=?",(rec_obj['args'][0],))
	record = db.fetchone()
	if record is None:
		send(conn_info, {'error':'no such conversation'})
		return
	conversation_id = record[0]
	db.execute("select * from UserConversationMap where UserID=? and ConversationID=?", (user_id, conversation_id))
	if db.fetchone() is None:
		send(conn_info, {'error': 'Conversation access restricted'})
		return
	msg = 'Opened Conversation'
	db.execute("""
		select datetime(senttime, 'unixepoch', 'localtime'), Users.username, MessageID
		from Messages
		left join Users on Users.UserID=SenderID
		where ConversationID=?
		""", (conversation_id,))
	record = db.fetchone()
	messages = ll()
	while(record is not None):
		messages.append({'senttime':record[0],'username':record[1],'digest':record[2]})
		record = db.fetchone()
	#handling case of some messages not being encrypted for the device yet
	for message in messages:
		db.execute("select contents from Digests where MessageID=? and DeviceID=?",(message.data['digest'],device_id))
		record = db.fetchone()
		if record is None:
			messages.remove(message)
		else:
			message.data['digest'] = record[0]
	db.execute("select UserID from UserConversationMap where ConversationID=?",(conversation_id,))
	user_ids = []
	record = db.fetchone()
	while(record is not None):
		user_ids.append(record[0])
		record = db.fetchone()
	public_keys = {}
	for i in range(len(user_ids)):
		db.execute("select DeviceID, PublicKey from Devices where UserID=?",(user_ids[i],))
		record = db.fetchone()
		while(record is not None):
			public_keys[record[0]] = record[1]
			record = db.fetchone()
	send(conn_info, {'msg':msg, 'ConversationID':conversation_id, 'messages':list(x.data for x in messages), 'PublicKeys':public_keys})

def _exec_cmd_ls(conn_info, user_info, rec_obj, db_info):
	user_id, device_id = user_info
	mydb, db = db_info
	db.execute("""
		select Conversations.name
		from UserConversationMap
		left join Conversations on UserConversationMap.ConversationID=Conversations.ConversationID
		where UserID=?""", (user_id,))
	msg = ['Conversations:']
	record = db.fetchone()
	while(record is not None):
		msg.append(record[0])
		record = db.fetchone()
	msg = '\n'.join(msg)
	send(conn_info, {'msg':msg})

def _exec_cmd_refresh(conn_info, user_info, rec_obj, db_info):
	conn, address = conn_info
	user_id, device_id = user_info
	mydb, db = db_info
	if(len(rec_obj['args']) < 1):
		send(conn_info, {'error':"argument length incorrect"})
		return
	try:
		conversation_id = int(rec_obj['args'][0])
	except ValueError:
		send(conn_info, {'error':'could not convert ConversationID to valid value'})
		return
	db.execute("select * from UserConversationMap where UserID=? and ConversationID=?", (user_id, conversation_id))
	if db.fetchone() is None:
		send(conn_info, {'error': 'Conversation access restricted'})
		return
	db.execute("""
		select datetime(senttime, 'unixepoch', 'localtime'), Users.username, MessageID
		from Messages
		left join Users on Users.UserID=SenderID
		where ConversationID=?
		""", (conversation_id,))
	record = db.fetchone()
	messages = ll()
	while(record is not None):
		messages.append({'senttime':record[0],'username':record[1],'digest':record[2]})
		record = db.fetchone()
	#handling case of some messages not being encrypted for the device yet
	for message in messages:
		db.execute("select contents from Digests where MessageID=? and DeviceID=?",(message.data['digest'],device_id))
		record = db.fetchone()
		if record is None:
			messages.remove(message)
		else:
			message.data['digest'] = record[0]
	send(conn_info, {'messages':list(x.data for x in messages)})

def _exec_cmd_newcon(conn_info, user_info, rec_obj, db_info):
	conn, address = conn_info
	user_id, device_id = user_info
	mydb, db = db_info
	if(len(rec_obj['args']) <= 1):
		send(conn_info, {'error': 'argument length incorrect'})
		return
	conversation_name = rec_obj['args'][0]
	db.execute("select * from Conversations where name=?", (conversation_name,))
	if db.fetchone() is not None:
		send(conn_info, {'error':'Conversation name is not unique'})
		return
	false_users = set()
	correct_users = set()
	db.execute("select username from Users where UserID=?", (user_id,))
	correct_users.add(db.fetchone()[0])
	for arg in rec_obj['args'][1:]:
		db.execute("select * from Users where username=?", (arg,))
		if db.fetchone() is None:
			false_users.add(arg)
		else:
			correct_users.add(arg)
	if(len(false_users) == 0):
		db.execute("insert into Conversations (name) values (?)", (conversation_name,))
		db.execute("select ConversationID from Conversations where name=?", (conversation_name,))
		conversation_id = db.fetchone()[0]
		for user in correct_users:
			db.execute("select UserID from Users where username=?", (user,))
			tempid = db.fetchone()[0]
			db.execute("insert into UserConversationMap (UserID, ConversationID) values (?,?)", (tempid, conversation_id))
		mydb.commit()
		send(conn_info, {'msg': 'Conversation "%s" successfully created' % conversation_name})
	else:
		msg = 'User%s %s %s not found' % ('s' if len(false_users) > 1 else '', ' '.join(false_users), 'were' if len(false_users) > 1 else 'was')
		send(conn_info, {'error': msg})


def _exec_cmd(conn_info, user_info, rec_obj, db_info):
	conn, address = conn_info
	user_id, device_id = user_info
	mydb, db = db_info
	if 'args' not in rec_obj:
		print('invalid request from:', address)
		send(conn_info, {'error':'missing args'})
		return
	if not isinstance(rec_obj['args'], list):
		print('invalid request from:', address)
		send(conn_info, {'error':'args TypeError'})
		return
	if not all(isinstance(arg, str) for arg in rec_obj['args']):
		print('invalid request from:', address)
		send(conn_info, {'error':'args TypeError'})
		return
	if rec_obj['cmd'] == 'open':
		_exec_cmd_open(conn_info, user_info, rec_obj, db_info)
	elif rec_obj['cmd'] == 'ls':
		_exec_cmd_ls(conn_info, user_info, rec_obj, db_info)
	elif rec_obj['cmd'] == 'refresh':
		_exec_cmd_refresh(conn_info, user_info, rec_obj, db_info)
	elif rec_obj['cmd'] == 'newcon':
		_exec_cmd_newcon(conn_info, user_info, rec_obj, db_info)
	else:
		print('unknown cmd:', rec_obj['cmd'])
		send(conn_info, {'error':'unknown cmd'})

def _store_digests(conn_info, user_info, rec_obj, db_info):
	conn, address = conn_info
	user_id, device_id = user_info
	mydb, db = db_info
	#this is where encryption needs to be added
	if 'ConversationID' not in rec_obj:
		print('invalid request from:', address)
		send(conn_info, {'error': 'missing ConversationID'})
		return
	if not isinstance(rec_obj['ConversationID'], int):
		print('invalid request from:', address)
		send(conn_info, {'error': 'ConversationID TypeError'})
		return
	if not isinstance(rec_obj['digests'], dict):
		print('invalid request from:', address)
		send(conn_info, {'error': 'digests TypeError'})
		return
	conversation_id = rec_obj['ConversationID']
	db.execute("select * from UserConversationMap where UserID=? and ConversationID=?", (user_id, conversation_id))
	if(db.fetchone() is None):
		send(conn_info, {'error':'Conversation access restricted'})
		return
	db.execute("select UserID from UserConversationMap where ConversationID=?", (conversation_id,))
	record = db.fetchone()
	user_ids = []
	while(record is not None):
		user_ids.append(record[0])
		record = db.fetchone()
	id_set = set()
	for i in range(len(user_ids)):
		db.execute("select DeviceID from Devices where UserID=?",(user_ids[i],))
		record = db.fetchone()
		while(record is not None):
			id_set.add(str(record[0]))
			record = db.fetchone()
	if set(rec_obj['digests'].keys()) != id_set:
		send(conn_info, {'error': 'digest keys did not match conversation keys'})
		return
	senttime = calendar.timegm(time.gmtime())
	db.execute("insert into Messages (SenderID, ConversationID, senttime) values (?,?,?)",
		(user_id, conversation_id, senttime))
	message_id = db.lastrowid
	for key in rec_obj['digests']:
		db.execute("insert into Digests (MessageID, DeviceID, contents) values (?,?,?)", (message_id, key, rec_obj['digests'][key]))
	mydb.commit()
	send(conn_info, {'status':200})


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
	db.execute("select hash, client_salt, keygen_salt, server_salt from Users where username=?", (username,))
	record = db.fetchone()
	if record is None:
		client_salt = ''.join(random.choice(salt_chars) for _ in range(salt_len))
		keygen_salt = ''.join(random.choice(salt_chars) for _ in range(salt_len))
		to_send = {'action':'create', 'args':['Creating new user: %s please enter a password:\n' % username,client_salt, keygen_salt]}
		rec_obj = sendrec(conn_info, to_send, expected_rv_keys=['hash','PublicKey'])
		server_salt = ''.join(random.choice(salt_chars) for _ in range(salt_len))
		to_hash = rec_obj['hash'].encode() + server_salt.encode()
		pw_hash = hashlib.sha3_256(to_hash).digest()
		#convert byte string to utf-8 encodable representation
		hash_str = ''.join('{:02x}'.format(c) for c in pw_hash)
		db.execute('insert into Users (username, hash, client_salt, keygen_salt, server_salt) values (?,?,?,?,?)', (username, pw_hash, client_salt, keygen_salt, server_salt))
		db.execute('select UserID from Users where username=?', (username,))
		record = db.fetchone()
		user_id = record[0]
		db.execute('insert into Devices (name, UserID, PublicKey) values (?,?,?)',('Browser',user_id,rec_obj['PublicKey']))
		mydb.commit()
	else:
		authenticated = False
		prompt = 'Password:'
		while not authenticated:
			to_send = {'action':'password', 'args':[prompt,record[1], record[2]]}
			rec_obj = sendrec(conn_info, to_send, expected_rv_keys=['hash'])
			if rec_obj is None:
				mydb.commit()
				mydb.close()
				connection.close()
				return
			if not isinstance(rec_obj['hash'], str):
				print('request provided wrong datatype from ({})'.format(address))
				mydb.commit()
				mydb.close()
				connection.close()
				return
			to_hash = rec_obj['hash'].encode() + record[3].encode()
			pw_hash = hashlib.sha3_256(to_hash).digest()
			if pw_hash == record[0]:
				authenticated = True
				break
			prompt = 'Incorrect please re-enter your password:'
	send(conn_info, {'action':'start_requests', 'msg':'Welcome %s\n' % username})
	db.execute("select UserID from Users where username=?", (username,))
	#will never fail as username has been verified to exist
	#possible race condition when username changing is added
	user_id = db.fetchone()[0]
	#temporary as treating every connection as a browser with no persistance
	db.execute("select DeviceID from Devices where UserID=? and name='Browser'", (user_id,))
	device_id = db.fetchone()[0]
	db_info = mydb, db
	user_info = user_id, device_id
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
			_exec_cmd(conn_info, user_info, rec_obj, db_info)
		elif 'digests' in rec_obj:
			_store_digests(conn_info, user_info, rec_obj, db_info)
		else:
			print('invalid request from:', address)
			send(conn_info, {'error':'invalid_request'})

	connection.close()
	mydb.commit()
	mydb.close()


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
		close_server: threadsafe container for checking to exit
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
	threads = ll()
	while(close_server == False):
		try:
			conn, addr = sock.accept()
		except socket.timeout:
			for thread in threads:
				if not thread.data.is_alive():
					thread.data.join()
					threads.remove(thread)
			continue
		new_thread = threading.Thread(target=connection_thread, args=(conn,addr))
		print('new connection from:', addr)
		new_thread.start()
		threads.append(new_thread)
	for thread in threads:
		thread.data.join()

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
