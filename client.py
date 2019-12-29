import socket
import sys
import json
import hashlib
import getpass
port = 12981
help_string = """
TERMINAL-IM-APP-CLIENT v0.1

Commands:
ls\tlists conversations
open <conversation_name>\t opens a conversation
close\t closes current conversation
newcon <conversation_name> <user1> [user1 user2 ...]\t creates new conversation
refresh\t reloads the contents of the conversation

To enter a command when a conversation is open prepend the command with ::
Example... ::refresh
"""

try:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as err:
	print('socket creation failed with error:', err)
	sys.exit(1)

try:
	sock.connect(('localhost', port))
except Exception as err:
	print(err)
	sys.exit(1)

#will be a bug with buffersize but will address later
while(True):
	try:
		contents_buff = sock.recv(4096**2).decode()
		if(len(contents_buff) == 0):
			break
		contents = json.loads(contents_buff)
		to_send = {}
		if 'msg' in contents:
			print(contents['msg'],end='')
		if 'action' in contents:
			if contents['action'] == 'input':
				req_input = input()
				to_send['input'] = req_input
			elif contents['action'] == 'password':
				req_input = getpass.getpass(contents['args'][0])
				to_hash = req_input.encode() + contents['args'][1].encode()
				pw_hash = hashlib.sha3_256(to_hash).digest()
				#convert byte string to utf-8 encodable representation
				to_send['hash'] = ''.join('{:02x}'.format(c) for c in pw_hash)
			elif contents['action'] == 'exit':
				sock.close()
				sys.exit(1)
			elif contents['action'] == 'start_requests':
				break
		sock.send(json.dumps(to_send).encode())
	except Exception as e:
		print(e)
		sys.exit(1)

def request(socket, to_send):
	socket.send(json.dumps(to_send).encode())
	rec_obj = json.loads(socket.recv(4096**2).decode())
	return rec_obj

def handle_cmd(text, convoID, sock):
	args = text.split()
	cmd = args.pop(0)
	to_send = {}
	if cmd == 'open':
		to_send = {'cmd':'open', 'args':args}
	elif cmd == 'close':
		if convoID is not None:
			to_send = {'cmd':'ls', 'args':[]}
			convoID = None
		else:
			print('no conversation to close')
			return None
	elif cmd == 'ls':
		if convoID is None:
			to_send = {'cmd':'ls', 'args':args}
		else:
			print('close conversation to view other conversations')
			return convoID
	elif cmd == 'refresh':
		if convoID is not None:
			to_send = {'cmd':'refresh', 'args':[str(convoID)]}
		else:
			print('refresh requires an open conversation')
			return convoID
	elif cmd == 'newcon':
		if(len(args) < 2):
			print('usage: newcon <conversation_name> [username1, username2, ...]')
			return convoID
		else:
			to_send = {'cmd':'newcon', 'args':args}
	elif cmd == 'help':
		print(help_string)
		return convoID
	else:
		print('unknown command:', cmd)
		return convoID
	response = request(sock, to_send)
	if('error' in response):
		print('Error:', response['error'])
	if('msg' in response):
		print(response['msg'])
	if('ConversationID' in response):
		convoID = response['ConversationID']
	return convoID


convoID = None
while(True):
	text = input()
	if(len(text) == 0):
		continue
	if convoID is not None:
		if len(text) > 1:
			if(text[:2] == '::'):
				if text[2::] == 'exit':
					break
				convoID = handle_cmd(text[2:], convoID, sock)
				continue
		response = request(sock, {'msg':text, 'ConversationID':convoID})
		if ('error' in response):
			print('Error:', response['error'])
	else:
		if text == 'exit':
			break
		convoID = handle_cmd(text, convoID, sock)





