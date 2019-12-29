import socket
import sys
import json
import hashlib
port = 12981

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
				req_input = input()
				to_hash = req_input.encode() + contents['args'][0].encode()
				print(to_hash)
				pw_hash = hashlib.sha3_256(to_hash).digest()
				#convert byte string to utf-8 encodable representation
				to_send['hash'] = ''.join('{:02x}'.format(c) for c in pw_hash)
				print(to_send['hash'])
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

def handle_cmd(text, convoID):
	args = text.split()
	cmd = args.pop(0)
	to_send = {}
	if cmd == 'open':
		to_send = {'cmd':'open', 'args':args}
	elif cmd == 'close':
		if(convoID):
			to_send = {'cmd':'ls', 'args':[]}
			convoID = None
		else:
			print('no conversation to close')
			continue
	elif cmd == 'ls':
		if convoID is not None:
			to_send = {'cmd':'ls', 'args':args}
	elif cmd == 'refresh':
		if convoID is not None:
			to_send = {'cmd':'refresh', 'args':convoID}
	else:
		print('unknown command:' cmd)
		return convoID
	response = request(sock, to_send)
	if('error' in response):
		print('Error:', response['error'])
	if('msg' in response):
		print(msg)
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
				convoID = handle_cmd(text[2:], True)
	else:
		handle_cmd(text, False)





