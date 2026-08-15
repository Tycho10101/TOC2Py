import socket
import struct
import threading

class TOC2:
    def __init__(self, host, port, username, password, use_enc=False):
        self.on_message = self._default_function
        self.buddy_list_update = self._default_function
        self.on_chatroom_invite = self._default_function
        self.chatroom_list_update = self._default_function
        self.on_chatroom_message = self._default_function
        self.on_warn = self._default_function

        self.host = host
        self.port = port
        self.username = self.normalize(username)
        self.password = password

        # useless other than compatibility of sorts
        # might not even be properly implemented
        self.use_enc = use_enc

        self.roast = "Tic/Toc"
        self.done = False
        self.buddy_list = {"buddy":{}, "permit": [], "deny":[], "mode": 0}
        self.chatroom_list = {}


    def _default_function(*args, **kwargs):
        pass


    def set_on_message(self):
        def decorator(func):
            self.on_message = func
            return func
        return decorator
    

    def set_buddy_list_update(self):
        def decorator(func):
            self.buddy_list_update = func
            return func
        return decorator
    

    def set_on_chatroom_invite(self):
        def decorator(func):
            self.on_chatroom_invite = func
            return func
        return decorator
    
    
    def set_chatroom_list_update(self):
        def decorator(func):
            self.chatroom_list_update = func
            return func
        return decorator
    

    def set_on_chatroom_message(self):
        def decorator(func):
            self.on_chatroom_message = func
            return func
        return decorator
    

    def set_on_warn(self):
        def decorator(func):
            self.on_warn = func
            return func
        return decorator
    

    def roast_password(self, password):
        result = []
        for i, ch in enumerate(password):
            xored = ord(ch) ^ ord(self.roast[i % len(self.roast)])
            result.append(f"{xored:02x}")
        return "0x" + "".join(result)


    def send_flap(self, frame_type, seq, payload):
        data = payload.encode("ascii") if isinstance(payload, str) else payload
        if frame_type == 2:
            data += b"\x00"
        header = struct.pack("!BBHH", 0x2A, frame_type, seq, len(data))
        self.sock.sendall(header + data)
        return seq + 1


    def recv_flap(self, sock):
        header = b""
        while len(header) < 6:
            chunk = sock.recv(6 - len(header))
            if not chunk:
                raise ConnectionError("Connection closed")
            header += chunk
        marker, frame_type, seq, length = struct.unpack("!BBHH", header)
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                raise ConnectionError("Connection closed")
            payload += chunk
        return frame_type, seq, payload


    def normalize(self, screen_name):
        return screen_name.lower().replace(" ", "")


    def escape(self, text):
        for ch in r'\$"(){}[]':
            text = text.replace(ch, "\\" + ch)
        return text
    

    def parse_buddy_list(self, text):
        buddy_list = {"buddy":{}, "permit": [], "deny":[], "mode": 0}
        last_group = None
        for line in text.strip().split('\n'):
            data = line.split(':')
            if data[0] == "g":
                buddy_list["buddy"][data[1]] = []
                last_group = data[1]
            elif data[0] == "b":
                if last_group:
                    buddy_list["buddy"][last_group].append({"name": data[1], "status": "offline", "typing": 0})
            elif data[0] == "p":
                buddy_list["permit"].append(data[1])
            elif data[0] == "d":
                buddy_list["deny"].append(data[1])
            elif data[0] == "m":
                buddy_list["mode"] = int(data[1])
            elif data[0] == "done":
                break
            else:
                print(f"Unknown command: {data[0]}")

        return buddy_list


    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(5)

        # Step 1: Send FLAPON
        self.sock.sendall(b"FLAPON\r\n\r\n")

        # Step 2: Receive server SIGNON frame
        frame_type, seq, payload = self.recv_flap(self.sock)
        assert frame_type == 1, f"Expected SIGNON frame, got {frame_type}"

        # Step 3: Send client SIGNON frame
        sn = self.normalize(self.username).encode("ascii")
        signon_payload = struct.pack("!IHH", 1, 1, len(sn)) + sn
        self.seq_out = self.send_flap(1, 0, signon_payload)

        # Step 4: Send toc_signon
        roasted = self.roast_password(self.password)
        if self.use_enc:
            login_mode = "login"
            extra_data = f' 160 US "" "" 3 0 30303 -kentucky -utf8 {7696 * ord(self.username[0]) * ord(self.password[0])}'
        else:
            login_mode = "signon"
            extra_data = ""
        cmd = f'toc2_{login_mode} login.oscar.aol.com 5190 {self.normalize(self.username)} {roasted} english "TIC:PythonTOC2"{extra_data}'
        self.seq_out = self.send_flap(2, self.seq_out, cmd)

        # Step 5: Read responses
        messages_needed = ["SIGN_ON", "NICK", "CONFIG2"]
        messages_recived = [False, False, False]
        while not all(messages_recived):
            try:
                frame_type, seq, payload = self.recv_flap(self.sock)
                if frame_type == 2:
                    print(f"← {payload.decode('ascii', errors='replace')}")

                    message = payload.decode('ascii', errors='replace').split(':')
                    if message[0] in messages_needed:
                        messages_recived[messages_needed.index(message[0])] = True

                    if message[0] == "CONFIG2":
                        self.buddy_list = self.parse_buddy_list(':'.join(message[1::]))
                        self.buddy_list_update(self.buddy_list)
                                
            except socket.timeout:
                break

        # Step 6: Send init_done
        self.seq_out = self.send_flap(2, self.seq_out, "toc_init_done")
        self.seq_out = self.send_flap(2, self.seq_out, "toc_set_caps 748F2420-6287-11D1-8222-444553540000 0946134D-4C7F-11D1-8222-444553540000")

        self.t = threading.Thread(target=self.socket_loop)
        self.t.start()


    def socket_loop(self):
        while not self.done:
            try:
                frame_type, seq, payload = self.recv_flap(self.sock)
                if frame_type == 2:
                    print(f"← {payload.decode('ascii', errors='replace')}")

                    message = payload.decode('ascii', errors='replace').split(':')
                    if message[0] == "IM_IN2":
                        self.on_message(message[1], ':'.join(message[4::]))
                    elif message[0] == "IM_IN_ENC2":
                        self.on_message(message[1], ':'.join(message[9::]))
                    elif message[0] == "UPDATE_BUDDY2":
                        if message[2] == 'T':
                            if message[6][2] == 'U':
                                status = "away"
                            else:
                                status = "online"
                        else:
                            status = "offline"

                        for group_name, buddies in self.buddy_list["buddy"].items():
                            for buddy in buddies:
                                if buddy['name'] == message[1]:
                                    buddy_index = buddies.index(buddy)
                                    self.buddy_list["buddy"][group_name][buddy_index]['status'] = status

                        self.buddy_list_update(self.buddy_list)
                    elif message[0] == "CHAT_INVITE":
                        self.on_chatroom_invite(message[3], message[1], message[2], ':'.join(message[4::]))
                    elif message[0] == "CHAT_IN":
                        self.on_chatroom_message(message[1], message[2], ':'.join(message[4::]))
                    elif message[0] == "CHAT_JOIN":
                        self.chatroom_list[message[1]] = {'name': message[2], 'users': []}

                        self.chatroom_list_update(self.chatroom_list)
                    elif message[0] == "CHAT_LEFT":
                        if message[1] in self.chatroom_list:
                            del self.chatroom_list[message[1]]
                        
                        self.chatroom_list_update(self.chatroom_list)
                    elif message[0] == "CHAT_UPDATE_BUDDY":
                        if message[2] == "T":
                            self.chatroom_list[message[1]]['users'] += message[3::]
                        else:
                            for user in message[3::]:
                                if user in self.chatroom_list[message[1]]['users']:
                                    self.chatroom_list[message[1]]['users'].remove(user)
                    
                        self.chatroom_list_update(self.chatroom_list)
                    elif message[0] == "CLIENT_EVENT2":
                        self.buddy_list["buddy"][message[1]]["typing"] = int(message[2])
                        self.buddy_list_update(self.buddy_list)
                    elif message[0] == "EVILED":
                        self.on_warn(message[1], message[2])

            except socket.timeout:
                pass
            except ConnectionError:
                break


    def send_message(self, user, message):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_send_im {self.normalize(user)} "{self.escape(message)}"'.encode('ascii'))


    def send_chatroom_message(self, room_id, message):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc_chat_send {room_id} "{self.escape(message)}"'.encode('ascii'))

    
    def join_chatroom(self, chat_name, exchange=4):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc_chat_join {exchange} "{self.escape(chat_name)}"'.encode('ascii'))


    def invite_chatroom(self, room_id, users, message):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc_chat_invite {room_id} "{self.escape(message)}" {",".join(users)}'.encode('ascii'))
        print(f'toc_chat_invite {room_id} "{self.escape(message)}" {",".join(users)}')


    def accept_chatroom_invite(self, room_id):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc_chat_accept {room_id}'.encode('ascii'))

    
    def leave_chatroom(self, room_id):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc_chat_leave {room_id}'.encode('ascii'))

    
    def send_typing_status(self, user, level):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_client_event {self.normalize(user)} {level}'.encode('ascii'))


    def add_group(self, group):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_new_group "{group}"'.encode('ascii'))
        if group not in self.buddy_list["buddy"]:
            self.buddy_list["buddy"][group] = []
        self.buddy_list_update(self.buddy_list)

    
    def remove_group(self, group):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_del_group "{group}"'.encode('ascii'))
        if group in self.buddy_list["buddy"]:
            del self.buddy_list["buddy"][group]
        self.buddy_list_update(self.buddy_list)


    def add_buddies(self, group, users):
        for user in users:
            if user not in self.buddy_list["buddy"][group]:
                self.buddy_list["buddy"][group].append({"name": self.normalize(user), "status": "offline", "typing": 0})
        users_list = "\n".join(f"b:{self.normalize(user)}" for user in users)
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_new_buddies "{{g:{group}\n{users_list}\n}}"'.encode('ascii'))
        self.buddy_list_update(self.buddy_list)


    def remove_buddy(self, group, user):
        for group_name, buddies in self.buddy_list["buddy"].items():
            for buddy in buddies:
                if buddy['name'] == self.normalize(user):
                    buddy_index = buddies.index(buddy)
                    del self.buddy_list["buddy"][group_name][buddy_index]
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_remove_buddy {self.normalize(user)} "{self.escape(group)}"'.encode('ascii'))
        self.buddy_list_update(self.buddy_list)

    
    def add_permit(self, user):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_add_permit {self.normalize(user)}'.encode('ascii'))
        self.buddy_list["permit"].append(self.normalize(user))
        self.buddy_list_update(self.buddy_list)
    

    def remove_permit(self, user):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_remove_permit {self.normalize(user)}'.encode('ascii'))
        self.buddy_list["permit"].remove(self.normalize(user))
        self.buddy_list_update(self.buddy_list)

    

    def add_deny(self, user):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_add_deny {self.normalize(user)}'.encode('ascii'))
        self.buddy_list["deny"].append(self.normalize(user))
        self.buddy_list_update(self.buddy_list)
    
    
    def remove_deny(self, user):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_remove_deny {self.normalize(user)}'.encode('ascii'))
        self.buddy_list["deny"].remove(self.normalize(user))
        self.buddy_list_update(self.buddy_list)

    
    def set_pdmode(self, mode):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc2_set_pdmode {mode}'.encode('ascii'))
        self.buddy_list["mode"] = mode
        self.buddy_list_update(self.buddy_list)


    def warn_user(self, user, anom=False):
        self.seq_out = self.send_flap(2, self.seq_out, f'toc_evil {self.normalize(user)} {"norm" if not anom else "anom"}'.encode('ascii'))
        self.buddy_list_update(self.buddy_list)


    def disconnect(self):
        self.done = True
        if threading.current_thread() is not self.t:
            self.t.join()
        try:
            self.send_flap(4, self.seq_out, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    HOST = "localhost"
    PORT = 9898
    USERNAME = "username"
    PASSWORD = "password"

    toc = TOC2(HOST, PORT, USERNAME, PASSWORD, True)
    buddy_list = toc.buddy_list
    chatroom_list = toc.chatroom_list

    @toc.set_on_message()
    def on_message(user, message):
        print(f'{user}: {message}')
        toc.send_message(user, message)

    @toc.set_buddy_list_update()
    def buddy_list_update(bl):
        global buddy_list
        buddy_list = bl
        print(bl)

    @toc.set_on_chatroom_invite()
    def on_chat_invite(user, room_name, room_id, message):
        toc.accept_chatroom_invite(room_id)
        print(f'{user} invited you to join {room_name}: {message}')

    @toc.set_chatroom_list_update()
    def chatroom_list_update(cl):
        global chatroom_list
        chatroom_list = cl
        print(cl)

    @toc.set_on_chatroom_message()
    def on_chatroom_message(room_id, user, message):
        print(f'In {room_id}\n{user}: {message}')
        if not user == toc.username:
            toc.send_chatroom_message(room_id, message)

    @toc.set_on_warn()
    def on_warn(amount_warned, user):
        if not user:
            user = "An anonymous user"
        print(f'{user} has warned you. You are now at {amount_warned}')

    toc.start()
