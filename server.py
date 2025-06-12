import socket
import threading
import logging
import ssl
import os
import json
from database import Database

LOG_FILE = "server.log"
CERTIFICATE = "cert.pem"
PRIVATE_KEY = "key.pem"
IP = '0.0.0.0'
PORT = 443
QUEUE_SIZE = 10
SOCKET_TIMEOUT = 5
OK = "HTTP/1.1 200 OK"
CREATED = "HTTP/1.1 201 Created"
BAD_REQUEST = 'HTTP/1.1 400 Bad Request'
UNAUTHORIZED = "HTTP/1.1 401 Unauthorized"
FORBIDDEN = 'HTTP/1.1 403 Forbidden'
NOT_FOUND = 'HTTP/1.1 404 Not Found'
CONFLICT = "HTTP/1.1 409 Conflict"
UPLOAD_FOLDER = 'uploads'
CONNECTED_USERS = {}
DATABASE = Database()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(LOG_FILE, mode='a'), logging.StreamHandler()])
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def build_response(status_line: str, body: dict, type_header="response", content_type="application/json") -> bytes:
    """
    Constructs a basic HTTP-like response from provided status, headers, and body.

    :param status_line: HTTP status (e.g., "HTTP/1.1 200 OK")
    :param body: Dictionary to send as JSON body
    :param type_header: Custom header to define type of message
    :param content_type: MIME type of the content
    :return: Byte-encoded HTTP response
    """
    body_str = json.dumps(body)
    headers = (f"{status_line}\r\n"
               f"Content-Type: {content_type}\r\n"
               f"Content-Length: {len(body_str.encode())}\r\n"
               f"Type: {type_header}\r\n\r\n")
    return (headers + body_str).encode()


# GET
def get_download(params, client_socket):
    """
    Handles a file download request.
    Validates file path and sends the file in binary format if it exists.
    """
    file_path = params.get("file")
    if not file_path:
        logging.warning("Download request missing file path.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
        return

    safe_path = os.path.normpath(file_path)
    if not safe_path.startswith("uploads") or ".." in safe_path:
        logging.warning(f"Unsafe download path attempt: {safe_path}")
        client_socket.sendall(build_response(FORBIDDEN, {"message": "Access denied"}))
        return

    if not os.path.exists(file_path):
        logging.error("File does not exist")
        client_socket.sendall(build_response(NOT_FOUND, {"message": "Not Found"}))
        return

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        response_headers = ("HTTP/1.1 200 OK\r\n"
                            "Content-Type: application/octet-stream\r\n"
                            f"Content-Length: {len(file_data)}\r\n"
                            f"Type: response\r\n\r\n").encode()
        client_socket.sendall(response_headers + file_data)
        logging.info(f"File '{file_path}' successfully sent to client.")
    except Exception as e:
        logging.error(f"Error sending file '{file_path}': {e}")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def get_gallery(params, client_socket):
    """
    Returns a list of images uploaded by a specific user.
    Requires a valid user ID in the parameters.
    """
    user_id = params.get("id")
    if not user_id:
        logging.warning("Gallery request missing user ID.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Missing user ID"}))
        return

    try:
        files = DATABASE.get_user_files(user_id)
        image_list = [{"name": filename, "path": f"uploads/{user_id}/{filename}"} for filename in files]

        logging.info(f"Gallery returned {len(image_list)} images for user {user_id}")
        client_socket.sendall(build_response(OK, {"images": image_list}))
    except Exception as e:
        logging.error(f"Error retrieving gallery: {e}")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def get_chats(params, client_socket):
    """
    Retrieves all chats the user is a member of.
    """
    user_id = params.get("id")
    if not user_id:
        logging.warning("Chats request missing user ID.")
        client_socket.sendall(build_response(UNAUTHORIZED, {"message": "Invalid ID"}))
        return

    username = DATABASE.get_username(user_id)
    chats = DATABASE.get_user_chats(user_id)
    logging.info(f"User {username} requested chat list.")
    client_socket.sendall(build_response(OK, {"chats": chats}))


def get_friends_list(params, client_socket):
    """
    Returns the user's friends list along with their online status.
    """
    user_id = params.get("user_id")
    username = DATABASE.get_username(user_id)
    if not user_id:
        client_socket.sendall(build_response(UNAUTHORIZED, {"message": "Invalid ID"}))
        return

    friends_ids = DATABASE.get_friends(user_id)
    friends = []
    for fid in friends_ids:
        friend_name = DATABASE.get_username(fid)
        online = fid in CONNECTED_USERS
        friends.append({"friend_name": friend_name, "friend_id": fid, "online": online})
    logging.info(f"User {username} requested friends list.")
    client_socket.sendall(build_response(OK, {"friends": friends}))


def get_incoming_requests(params, client_socket):
    """
    Returns a list of incoming friend requests for the user.
    """
    user_id = params.get("user_id")
    username = DATABASE.get_username(user_id)
    if not user_id:
        client_socket.sendall(build_response(UNAUTHORIZED, {"message": "Invalid ID"}))
        return

    incoming = DATABASE.get_incoming_requests(user_id)
    logging.info(f"User {username} requested incoming requests list.")
    client_socket.sendall(build_response(OK, {"incoming": incoming}))


def get_outgoing_requests(params, client_socket):
    """
    Returns a list of outgoing friend requests sent by the user.
    """
    user_id = params.get("user_id")
    username = DATABASE.get_username(user_id)
    if not user_id:
        client_socket.sendall(build_response(UNAUTHORIZED, {"message": "Invalid ID"}))
        return

    outgoing = DATABASE.get_outgoing_requests(user_id)
    logging.info(f"User {username} requested outgoing requests list.")
    client_socket.sendall(build_response(OK, {"outgoing": outgoing}))


def get_user_search(params, client_socket):
    """
    Searches for users by username substring.
    Excludes the current user from results.
    """
    username = params.get("username")
    searcher_id = params.get("searcher_id")
    if not username:
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
        return

    users = DATABASE.search_users(username, searcher_id)
    if not users:
        client_socket.sendall(build_response(NOT_FOUND, {"message": "User not found"}))
        return

    logging.info(f"User {username} search.")
    client_socket.sendall(build_response(OK, {"results": users}))


def get_exit(params, client_socket):
    """
    Handles user logout.
    Updates online status and closes the connection.
    """
    user_id = params.get("id")
    username = DATABASE.get_username(user_id)

    if not user_id:
        logging.warning("Unauthorized exit attempt.")
        client_socket.sendall(build_response(UNAUTHORIZED, {"message": "Invalid ID"}))
        return

    client_socket.sendall(build_response(OK, {"message": "Logged out successfully"}))
    DATABASE.set_user_online_status(user_id, False)
    CONNECTED_USERS.pop(user_id, None)
    logging.info(f"Client {username} logged out.")

    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except Exception as e:
        logging.warning(f"Error during shutdown: {e}")
    finally:
        client_socket.close()


def get_interfaces(url, params, client_socket):
    """
    Routes GET requests to the appropriate handler based on the URL.
    Logs each route call and returns a 'Not Found' if unmatched.
    """
    if url == "/download":
        logging.info('GET /download request')
        get_download(params, client_socket)
    elif url == "/gallery":
        logging.info('GET /gallery request')
        get_gallery(params, client_socket)
    elif url == "/chats":
        logging.info('GET /chats request')
        get_chats(params, client_socket)
    elif url == "/friends":
        logging.info('GET /friends request')
        get_friends_list(params, client_socket)
    elif url == "/requests_incoming":
        logging.info('GET /requests_incoming request')
        get_incoming_requests(params, client_socket)
    elif url == "/requests_outgoing":
        logging.info('GET /requests_outgoing request')
        get_outgoing_requests(params, client_socket)
    elif url == "/search_user":
        logging.info('GET /search_user request')
        get_user_search(params, client_socket)
    elif url == "/exit":
        logging.info('GET /exit request')
        get_exit(params, client_socket)
    else:
        logging.error("Unknown GET request")
        client_socket.sendall(build_response(NOT_FOUND, {"message": "Not Found"}))


# POST
def post_login(body, client_socket):
    """
    Handles user login.
    Verifies credentials and sets user as online if successful.
    """
    try:
        data = json.loads(body.decode())
        login = data.get("login")
        password = data.get("password")

        if not login or not password:
            logging.warning("Login request missing login or password.")
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        authentication, user_id, username = DATABASE.authenticate_user(login, password)
        if authentication:
            logging.info(f"User '{username}' logged in.")
            client_socket.sendall(build_response(OK, {"message": "Login successful",
                                                      "id": user_id, "username": username}))
            DATABASE.set_user_online_status(user_id, True)
            CONNECTED_USERS[user_id] = client_socket
        else:
            logging.warning(f"Failed login attempt.")
            client_socket.sendall(build_response(UNAUTHORIZED, {"message": "Invalid username or password"}))

    except json.JSONDecodeError:
        logging.error("Invalid JSON in login request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_sign_in(body, client_socket):
    """
    Registers a new user.
    Validates input and stores user credentials in the database.
    """
    try:
        data = json.loads(body.decode())
        login = data.get("login")
        username = data.get("username") or login
        password = data.get("password")

        if not login or not password:
            logging.warning("Sign-in request missing login or password.")
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        registration, user_id = DATABASE.register_user(login, username, password)
        if registration:
            logging.info(f"New user '{username}' registered.")
            client_socket.sendall(build_response(CREATED,
                                                 {"message": "Account created successfully", "id": user_id}))

        else:
            logging.warning(f"Login '{login}' already exists.")
            client_socket.sendall(build_response(CONFLICT, {"message": "Login already exists"}))

    except json.JSONDecodeError:
        logging.error("Invalid JSON in sign-in request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_upload(params, body, client_socket):
    """
    Handles file upload from the client.
    Stores file in a user-specific directory and updates the database.
    """
    file_name = params.get("filename")
    user_id = params.get("id")

    if not file_name or not user_id:
        logging.warning("Upload request missing filename or ID.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
        return

    if user_id == 'None':
        logging.warning("Unauthorized upload attempt.")
        client_socket.sendall(build_response(FORBIDDEN, {"message": "User not registered"}))
        return

    try:
        user_folder = os.path.join(UPLOAD_FOLDER, user_id)
        os.makedirs(user_folder, exist_ok=True)

        file_path = os.path.join(user_folder, file_name)
        with open(file_path, "wb") as f:
            f.write(body)

        DATABASE.add_file(user_id, file_name)
        logging.info(f"File '{file_name}' uploaded by '{DATABASE.get_username(user_id)}'.")
        client_socket.sendall(build_response(OK, {"message": "File uploaded"}))
    except Exception as e:
        logging.error(f"Error during file upload: {e}")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Internal Server Error"}))


def post_create_chat(body, client_socket):
    """
    Creates a new group chat with specified members.
    Stores chat in the database and assigns initial users.
    """
    try:
        data = json.loads(body.decode())
        chat_name = data.get("chat_name")
        creator_id = data.get("creator_id")
        members = data.get("members", [])

        if not chat_name or not creator_id:
            logging.warning("Create chat request missing chat_name or creator_id.")
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        chat_id = DATABASE.create_chat(chat_name, creator_id, members)
        if chat_id:
            creator_name = DATABASE.get_username(creator_id) or "Unknown"
            logging.info(f"Chat '{chat_name}' created by user {creator_name}.")
            client_socket.sendall(build_response(CREATED, {"message": "Chat created successfully!",
                                                           "chat_id": chat_id}))
        else:
            logging.error("Failed to create chat.")
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Failed to create chat"}))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in create_chat request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_send_message(body, client_socket):
    """
    Sends a message to a chat.
    Forwards message to all online participants (excluding sender).
    """
    try:
        data = json.loads(body.decode())
        chat_id = data.get("chat_id")
        sender = data.get("sender")
        sender_id = data.get("sender_id")
        message_type = data.get("message_type")
        content = data.get("content")
        timestamp = data.get("timestamp")

        if not chat_id or not sender_id or not content:
            logging.warning("Send message request missing required fields.")
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        if not DATABASE.is_chat_member(chat_id, sender_id):
            logging.warning(f"Unauthorized message attempt by user {sender} in chat {chat_id}.")
            client_socket.sendall(build_response(FORBIDDEN, {"message": "Access denied"}))
            return

        message_data = {"chat_id": chat_id, "sender": sender, "sender_id": sender_id, "message_type": message_type,
                        "content": content, "timestamp": timestamp}
        members = DATABASE.get_chat_members(chat_id)

        for user_id in members:
            if user_id == sender_id:
                continue

            username = DATABASE.get_username(user_id)
            s = CONNECTED_USERS.get(user_id)
            if s:
                try:
                    s.sendall(build_response(OK, message_data, type_header="message"))
                    logging.info(f"Delivered message to user {username}")
                except Exception as e:
                    logging.warning(f"Failed to send message to user {username}: {e}")

        logging.info(f"User {sender} sent message to chat {chat_id}.")
        client_socket.sendall(build_response(OK, {"message": "Message sent"}))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in send_message request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_add_to_chat(body, client_socket):
    """
    Adds a user to an existing chat.
    """
    try:
        data = json.loads(body.decode())
        chat_id = data.get("chat_id")
        user_id = data.get("user_id")
        username = DATABASE.get_username(user_id)

        if not chat_id or not user_id:
            logging.warning("Add to chat request missing chat_id or user_id.")
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        success = DATABASE.add_user_to_chat(chat_id, user_id)
        if success:
            logging.info(f"User {username} added to chat {chat_id}.")
            client_socket.sendall(build_response(OK, {"message": "User added to chat"}))
        else:
            logging.error(f"Failed to add user {username} to chat {chat_id}.")
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Failed to add user"}))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in add_to_chat request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_add_friend(body, client_socket):
    """
    Sends a friend request to another user.
    """
    try:
        data = json.loads(body.decode())
        user_id = data.get("user_id")
        friend_id = data.get("friend_id")

        if not user_id:
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        if not friend_id:
            client_socket.sendall(build_response(NOT_FOUND, {"message": "User not found"}))
            return

        DATABASE.add_friend_request(user_id, friend_id)
        client_socket.sendall(build_response(OK, {"message": "Friend request sent"}))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in add_friend request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_accept_friend(body, client_socket):
    """
    Accepts a pending friend request.
    """
    try:
        data = json.loads(body.decode())
        user_id = data.get("user_id")
        friend_id = data.get("friend_id")

        if not user_id or not friend_id:
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        DATABASE.accept_friend_request(user_id, friend_id)
        client_socket.sendall(build_response(OK, {"message": "Friend request accepted"}))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in accept_friend request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_decline_friend(body, client_socket):
    """
    Declines a pending friend request.
    """
    try:
        data = json.loads(body.decode())
        user_id = data.get("user_id")
        friend_id = data.get("friend_id")

        if not user_id or not friend_id:
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        DATABASE.decline_friend_request(user_id, friend_id)
        client_socket.sendall(build_response(OK, {"message": "Friend request declined"}))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in decline_friend request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_remove_friend(body, client_socket):
    """
    Removes a friend from the user's friend list.
    """
    try:
        data = json.loads(body.decode())
        user_id = data.get("user_id")
        friend_id = data.get("friend_id")

        if not user_id or not friend_id:
            client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            return

        DATABASE.remove_friend(user_id, friend_id)
        client_socket.sendall(build_response(OK, {"message": "Friend removed"}))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in remove_friend request.")
        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))


def post_interfaces(url, params, body, client_socket):
    """
    Routes POST requests to the appropriate handler based on the URL.
    Logs each route call and returns a 'Not Found' if unmatched.
    """
    if url == "/login":
        logging.info('POST /login request')
        post_login(body, client_socket)
    elif url == "/sign_in":
        logging.info('POST /sign_in request')
        post_sign_in(body, client_socket)
    elif url == "/upload":
        logging.info('POST /upload request')
        post_upload(params, body, client_socket)
    elif url == "/create_chat":
        logging.info('POST /create_chat request')
        post_create_chat(body, client_socket)
    elif url == "/send_message":
        logging.info('POST /send_message request')
        post_send_message(body, client_socket)
    elif url == "/add_to_chat":
        logging.info('POST /add_to_chat request')
        post_add_to_chat(body, client_socket)
    elif url == "/add_friend":
        logging.info('POST /add_friend request')
        post_add_friend(body, client_socket)
    elif url == "/accept_friend":
        logging.info('POST /accept_friend request')
        post_accept_friend(body, client_socket)
    elif url == "/decline_friend":
        logging.info('POST /decline_friend request')
        post_decline_friend(body, client_socket)
    elif url == "/remove_friend":
        logging.info('POST /remove_friend request')
        post_remove_friend(body, client_socket)
    else:
        logging.error("Unknown POST request")
        client_socket.sendall(build_response(NOT_FOUND, {"message": "Not Found"}))


def url_params_parser(url_params):
    """
    Parses URL query parameters from a query string into a dictionary.

    :param url_params: String like "id=123&file=name"
    :return: Dictionary of parsed parameters
    """
    params = {}
    for pair in url_params.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            params[key] = value
    return params


def request_parser(client_request):
    """
    Parses a raw HTTP-like client request into method, URL, params, headers, and body.

    :param client_request: Raw bytes received from client
    :return: Tuple of (method, url, params_dict, headers, body) or None on error
    """
    try:
        request_lines = client_request.split(b"\r\n")
        if len(request_lines) < 2:
            return None

        first_line = request_lines[0].decode().split(" ")
        if len(first_line) != 3 or first_line[2] != "HTTP/1.1":
            return None

        method = first_line[0]
        raw_url = first_line[1]
        headers = {}

        i = 1
        while i < len(request_lines) and request_lines[i] != b'':
            key, value = request_lines[i].decode().split(": ", 1)
            headers[key] = value
            i += 1

        body = b"\r\n".join(request_lines[i + 1:])
        url, params = raw_url.split("?", 1) if "?" in raw_url else (raw_url, "")
        params_dict = url_params_parser(params)

        logging.info(f"Request: {method} {url} | Headers: {headers}")
        return method, url, params_dict, headers, body
    except Exception as e:
        logging.error(f"Request parsing error: {e}")
        return None


def receive_data(client_socket):
    """
    Reads incoming data from the client socket in chunks.

    :param client_socket: The socket object
    :return: Byte string of the received data
    """
    data = b''
    while True:
        chunk = client_socket.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(chunk) < 1024:
            break
    return data


def handle_client(client_socket, client_address):
    """
    Handles a connected client. Parses requests, routes them,
    and responds based on HTTP-like method (GET/POST).

    :param client_socket: SSL-wrapped client connection
    :param client_address: Tuple (IP, port) of client
    """
    logging.info(f"New connection from {client_address}")
    while True:
        try:
            client_request = receive_data(client_socket)
            if client_request != b'':
                parsed_request = request_parser(client_request)
                if parsed_request:
                    method, url, params, headers, body = parsed_request
                    if method == 'GET':
                        logging.info('Got a HTTP GET request')
                        get_interfaces(url, params, client_socket)
                    elif method == 'POST':
                        logging.info('Got a HTTP POST request')
                        post_interfaces(url, params, body, client_socket)
                    else:
                        logging.error('Not a valid HTTP request')
                        client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
                        break
                    if url == "/exit":
                        break
                else:
                    logging.warning("The client sent an incorrect request.")
                    client_socket.sendall(build_response(BAD_REQUEST, {"message": "Bad Request"}))
            else:
                logging.warning("An empty request from the client.")
                break
        except socket.timeout:
            logging.warning("Client connection timeout.")
            break
    client_socket.close()
    logging.info(f"Connection with {client_address} closed.")


def main():
    """
    Entry point for the server:
    - Initializes socket
    - Wraps with SSL context
    - Accepts incoming connections
    - Launches new thread for each client
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((IP, PORT))
        server_socket.listen(QUEUE_SIZE)
        logging.info(f"Server is listening on {IP}:{PORT}")

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=CERTIFICATE, keyfile=PRIVATE_KEY)

        while True:
            raw_conn, addr = server_socket.accept()
            try:
                client_conn = ssl_context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as e:
                logging.error(f"SSL handshake failed with {addr}: {e}")
                raw_conn.close()
                continue
            client_handler = threading.Thread(target=handle_client, args=(client_conn, addr), daemon=True)
            client_handler.start()
    except socket.error as msg:
        logging.error(f'Failed to open server socket - {str(msg)}')
    finally:
        server_socket.close()


if __name__ == '__main__':
    main()
