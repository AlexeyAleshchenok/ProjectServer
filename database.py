import sqlite3
import bcrypt
import random


class Database:
    """
    Handles all database operations for users, files, friends, and chats.
    Uses SQLite as backend.
    """
    def __init__(self, db_name="database.db"):
        """
        Initializes the database and creates tables if they do not exist.
        """
        self.db_name = db_name
        self._create_tables()

    def _connect(self):
        """
        Returns a new SQLite connection with timeout set.
        """
        return sqlite3.connect(self.db_name, timeout=5)

    def _create_tables(self):
        """
        Creates required database tables for users, files, friends, chats, and chat_members.
        Executes only once on startup.
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""CREATE TABLE IF NOT EXISTS users 
                          (id TEXT PRIMARY KEY,
                          login TEXT UNIQUE NOT NULL, 
                          username TEXT NOT NULL,
                          password TEXT NOT NULL,
                          is_online INTEGER DEFAULT 0)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS files
                          (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          owner_id TEXT NOT NULL,
                          filename TEXT NOT NULL,
                          FOREIGN KEY (owner_id) REFERENCES users (id))""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS friends
                          (user_id TEXT NOT NULL,
                          friend_id TEXT NOT NULL,
                          status TEXT NOT NULL, -- pending, accepted
                          PRIMARY KEY (user_id, friend_id),
                          FOREIGN KEY (user_id) REFERENCES users (id),
                          FOREIGN KEY (friend_id) REFERENCES users (id))""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS chats
                          (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT,
                          is_group BOOLEAN NOT NULL)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS chat_members
                          (chat_id INTEGER NOT NULL,
                          user_id TEXT NOT NULL,
                          PRIMARY KEY (chat_id, user_id),
                          FOREIGN KEY (chat_id) REFERENCES chats (id),
                          FOREIGN KEY (user_id) REFERENCES users (id))""")

        conn.commit()
        conn.close()

    # Registration
    def generate_id(self):
        """
        Generates a unique 6-digit user ID that doesn't yet exist in the database.
        """
        while True:
            user_id = str(random.randint(100000, 999999))
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
                if not cursor.fetchone():
                    return user_id

    def register_user(self, login: str, username: str, password: str) -> tuple[bool, str | None]:
        """
        Registers a new user with hashed password.
        Returns (success flag, user ID if successful).
        """
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                user_id = self.generate_id()
                cursor.execute("INSERT INTO users (id, login, username, password) VALUES (?, ?, ?, ?)",
                               (user_id, login, username, hashed_password))
                conn.commit()
            return True, user_id
        except sqlite3.IntegrityError:
            return False, None

    def authenticate_user(self, login: str, password: str) -> tuple[bool, str | None, str | None]:
        """
        Verifies login credentials.
        Returns tuple (is_authenticated, user_id, username).
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password, username FROM users WHERE login = ?", (login,))
            result = cursor.fetchone()

        if result:
            user_id, stored_password, username = result
            if bcrypt.checkpw(password.encode(), stored_password):
                return True, user_id, username
        return False, None, None

    def set_user_online_status(self, user_id: str, is_online: bool):
        """
        Updates user's online status (1 = online, 0 = offline).
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_online=? WHERE id=?", (int(is_online), user_id))
            conn.commit()

    def get_username(self, user_id: str):
        """
        Returns the username of a user by their ID.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
        return result[0] if result else None

    def search_users(self, username: str, user_id: str) -> list[dict]:
        """
        Searches users by partial username (excluding current user).
        Returns list of dicts with id and username.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT id, username
                                    FROM users
                                    WHERE username LIKE ? AND id != ?
                                    LIMIT 20""", (username, user_id))
            return [{"id": row[0], "username": row[1]} for row in cursor.fetchall()]

    # Files
    def add_file(self, owner_id: str, filename: str):
        """
        Adds a file entry to the database for the given user.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO files (owner_id, filename) VALUES (?, ?)", (owner_id, filename))
            conn.commit()

    def get_user_files(self, owner_id: str) -> list[str]:
        """
        Returns list of filenames uploaded by a specific user.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT filename FROM files WHERE owner_id = ?", (owner_id,))
            files = [row[0] for row in cursor.fetchall()]
        return files

    # Friends
    def add_friend_request(self, user_id: str, friend_id: str):
        """
        Sends a friend request (status='pending').
        Uses INSERT OR IGNORE to prevent duplicates.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'pending')",
                           (user_id, friend_id))
            conn.commit()

    def accept_friend_request(self, user_id: str, friend_id: str):
        """
        Accepts a pending friend request.
        Updates status to 'accepted' in both directions.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE friends SET status = 'accepted' WHERE user_id = ? AND friend_id = ?",
                           (friend_id, user_id))
            cursor.execute("INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'accepted')",
                           (user_id, friend_id))
            conn.commit()

    def decline_friend_request(self, user_id: str, friend_id: str):
        """
        Removes a pending incoming request from friend_id.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'pending'",
                           (friend_id, user_id))
            conn.commit()

    def remove_friend(self, user_id: str, friend_id: str):
        """
        Removes a friendship in both directions.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)",
                (user_id, friend_id, friend_id, user_id))
            conn.commit()

    def get_friends(self, user_id: str) -> list[str]:
        """
        Returns a list of user IDs that are friends with the given user.
        Includes both directions.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT friend_id FROM friends WHERE user_id = ? AND status = 'accepted'
                              UNION
                              SELECT user_id FROM friends WHERE friend_id = ? AND status = 'accepted'""",
                           (user_id, user_id))
            friends = [row[0] for row in cursor.fetchall()]
        return friends

    def get_incoming_requests(self, user_id: str) -> list[dict]:
        """
        Returns a list of pending incoming friend requests (with usernames).
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT users.id, users.username FROM friends
                                    JOIN users ON friends.user_id = users.id
                                    WHERE friends.friend_id = ? AND friends.status = 'pending'""", (user_id,))
            return [{"id": row[0], "username": row[1]} for row in cursor.fetchall()]

    def get_outgoing_requests(self, user_id: str) -> list[dict]:
        """
        Returns a list of pending outgoing friend requests (with usernames).
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT users.id, users.username FROM friends
                                    JOIN users ON users.id = friends.friend_id
                                    WHERE friends.user_id = ? AND friends.status = 'pending'""", (user_id,))
            return [{"id": row[0], "username": row[1]} for row in cursor.fetchall()]

    # Chats
    def create_chat(self, name: str, is_group: bool, members: list[str]) -> int:
        """
        Creates a new chat (group or private) with the provided members.
        Returns the chat ID.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO chats (name, is_group) VALUES (?, ?)", (name, is_group))
            chat_id = cursor.lastrowid
            for user_id in members:
                cursor.execute("INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)", (chat_id, user_id))
            conn.commit()
        return chat_id

    def get_user_chats(self, user_id: str) -> list[dict]:
        """
        Returns a list of chats (id + name) that the user is a member of.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT c.id, c.name
                                    FROM chats c
                                    JOIN chat_members cm ON c.id = cm.chat_id
                                    WHERE cm.user_id = ?""", (user_id,))
            chats = [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]
        return chats

    def get_chat_members(self, chat_id: int) -> list[str]:
        """
        Returns a list of user IDs that are members of the given chat.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM chat_members WHERE chat_id = ?", (chat_id,))
            members = [row[0] for row in cursor.fetchall()]
        return members

    def is_chat_member(self, chat_id: int, user_id: str) -> bool:
        """
        Checks if a user is a member of a specific chat.
        Returns True or False.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?", (chat_id, user_id))
            return cursor.fetchone() is not None

    def add_user_to_chat(self, chat_id: int, user_id: str) -> bool:
        """
        Adds a user to an existing chat.
        Returns True if successful, False on error.
        """
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)",
                               (chat_id, user_id))
                conn.commit()
            return True
        except sqlite3.Error:
            return False
