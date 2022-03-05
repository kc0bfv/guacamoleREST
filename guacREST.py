#!/usr/bin/env python3

"""
Based on API reference at https://github.com/ridvanaltun/guacamole-rest-api-documentation

To use this, simply run the file with a "--help" option.

To improve upon this, well, you need to know a little more.  The CommandFile class is the main handler, facilitating parsing of the command file, and executing the commands.  The meat of the code is in GuacConnection though.  The commands are implemented and described there.
"""

import argparse
from functools import wraps
import json
import urllib.parse
import urllib.request
import socket
import time

def require_token(func):
    """
    Validates that the self object has a token set on it, thus ensuring that the object has retrieved a token as part of the login process.
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.token is None:
            raise RuntimeError("Token not set!")
        return func(self, *args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

class Command:
    """
    Defines a command from the command file, keeps track of known commands, and understands how to call the underlying code from a command specified in the command file
    """
    registered = dict()
    def __init__(self, command, args):
        """
        Initialize the Command - takes a command name and a list of arguments.  The result may be executed using the execute function and by passing an initialized GuacConnection
        """
        self.command = command
        self.args = args
    @classmethod
    def register(cls, func):
        """
        This decorator registers a function name from a GuacConnection function and remembers it, so it can be called from the command file by name
        """
        fname = func.__name__
        if fname in cls.registered:
            raise RuntimeError("Function already registered: {}".format(fname))
        cls.registered[fname] = func
        return func
    def execute(self, target):
        """
        Executes a command against a target GuacConnection object

        :param target: the initialized GuacConnection to execute upon
        """
        return self.registered[self.command](target, *self.args)

class GuacConnection:
    def __init__(self, urlbase, admin_user="guacadmin", admin_pass="guacadmin"):
        """
        Initialize the GuacConnection object.  After this, initialize the connection by running the init_guac function.

        :param urlbase: the base URL for the guac server
        :param admin_user: the admin username for the guac server, typically "guacadmin"
        :param admin_pass: the initial password for the guac admin, typically "guacadmin".  During init_guac, GuacConnection will try this password first, and if it succeeds init_guac will change the password immediately.  If admin_pass fails, then init_guac will try the desired final admin password automatically.  That way, a command file can run multiple times without needing to worry about the current state of the admin password.
        """
        self.urlbase = urlbase
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.token = None
        self.dataSource = None
        self.timeout = 5
        self.max_wait = 6

    def _get_url(self, api_point, url_dict=None, add_token=True):
        """
        Returns a url based on the settings, api_point, and token
        :param api_point: the action within the API to return a URL for
        :param url_dict: an optional dictionary of parameters that can get inserted into the api_point string
        :param add_token: if true, adds in the authentication token
        """
        if url_dict is None:
            url_dict = dict()
        cur_url = urllib.parse.urljoin(self.urlbase, api_point)
        cur_url = cur_url.format(dataSource = self.dataSource, **url_dict)
        if add_token:
            cur_url = urllib.parse.urljoin(cur_url, "?token={}".format(self.token))
        return cur_url

    def wait_on_server(self, add_delay=False):
        """
        Waits for the server to respond, then if add_delay is set waits an additional period
        """
        print("Beginning to wait for server")
        req = urllib.request.Request(self._get_url("/"))
        for i in range(self.max_wait):
            try:
                urllib.request.urlopen(req, timeout=self.timeout).close()
                break
            except urllib.error.URLError as e:
                if (not isinstance(e.reason, socket.timeout)) and e.reason.errno != 111:
                    break
            print("Continuing waiting: {} of {}".format(i+1, self.max_wait))
            time.sleep(5)
        print("Finished waiting for server")

        if add_delay:
            print("Doing additional 120 second delay, then re-waiting for server")
            time.sleep(120)
            self.wait_on_server()

    def init_guac(self, desired_pass):
        """
        Initialize the Guacamole connection by getting a token and setting
        a new administrator password.
        :param desired_pass: the desired password to set
        """
        if self._get_token():
            if self._change_password(self.admin_user, self.admin_pass, desired_pass):
                self.admin_pass = desired_pass
            else:
                raise RuntimeError("Changing the administrator password failed")
        else:
            if self._get_token(desired_pass):
                self.admin_pass = desired_pass
            else:
                raise RuntimeError("Failed to authenticate with original and new passwords")

    def _get_token(self, try_pass=None):
        """
        Generally you don't need this - generally you want to use init_guac.

        Get a token for the Guacamole connection.
        """
        if try_pass is None:
            try_pass = self.admin_pass
            print("Getting login token for: {}".format(self.admin_user))
        else:
            print("Getting login token with desired pw for: {}".format(self.admin_user))

        # API Properties
        api_point = "/api/tokens"
        api_method = "POST"
        headers = {}

        # Data to Send
        data_str = "username={}&password={}".format(self.admin_user, try_pass)

        # Convert formats for Python
        dest = self._get_url(api_point, add_token=False)
        data = data_str.encode("ascii")

        req = urllib.request.Request(dest, data, headers, method=api_method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                output = resp.read()
        except urllib.error.HTTPError as e:
            output = e.read().decode("utf-8")
            if e.code == 403:
                print("Error 403 on login - password may be wrong or already changed")
                self.token, self.dataSource = None, None
                return False
            else:
                raise e

        outvals = json.loads(output)
        self.token, self.dataSource = outvals["authToken"], outvals["dataSource"]
        return True

    @require_token
    def _change_password(self, username, old_password, new_password):
        print("Changing password for: {}".format(username))

        # API Properties
        api_point = "/api/session/data/{dataSource}/users/{username}/password"
        api_method = "PUT"
        headers = {"Content-Type": "application/json"}

        # Data to Send
        data_dict = {"oldPassword": old_password, "newPassword": new_password}

        # Convert formats for Python
        dest = self._get_url(api_point, {"username": username})
        data = json.dumps(data_dict).encode("ascii")

        req = urllib.request.Request(dest, data, headers, method=api_method)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            output = resp.read()
        if output == b"":
            print("Password changed")
            return True
        else:
            raise RuntimeError("Returned: {}".format(output.decode("utf-8")))

    @require_token
    def _get_connection_id(self, conn_name):
        """
        Gets the ID of a connection based on it's name
        """
        print("Getting connection ID: {}".format(conn_name))

        # API Properties
        api_point = "/api/session/data/{dataSource}/connections"
        api_method = "GET"
        headers = {}

        # Data to Send
        # None

        # Convert formats for Python
        dest = self._get_url(api_point)

        req = urllib.request.Request(dest, None, headers, method=api_method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                output = resp.read()
        except urllib.error.HTTPError as e:
            # This is bad here, we don't want a spot where we didn't get the ID
            raise e
                
        output_json = json.loads(output)
        for _, conn in output_json.items():
            if conn["name"] == conn_name:
                print("Found connection ID: {}".format(conn["identifier"]))
                return conn["identifier"]

        raise RuntimeError("Connection not found")

    @Command.register
    def nop(self, *args, **kwargs):
        """
        Command - nop.  Does nothing.  It's useful when you're using Ansible or something automated to create the command file, and the template language is running through a list and doesn't have a good way to leave the last comma off the command list.  With nop you can let it create that list with the last comma, then you can put in a nop with no comma afterwards.

            ["nop"]
        """
        pass

    @Command.register
    @require_token
    def add_user(self, username, password):
        """
        Command - add a Guacamole user.  Example command entry:

            ["add_user", "username", "password"]

        :param username: the Guacamole user name
        :param password: the user password
        """
        print("Creating user: {}".format(username))

        # API Properties
        api_point = "/api/session/data/{dataSource}/users"
        api_method = "POST"
        headers = {"Content-Type": "application/json"}

        # Data to Send
        data_dict = {
            "username": username,
            "password": password,
            "attributes": {
                "disabled": "",
                "expired": "",
                "access-window-start": "",
                "access-window-end": "",
                "valid-from": "",
                "valid-until": "",
                "timezone": None,
                "guac-full-name": "",
                "guac-organization": "",
                "guac-organizational-role": ""
            }
        }

        # Convert formats for Python
        dest = self._get_url(api_point)
        data = json.dumps(data_dict).encode("ascii")

        req = urllib.request.Request(dest, data, headers, method=api_method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                output = resp.read()
        except urllib.error.HTTPError as e:
            output = e.read().decode("utf-8")
            if e.code == 400 and "already exists" in output:
                print("User already exists, not created")
                return False
            else:
                raise e
                
        output_str = output.decode("utf-8")
        if username in output_str:
            print("User created")
            return True
        else:
            raise RuntimeError("Returned: {}".format(output.decode("utf-8")))

    @Command.register
    @require_token
    def add_vnc_connection(self, name, host, port, password):
        """
        Command - create a VNC connection.  Example command entry:

            ["add_vnc_connection", "connection name", "connection_host", 80, "password"]

        :param name: the connection to pair the user to
        :param host: the hostname or address of the VNC server
        :param port: the port the VNC server is running on
        :param password: the VNC server password
        """
        print("Creating vnc connection: {}".format(name))

        # API Properties
        api_point = "/api/session/data/{dataSource}/connections"
        api_method = "POST"
        headers = {"Content-Type": "application/json"}

        # Data to Send
        data_dict = {
            "parentIdentifier": "ROOT",
            "name": name,
            "protocol": "vnc",
            "parameters": {
                "port": "{}".format(port),
                "read-only": "",
                "swap-red-blue": "",
                "cursor": "",
                "color-depth": "",
                "clipboard-encoding": "",
                "disable-copy": "",
                "disable-paste": "",
                "dest-port": "",
                "recording-exclude-output": "",
                "recording-exclude-mouse": "",
                "recording-include-keys": "",
                "create-recording-path": "",
                "enable-sftp": "false",
                "sftp-port": "",
                "sftp-server-alive-interval": "",
                "enable-audio": "",
                "audio-servername": "",
                "sftp-directory": "",
                "sftp-root-directory": "",
                "sftp-passphrase": "",
                "sftp-private-key": "",
                "sftp-username": "",
                "sftp-password": "",
                "sftp-host-key": "",
                "sftp-hostname": "",
                "recording-name": "",
                "recording-path": "",
                "dest-host": "",
                "password": password,
                "username": "",
                "hostname": host,
            },
            "attributes": {
                "max-connections": "",
                "max-connections-per-user": "",
                "weight": "",
                "failover-only": "",
                "guacd-port": "",
                "guacd-encryption": "",
                "guacd-hostname": "",
            }
        }

        # Convert formats for Python
        dest = self._get_url(api_point)
        data = json.dumps(data_dict).encode("ascii")

        req = urllib.request.Request(dest, data, headers, method=api_method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                output = resp.read()
        except urllib.error.HTTPError as e:
            output = e.read().decode("utf-8")
            if e.code == 400 and "already exists" in output:
                print("Connection already exists, not created")
                return False
            else:
                raise e
                
        output_str = output.decode("utf-8")
        if host in output_str:
            print("Connection created")
            return True
        else:
            raise RuntimeError("Returned: {}".format(output.decode("utf-8")))
        
    @Command.register
    @require_token
    def pair_user_connection(self, username, conn_name):
        """
        Command - pair a user with a connection.  Example command entry:

            ["pair_user_connection", "user", "connection"]

        :param username: the username to pair up
        :param conn_name: the connection to pair the user to
        """
        print("Pairing user with connection: {}:{}".format(username, conn_name))

        # First get the connection ID from the name
        conn_id = self._get_connection_id(conn_name)

        # API Properties
        api_point = "/api/session/data/{dataSource}/users/{username}/permissions"
        api_method = "PATCH"
        headers = {"Content-Type": "application/json"}

        # Data to Send
        data_dict = [
            {
                "op": "add",
                "path": "/connectionPermissions/{}".format(conn_id),
                "value": "READ",
            },
        ]

        # Convert formats for Python
        dest = self._get_url(api_point, {"username": username})
        data = json.dumps(data_dict).encode("ascii")

        req = urllib.request.Request(dest, data, headers, method=api_method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                output = resp.read()
        except urllib.error.HTTPError as e:
            output = e.read().decode("utf-8")
            if e.code == 400 and "already exists" in output:
                print("User/connection association already exists, not created")
                return False
            else:
                raise e
                
        output_str = output.decode("utf-8")
        if output_str == "":
            print("User/connection associated")
            return True
        else:
            raise RuntimeError("Returned: {}".format(output_str))

class CommandFile:
    """
    Parses and runs the command file.  Expects the file to contain one json object with keys "server", "admin_user", "initial_admin_pass", "desired_admin_pass", and "commands".  Each must have a value that's a string, except "commands" which has a list.

    server: the URL of the server to connect to, like "https://example.com:4000/"
    admin_user: the username of the admin user, often "guacadmin"
    initial_admin_pass: the original password of the admin user, which will change as soon as possible, often "guacadmin"
    desired_admin_pass: the desired password of the admin user, which gets changed early then can be used on subsequent executions automatically
    commands: a json list of commands

    Commands are also json lists, with a varying number of elements depending on the command.  Commands are defined in the GuacConnection class, and their parameters are documented there.  An example commands list is:

    [
        ["add_user", "user_one", "user_one_password"],
        ["add_vnc_connection", "kali_one", "10.1.1.15", 5901, "vnc_pass"],
        ["pair_user_connection", "user_one", "kali_one"]
    ]
    """

    def __init__(self, cmd_file, delay=False):
        """
        :param cmd_file: an open command file that can be read-from
        :param delay: instructs the GuacConnection to delay for a period
        """
        settings = json.loads(cmd_file.read())
        self.server = settings["server"]
        self.admin_user = settings["admin_user"]
        self.initial_admin_pass = settings["initial_admin_pass"]
        self.desired_admin_pass = settings["desired_admin_pass"]
        self.delay = delay
        self.commands = [
            Command(line[0], line[1:]) for line in settings["commands"]
        ]

    def run(self):
        """
        Execute the commands in the command file
        """
        self.guac = GuacConnection(self.server, self.admin_user, self.initial_admin_pass)
        self.guac.wait_on_server(add_delay=self.delay)
        self.guac.init_guac(self.desired_admin_pass)

        for command in self.commands:
            command.execute(self.guac)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure an Apache Guacamole server")
    parser.add_argument("cmdfile", nargs="?", type=argparse.FileType("r"),
        default="-")
    parser.add_argument("--delay", action="store_true",
        help="Wait 120 seconds after detecting the connection is available to make sure Guacamole is ready.")
    args = parser.parse_args()
    cf = CommandFile(args.cmdfile, args.delay)
    cf.run()
