import sys
import os
import argparse
import subprocess
import logging
import getpass
import time
import warnings
from datetime import datetime

# For output handling of pypsrp in RunspacePool
try:
    from pypsrp.powershell import PSDataStreams
except ImportError:
    PSDataStreams = None
    pass
except Exception:
    pass

warnings.filterwarnings(action='ignore', module='.*kerb.*')

__author__ = "Andy Doran"
__version__ = "3.8"
__copyright__ = "Copyright 2023 ScienceLogic, Inc. All Rights Reserved"
__status__ = "Limited Distribution"

"""
Definitions used for environment configuration and global constants
"""

ENV_None = "Not a collector"
ENV_CU = "CU Appliance"
ENV_CONTAINER = "Container image"
ENV_PY2 = 2
ENV_PY3 = 3

MSG_ENCRYPT_FORCE = "always"
MSG_ENCRYPT_AUTO = "auto"
MSG_ENCRYPT_NEVER = "never"
MSG_ENCRYPT_LIST = [
    MSG_ENCRYPT_AUTO,
    MSG_ENCRYPT_FORCE,
    MSG_ENCRYPT_NEVER
]

PYWINRM_TRANSPORT_KRB = "kerberos"
PYWINRM_TRANSPORT_NT = "ntlm"
PYWINRM_TRANSPORT_PLAINTEXT = "plaintext"
PYWINRM_TRANSPORT_BASIC = "basic"
PYWINRM_TRANSPORT_LIST = [
    PYWINRM_TRANSPORT_KRB,
    PYWINRM_TRANSPORT_NT,
    PYWINRM_TRANSPORT_PLAINTEXT,
    PYWINRM_TRANSPORT_BASIC
]

CERT_VALIDATE_IGNORE = "ignore"
CERT_VALIDATE_VALIDATE = "validate"
CERT_VALIDATE_LIST = [
    CERT_VALIDATE_IGNORE,
    CERT_VALIDATE_VALIDATE
]

"""
Just putting defaults here to make it easier to change if required
"""

DEFAULTS = {
    "cred_host": "%D",
    "cred_name": "Constructed",
    "cred_port_http": 5985,
    "cred_port_https": 5986,
    "cred_timeout": 10000,
    "ps_account_type": 1,
    "ps_encrypted": 0,
    "command": "(Get-CimInstance -ClassName Win32_ComputerSystem).Name",
    "msg_encrypt": MSG_ENCRYPT_AUTO,
    "transport": PYWINRM_TRANSPORT_KRB,
    "kinit_timeout": 10,
    "ping_timeout": 3,
    "cert_validate": CERT_VALIDATE_IGNORE,
    "idle_timeout": 120
}

MIN_PORT = 1024
MAX_PORT = 49151

ORACLE_RELEASE = "/etc/oracle-release"
REDHAT_RELEASE = "/etc/redhat-release"
DEBIAN_RELEASE = "/etc/debian_version"
EM7_VERSION = "/etc/em7-release"

CU_COLLECTOR = "em7-powershell-collector"

STARS = "**************************************************************************************************"

ENV = {
    "collector_version": None,
    "host_type": None,
    "is_collector": None,
    "python_version": sys.version_info[0],
    "os_version": None, 
}

"""
CONNECT_INFO includes the cred dictionary as well as other information used to establish connections to 
Windows Devices
"""

CONNECT_INFO = {
    'cred_host': DEFAULTS["cred_host"], 
    'cred_name': DEFAULTS["cred_name"],
    'cred_port': DEFAULTS["cred_port_http"], 
    'cred_pwd': '', 
    'cred_timeout': DEFAULTS["cred_timeout"], 
    'cred_user': '',
    'ps_account_type': DEFAULTS["ps_account_type"], 
    'ps_ad_domain': '', 
    'ps_ad_host': '', 
    'ps_encrypted': DEFAULTS["ps_encrypted"], 
    'ps_proxy_host': '',
    'ping_timeout': DEFAULTS["ping_timeout"], 
    'target_server': '',
    'connect_server': '',
    'connect_server_host': '',
    'existing_cache': False,
    'kinit_timeout': DEFAULTS["kinit_timeout"],
    'transport': DEFAULTS["transport"],
    'msg_encrypt': DEFAULTS["msg_encrypt"],
    'cert_validate': DEFAULTS["cert_validate"],
    'idle_timeout': DEFAULTS["idle_timeout"],
    "raw": False,
    "command": DEFAULTS["command"],
    "command_list": [],
    "pypsrp": False,
    "actual_ip": None,
    "cache_file": None,
}

DATA = {
    "total_commands": 0,
    "total_errors": 0,
    "total_time": 0,
}

SUMMARY_INFO = {}

"""
Just for debug purposes
"""

LOG_LEVELS = {
    0: "NOTSET",
    10: "DEBUG",
    20: "INFO",
    30: "WARN",
    40: "ERROR",
    50: "FATAL",
}

SERVER_LIST = []

# Process inputs

usage = "Test PowerShell execution on a Windows device. This an also be used to execute non PowerShell Commands"

parser = argparse.ArgumentParser(
    epilog=usage, formatter_class=argparse.RawDescriptionHelpFormatter
)

parser.add_argument("-server", help="Target Windows Device")
parser.add_argument("-sl", "--server-list", help="File containing a list of servers, one per line", dest="sl")
parser.add_argument("-cred", help="Credential ID for the existing defined credential (overrides other parameters indicated below)", type=int, dest="c")
parser.add_argument("-user", help="Windows user - USER@DOMAIN.COM, DOMAIN\\USER or just USER (for local account, -c overrides this parameter)")
parser.add_argument("-pwd", help="Windows password (if not supplied, you will be prompted unless -cred is used)")
parser.add_argument("-wsman", help="Use WSMAN service (default is HTTP)", action="store_true")
parser.add_argument("-host", help="use HOST service (default is HTTP)", action="store_true")
parser.add_argument("-https", help="use HTTPS protocol (default is HTTP)", action="store_true")
parser.add_argument("-http", help="use HTTP protocol to override -cred setting", action="store_true")
parser.add_argument("-port", help="Port to use (default is 5985 for HTTP or 5986 for HTTPS)", type=int)
parser.add_argument("-proxy", help="Windows Proxy to target")
parser.add_argument("-np", "--no-ping", help="Do not attempt an ICMP ping", action="store_true", dest="np")
parser.add_argument("-pt", "--ping-timeout", help="Ping timeout in seconds, default is 3", type=int, default=3, dest="pt")
parser.add_argument("-uekc", "--use-existing", help="Use existing kerberos cache file", action="store_true", dest="uekc")
parser.add_argument("-ktime", "--kinit-timeout", help="kinit timeout (default 10 seconds)", type=int, default=10, dest="ktime")
parser.add_argument("-encrypt", "--message-encryption", help="Message encryption (default is %s)" % DEFAULTS["msg_encrypt"], choices=MSG_ENCRYPT_LIST, default=DEFAULTS["msg_encrypt"], dest="encrypt")
parser.add_argument("-transport", help="Message transport", choices=PYWINRM_TRANSPORT_LIST, default=DEFAULTS["transport"])
parser.add_argument("-validation", help="Certificate validation when HTTPS is used (default is %s" % DEFAULTS["cert_validate"], choices=CERT_VALIDATE_LIST, default=DEFAULTS["cert_validate"])
parser.add_argument("-idle", "--winrm-idletimeout", help="Idle timeout for WinRM shell (default %s seconds)" % DEFAULTS["idle_timeout"], type=int, default=DEFAULTS["idle_timeout"], dest="idle")
parser.add_argument("-raw", help="Raw command (no PowerShell wrapper)", action="store_true")
parser.add_argument("-cmd", help="Command to run, default is %s" % DEFAULTS["command"])
parser.add_argument("-noprofile", help="Run PowerShell with no profile", action="store_true")
parser.add_argument("-new", "--use-pypsrp", help="Use \"new\" processing (pypsrp module)", action="store_true", dest="new")
parser.add_argument("-d", "--debug-logging", help="Verbose (DEBUG) logging", action="store_true", dest="v")
parser.add_argument("-force", help="Force execution if not running on a collector", action="store_true", dest="run_anyway")
parser.add_argument("-ll", "--line-length", help="Line length for explanation text", type=int, default=132, dest="line_length")
parser.add_argument("-lf", "--log-tofile", help="Log to file", action="store_true", dest="lf")
parser.add_argument("-sp", "--suppress-output", help="No output from successful commands", action="store_true", dest="sp")
parser.add_argument("-pool", "--pypsrp-pool", help="Use pypsrp pooling", action="store_true", dest="pool")
parser.add_argument("-ld", "--leave-domain", help="Do not convert Domain to uppercase when reading credentials", action="store_true", dest="leave_domain")
parser.add_argument("-fi", "--force-ip", help="Force IP for endpoint", action="store_true", dest="fi")
parser.add_argument("-ep", "--alternate-endpoint", help="Alternate endpoint instead of wsman", dest="ep")
parser.add_argument("-sum", "--summary-information", help="Only show pass/fail with no additional information", action="store_true", dest="sum")

args = parser.parse_args()

"""
Configure logging to stdout and use the format of 
    
    INFO <message>

"""

formatter = logging.Formatter('%(levelname)s: %(message)s')

logger = logging.Logger(__name__)
logger.level = logging.DEBUG if args.v else logging.INFO

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)

logger.addHandler(stdout_handler)

LOG_LEVEL = LOG_LEVELS[logger.level]

"""
Notice ...
"""

print(
    "\n%s\nSL1 PowerShell Credential and execution testing utility\n\nVersion:   %s\nStatus:    %s\n\nLog level: %s\n%s\n\n"
    % (STARS, __version__, __status__, LOG_LEVEL, STARS)
)

if args.lf:
    log_file = "/tmp/%s.log" % str(__file__).split("/")[-1]
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    logger.info("Logging to file: %s" % log_file)
    logger.info("Start: %s" % (datetime.now().strftime("%d-%h-%Y %H:%M:%S")))

#########################################################################################
# Global routines
#########################################################################################


def valid_args():
    """
    Validate the inputs that we get
    """

    valid = True
    errors = ""

    # If a server list is provided, that overrides the individual server. But first check
    # that the list is valid
    if args.sl is not None:
        if os.path.exists(args.sl):
            try:
                with open(args.sl, "r") as server_list:
                    lines = server_list.readlines()
                server_list.close()
            except IOError as e:
                errors += "\n  Unable to open server lost input. Error: %s" % e
                valid = False
            except Exception as e:
                errors += "\n  Unknown error opening server list. Error: %s" %e
                valid = False
            else:
                for line in lines:
                    SERVER_LIST.append(line.strip())
        else:
            errors += "\n  The server list file does not exist"
            valid = False

    if not valid:
        return valid, errors

    if len(SERVER_LIST) == 0:
        # We must have a target server to check
        if args.server is None or len(args.server) == 0:
            errors += "\n  You must supply a target server"
            valid = False
        else:
            SERVER_LIST.append(args.server)

    # Make sure that we have a credential and that it is in range
    if args.c is not None:
        if args.c < 1:
            errors += "\n  The credential id supplied is not valid: %s" % args.c
            valid = False
    else:
        # This is OK if credential information is manually supplied
        CONNECT_INFO["cred_name"] = DEFAULTS["cred_name"]

        if args.user is None:
            errors += "\n  No username was supplied"
            valid = False
        else:
            # Determine if this is a domain user or Local user
            CONNECT_INFO["cred_user"] = args.user

            if args.user.find("\\") > -1 or args.user.find("@") > -1:
                CONNECT_INFO["ps_account_type"] = 1
                CONNECT_INFO["transport"] = PYWINRM_TRANSPORT_KRB

                if args.user.find("@") > -1:
                    CONNECT_INFO["cred_user"] = args.user.split("@")[0]
                    CONNECT_INFO["ps_ad_domain"] = args.user.split("@")[1]
                else:
                    CONNECT_INFO["ps_ad_domain"] = args.user.split["\\"][0]
                    CONNECT_INFO["cred_user"] = args.user.split("\\")[1]

                CONNECT_INFO["ps_ad_domain"] = CONNECT_INFO["ps_ad_domain"] if args.leave_domain else CONNECT_INFO["ps_ad_domain"].upper()
            else:
                CONNECT_INFO["ps_account_type"] = 2
                CONNECT_INFO["transport"] = PYWINRM_TRANSPORT_BASIC if args.new else PYWINRM_TRANSPORT_PLAINTEXT
                CONNECT_INFO["msg_encrypt"] = MSG_ENCRYPT_NEVER

            if args.transport is not None:
                CONNECT_INFO["transport"] = args.transport

            if args.pwd is not None:
                CONNECT_INFO["cred_pwd"] = args.pwd
            
        
        if args.https:
            # Encrypted
            if args.port is not None:
                CONNECT_INFO["cred_port"] = args.port
            else:
                CONNECT_INFO["cred_port"] = DEFAULTS["cred_port_https"]

            CONNECT_INFO["ps_encrypted"] = 1
        else:
            # Not Encrypted
            if args.port is not None:
                CONNECT_INFO["cred_port"] = args.port
            else:
                CONNECT_INFO["cred_port"] = DEFAULTS["cred_port_http"]

            CONNECT_INFO["ps_encrypted"] = 0

        if CONNECT_INFO["cred_port"] < MIN_PORT:
            errors += "\n   The port %s is below the minimum value which is %s" % (CONNECT_INFO["cred_port"], MIN_PORT)
            valid = False
        if CONNECT_INFO["cred_port"] > MAX_PORT:
            errors += "\n   The port %s is above the maximum value which is %s" % (CONNECT_INFO["cred_port"], MAX_PORT)
            valid = False

        if args.wsman:
            CONNECT_INFO["cred_host"] = "WSMAN://%D"
        elif args.host:
            CONNECT_INFO["cred_host"] = "HOST://%D"
        else:
            CONNECT_INFO["cred_host"] = "%D"

        CONNECT_INFO["ps_proxy_host"] = args.proxy if args.proxy is not None else ''

    if args.pt:
        CONNECT_INFO["ping_timeout"] = args.pt
        if CONNECT_INFO["ping_timeout"] < 1:
            CONNECT_INFO["ping_timeout"] = 1
        if CONNECT_INFO["ping_timeout"] > 30:
            CONNECT_INFO["ping_timeout"] = 30

    if args.ktime:
        CONNECT_INFO["kinit_timeout"] = args.ktime
        if CONNECT_INFO["kinit_timeout"] < 1:
            CONNECT_INFO["kinit_timeout"] = 1
        if CONNECT_INFO["kinit_timeout"] > 60:
            CONNECT_INFO["kinit_timeout"] = 60

    #CONNECT_INFO["transport"] = args.transport if args.transport is not None else DEFAULTS["transport"]
    CONNECT_INFO["msg_encrypt"] = args.encrypt if args.encrypt is not None else DEFAULTS["msg_encrypt"]
    CONNECT_INFO["cert_validate"] = args.validation if args.validation is not None else DEFAULTS["cert_validate"]
    CONNECT_INFO["existing_cache"] = args.uekc if args.uekc is not None else False

    idle_timeout = args.idle if args.idle is not None else 270

    if idle_timeout < 60:
        idle_timeout = 60
    if idle_timeout > 7200:
        idle_timeout = 7200

    # Now ISO8601 format - there is a library to do this (isodate) but rather than include that just for this
    # conversion - use our own code here. W4 are limited to hours so do not need to be concerned with days,
    # weeks etc.

    iso_seconds = 1
    iso_minutes = iso_seconds * 60
    iso_hours = iso_minutes * 60
    iso_seconds_text, iso_minutes_text, iso_hours_text = ("0S", "0M", "0H")

    if idle_timeout >= iso_hours:
        iso_hours_text = "{0}H".format(idle_timeout // iso_hours)
        idle_timeout = idle_timeout % iso_hours

    if idle_timeout >= iso_minutes:
        iso_minutes_text = "{0}M".format(idle_timeout // iso_minutes)
        idle_timeout = idle_timeout % iso_minutes

    iso_seconds_text = "{0}S".format(idle_timeout)
    CONNECT_INFO["idle_timeout"] = "PT{0}{1}{2}".format(iso_hours_text, iso_minutes_text, iso_seconds_text)

    # Command

    CONNECT_INFO["command"] = args.cmd if args.cmd is not None else DEFAULTS["command"]
    CONNECT_INFO["raw"] = args.raw if args.raw is not None else False

    if args.new:
        # We will have to stop here if pypsrp is not available"
        try:
            import pypsrp
            CONNECT_INFO["pypsrp"] = True
            del pypsrp
        except ImportError:
            errors += "\n   The pypsrp module cannot be loaded - this option is available in the container"
            valid = False
        except Exception as e:
            errors +="\n   There was an error loading the pypsrp module: %s" % e
            valid = False
    else:
        # Make sure winrm is there
        try:
            import winrm
            del winrm
        except ImportError:
            errors += "\n   The winrm module is not available, install this package or run on a Collector"
            valid = False
        except Exception as e:
            errors +="\n   There was an error loading the winrm module: %s" % e
            valid = False

    return valid, errors


#########################################################################################
# Classes to handle kerberos
#########################################################################################

class kerberos():
    """
    run kinit to get a kerberos ticket, or optionally use the esisting cache file
    """

    def __init__(self, logger, connection_info, env):
        from subprocess import Popen, PIPE
        self.Popen = Popen
        self.PIPE = PIPE
        self.logger = logger
        self.connect_info = connection_info
        self.env = env
        self.error_handler = error_handler(logger)


    def set_cache(self, filename):
        """
        Set the environment variable for the cache file
        """

        self.logger.info("Setting kerberos cache to: %s" % filename)
        self.connect_info["existing_cache"] = True
        self.connect_info["cache_file"] = filename
        os.environ["KRB5CCNAME"] = filename


        
    def kinit(self):
        """
        Either use the existing cache file or run kinit to create one
        """

        if self.connect_info["ps_account_type"] == 2:
            self.logger.debug("Using a local account, no kinit setup required")
            return True

        cache_file = "krb5cc_%s_%s" % (self.connect_info["ps_ad_domain"], self.connect_info["cred_user"])

        # If we are to use an existing cache file - check that it exists first

        if self.connect_info["existing_cache"]:
            existing_file = self.connect_info["cache_file"] if self.connect_info["cache_file"] is not None else "/tmp/%s" % cache_file
            self.logger.info("Checking existing kerberos cache file: %s" % existing_file)

            if not os.path.exists(existing_file):
                self.logger.error("The existing cache file cannot be found")
                return False
            else:
                self.set_cache(existing_file)
                return True

        # If we are here then we need to run kinit using a test file name
        new_file = "/tmp/test_%s" % cache_file
        location = "running kinit"

        self.logger.info(
            "Using kinit to obtain ticket for %s in domain: %s"
            % (self.connect_info["cred_user"], self.connect_info["ps_ad_domain"])
        )

        try:
            param = "%s@%s" % (self.connect_info["cred_user"], self.connect_info["ps_ad_domain"])
            ph = self.Popen(["kinit", "-c", new_file, param], stdout=self.PIPE, stderr=self.PIPE, stdin=self.PIPE)

            location = "sending password"
            password = self.connect_info["cred_pwd"]

            if self.env["python_version"] == ENV_PY3:
                location += " with %s second timeout" % self.connect_info["kinit_timeout"]
                _stdout, _stderr = ph.communicate(bytes(password, "utf-8"), timeout=self.connect_info["kinit_timeout"])
            else:
                _stdout, _stderr = ph.communicate(password)
        except Exception as exc:
            self.error_handler.suggest_kinit(
                "Error encountered processing kerberos ticket at %s. The following call failed:\n\n"
                "  kinit -c %s %s\n\n"
                "The error returned was: %s"
                % (location, cache_file, param, exc)
            )
            return False

        # Check there were no additional problems

        rc = ph.returncode

        if rc != 0:
            if _stderr:
                if type(_stderr) == bytes:
                    _err = _stderr.decode("utf-8")
                else:
                    _err = str(_stderr)

                self.error_handler.suggest_kinit(
                    "Failed obtaining ticket with error:\n\n%s" % _err
                )
            else:
                self.error_handler.suggest_kinit(
                    "Error code %s returned when calling kiniit. Make sure .etc.krb5.conf is correctly setup"
                    % rc
                )
            return False
        else:
            self.set_cache(new_file)

        self.logger.info("Kerberos ticket obtained - credentials are OK")
        return True

#########################################################################################
# Class to prepare command
#########################################################################################

class command_handler():
    """
    Class to provide a list of commands to execute based on input (ie a single command, file or directory)
    """

    def __init__(self, logger, connect_info, env, encode=True):
        import base64
        self.base64 = base64
        self.logger = logger
        self.connect_info = connect_info
        self.env = env
        self.encode = encode
        self.proxy_wrapper = self.get_wrapper()

    def get_wrapper(self):
        """
        Just pick up the wrapper that will be used if a proxy server is needed
        """

        wrapper = (
            '$pwd=ConvertTo-SecureString -String "%s" -AsPlainText -Force;'
            '$cred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "%s",$pwd;'
            "$ses=New-PSSession -ComputerName %s -Credential $cred;"
            "Invoke-Command -Session $ses -ScriptBlock { %s } | %s | Out-String -Width 250;exit;"
            "Remove-PSSession $ses;"
        )
        return wrapper


    def format_from_file(self, data):
        """
        The inoput from the file will be a list, so turn that into a string. Simple str was not doing it
        :param data:
        :return:
        """

        return_data = ""

        for line in data:
            return_data += "%s\n" % line

        return return_data

    def add_file_contents(self, filename):
        """
        Add this file to the list
        """

        if os.path.isfile(filename):
            self.logger.debug(
                "Reading file: %s" % filename
            )

            try:
                with open(filename, "r") as ps_file:
                    my_cmd = self.format_from_file(ps_file.readlines())
                
                self.build_individual(my_cmd)
            except Exception as e:
                self.logger.error(
                    "Failed to read script file %s. Error: %s"
                    % (filename, e)
                )


    def read_from_files(self):
        """
        Read the commands from file(s)
        """

        if os.path.isfile(self.connect_info["command"]):
            self.add_file_contents(self.connect_info["command"])
        else:
            all_files = os.listdir(self.connect_info["command"])

            for file_name in all_files:
                full_name = "%s/%s" % (self.connect_info["command"], file_name)
                self.add_file_contents(full_name)


    def build_individual(self, in_command):
        """
        Prepare the individual command to run
        """

        self.logger.debug("Building individual command")

        if self.connect_info["ps_proxy_host"]:
            self.logger.debug(
                "Proxy is being used, command will be wrapped for use"
            )
            user = self.connect_info["cred_user"]

            if self.connect_info["ps_account_type"] == 1:
                user += "@%s" % self.connect_info["ps_ad_domain"]
            # fl is the default - one day we can allow an option to override
            command = self.proxy_wrapper % (
                self.connect_info["cred_pwd"],
                user,
                self.connect_info["target_server"],
                in_command,
                "fl"
            )
        else:
            command = in_command

        if args.noprofile:
            powershell_template = "powershell.exe -NoProfile -EncodedCommand %s"
        else:
            powershell_template = "powershell.exe -EncodedCommand %s"

        if self.connect_info["raw"] or not self.encode:
            # Not PowerShell, so no encoding needed
            self.connect_info["command_list"].append(command)
        else:
            try:
                encoded_cmd = self.base64.b64encode(command.encode("utf-16-le"))

                if self.env["python_version"] == ENV_PY3:
                    encoded_cmd = encoded_cmd.decode("ascii")
            except Exception as e:
                self.logger.error(
                    "Unable to base64 encode command: %s" % command
                )
                self.logger.error("Error: %s" % e)
                return

            self.connect_info["command_list"].append(powershell_template % encoded_cmd)


    def prepare_command_list(self):
        """
        Build a list of commands - normally just one, but we allow a directory to be read as well
        """

        if os.path.exists(self.connect_info["command"]):
            self.read_from_files()
        else:
            self.build_individual(self.connect_info["command"])


#########################################################################################
# Class to handle errors
#########################################################################################

class error_handler():
    """
    Common error handler class
    """

    def __init__(self, logger):
        import xml.etree.ElementTree as ET
        import re
        self.ET = ET
        self.re = re
        self.logger = logger
        self.CLIXML = "CLIXML"
        self.CLIXML_ERR_SIG = ""
        self.CLIXML_REMOVE = "_x000D__x000A_"
        self.CLIXML_SCHEMA = "{http://schemas.microsoft.com/powershell/2004/04}"


    def get_gss_error(self, raw_error):
        """
        Try to pull the useful GSS Error from the error message
        """

        if str(raw_error).find("GSS") < 0:
            self.logger.debug(
                "Raw error is not a GSS error"
            )
            return raw_error

        arr = str(raw_error).split("),")
        error = ""
        
        if len(arr) > 1:
            self.logger.debug(
                "Processing GSS error: %s" % arr
            )
            error = arr[-1].replace("))", ")")

        if len(error) == 0 or error is None:
            error = raw_error

        return error

    def parse_cli_xml_error(self, raw_data):
        """
        Use Xml parsing to determine if the meassage is simply informational or an error
        :param raw_data:
        :return:
        """

        is_error = False
        error_data = ""
        short_error = ""

        if raw_data.find(self.CLIXML) > -1:
            # Only process if this is CLIXML

            try:
                location = "setting Xml tree"
                tree = self.ET.fromstring(raw_data.replace(self.CLIXML, "").replace("#<", ""))

                location = "starting Xml processing"
                child_loop = 0

                for child in tree:
                    child_loop += 1
                    location = "processn Xml child node {0}".format(child_loop)

                    if child.attrib["S"] == "Error":
                        location += ", attribute is error"
                        is_error = True
                        error_line = child.text.replace(self.CLIXML_REMOVE, "").replace("\\'", "'")
                        error_data += "{0}".format(error_line)

                        #
                        # For display. Looks odd but Microsoft use a message format of
                        #
                        # MESSAGE HERE
                        #   + CONTINUE HERE
                        #   + CONTINUE HERE
                        #
                        # And also try to format within x characters, so some lines are
                        #
                        #   + CONINUE HERE BUT
                        #       BREAKS HERE
                        #

                        if error_line.lstrip()[0:1] != "+" and error_line.lstrip() == error_line:
                            short_error += "{0}".format(error_line)

            except BaseException as err:
                self.logger.error(
                    "PowerShell runtime error, failed to process raw error message when {0}. The error was: {1} and the"
                    "message being processed was: {2}".format(location, err, raw_data)
                )
                error_data = raw_data
                short_error = raw_data

        else:
            error_data = raw_data
            short_error = raw_data

        return is_error, short_error


    def word_wrap(self, raw_data):
        """
        Wrap to a predefined length to make the message look nice
        """

        return_paragraph = ""

        # First split at \n
        for line in raw_data.split("\n"):
            # Now create a new line of the specified length
            new_line = ""
            constructed_line = ""

            for word in line.split(" "):
                if len(new_line) + len(word) >= args.line_length:
                    constructed_line += "\n%s" % word
                    new_line = ""
                else:
                    constructed_line += ("%s" % word if len(constructed_line) == 0 else " %s" % word)
                    new_line += ("%s" % word if len(new_line) == 0 else " %s" % word)

            return_paragraph += "\n%s" % constructed_line

        return return_paragraph


    def suggest_cred_rejected(self, basic_error):
        """
        If there is a problem with the creds
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "The credentials supplied are valid (username and password correct), but the user does not  have access to the "
            "target server. This might be a permissions issue, or it could be that the spn is already in use for another "
            "application. Verify the user permissions on the target server (or test with an administrator account). Also "
            "check the spn on the target server - by default HTTP is used, so if that is not available try using WSMAN or "
            "HOST instead. To check the spn settings on the Windows device use the commands:\n\n"
            "\tsetspn -Q HTTP/<host>\n\tsetspn -Q HTTP/<FQDN>\n\n"
            "replacing <host> and <FQDN> with the host/FQDN of the Windows device. If an entry for HTTP appears under a user account, "
            "then the WSMAN or HOST options should be used. Also verify the Windows device is a member of the specified Domain if "
            "Active Directory is being used."
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


    def suggest_krb_exchange(self, basic_error):
        """
        kerberosExchangeError
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
        )

        formatted_err = str(basic_error) if type(basic_error) == str else basic_error.decode("utf-8")

        if self.re.search(r'Server not found in Kerberos database', formatted_err):
            suggestion += (
                "Kerberos requires the host resolution to match on the client - where the connection is being made from - to "
                "the target. This means that if the client resolves an IP address to SERVER1, then the target server name must "
                "be the same (SERVER1). If the target server name is SERVER2 then kerberos will reject the connection.\n\nAdditionally "
                "when using kerberos (the user account is in a Windows Domain) the target server must be a member of that Domain. If "
                "either of these is not true then the \"Server not found in Kerberos database\" message is returned. In this case, "
                "the Kerberos database is the Windows Active Directory."
            )
        else:
            suggestion += (
                "The credentials supplied are valid (username and password correct), but the user does not  have access to the"
                "target server. This might be a permissions issue, or it could be that the spn is already in use for another "
                "application. Verify the user permissions on the target server (or test with an administrator account). Also"
                "check the spn on the target server - by default HTTP is used, so if that is not available try using WSMAN or "
                "HOST instead. To check the spn settings on the Windows device use the commands:\n\n"
                "\tsetspn -Q HTTP/<host>\n\tsetspn -Q HTTP/<FQDN>\n\n"
                "replacing <host> and <FQDN> with the host/FQDN of the Windows device. If an entry for HTTP appears under a user account, "
                "then the WSMAN or HOST options should be used. Also verify the Windows device is a member of the specified Domain if "
                "Active Directory is being used."
            )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


    def suggest_shell(self, basic_error):
        """
        If there is an error at the point of creating the command shell
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "An error at this stage means that authentication was successful, but that there was an issue at the target server. Make "
            "sure that the user has permissions on the target server, and that the spn configuration is correct. If the HTTP spn "
            "has been used then try credentials using WSMAN or HOST. Verify the spn settings on the Windows device using:\n\n"
            "\tsetspn -Q HTTP/<host>\n\tsetspn -Q HTTP/<FQDN>\n\n"
            "replacing <host> and <FQDN> with the host/FQDN of the Windows device. If an entry for HTTP appears under a user account, "
            "then the WSMAN or HOST options should be used. Also verify the Windows device is a member of the specified Domain if "
            "Active Directory is being used."
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


    def suggest_read(self, basic_error):
        """
        If there is an error at the point of creating the command shell
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "An error at this stage means that authentication was successful, and the command was issued to the target device, "
            "but that there was a problem in retrieving the output. This could be a problem with PowerShell. To verify whether "
            "this is the case (if pyWinRM is being used), the \"raw\" option could be used:\n\n"
            "\t-raw -cmd PATH\n\n"
            "This would verify whether or not there is a problem invoking powershell.exe"
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


    def suggest_protocol(self, basic_error):
        """
        If there is an error at the point of creating the command shell
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "An error at this stage means that authentication was successful, but that there was an issue connecting to the target "
            "device using the WinRM protocol. Make sure that the winrm service is running on the target device, and that it is "
            "reachable."
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


    def suggest_transport_error(self, basic_error):
        """
        If there is an error at the point of creating the command shell
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "An error at this stage means that authentication was successful, but that there was an issue connecting to the target "
            "device using the WinRM transport. Make sure that the winrm service is running on the target device, and that it is "
            "reachable. This error can happen if the endpoint page does not exist (the default is wsman)"
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)

    def suggest_lookup(self, basic_error):
        """
        If there is an error at the point of forward/reverse lookup
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "An error at this stage means that the target device could not be correctly resolved. Make sure that either DNS "
            "or /etc/hosts is configured correctly to allow forward and reverse lookup (in the case of DNS - a reverse "
            "lookup zone should be defined)."
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


    def suggest_kinit(self, basic_error):
        """
        If there is an error running kinit
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "An error running the kinit command means that a ticket could not be granted. At this stage, the problem is "
            "that there was no response (or an unexpected response) from the Domain Controller for the domain that the "
            "specified user belongs to.\n\nThis could mean that DNS/hosts is not configured to provide host resolution for "
            "the Windows Domain or the Domain Controller itself. It may also be the case that the Domain Controller is not "
            "responding in a reasonable time. Check that a realm and at least one kdc is defined for the Windows Domain "
            "in the /etc/krb5.conf file - and that the kdc is resolvable.\n\nNote that on some Linux platforms, the command "
            "will prompt for the password even if that was supplied to the script, and failure to provide it at the prompt "
            "will lead to a timeout error."
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


    def suggest_execution_error(self, basic_error):
        """
        The command failed to run and so is maybe invalid
        """

        if args.sum:
            return

        suggestion = (
            "Possible Explanations:\n"
            "======================\n\n"
            "A connection was sucessfully established to the Windows device, so the credentials are valid and the transport "
            "has been been used to invoke the specified command. However, the command itself is either not valid or has "
            "generatred an error on execution."
        )

        full_error = "%s\n\n%s\n" % (basic_error, self.word_wrap(suggestion))
        self.logger.error(full_error)


#########################################################################################
# Class to handle pypsrp
#########################################################################################

class pypsrp_transport():
    """
    Connection using pypsrp

    https://github.com/ansible/ansible/blob/9ff26a4a22defc05d4a6ba9e650f74670067a51a/lib/ansible/plugins/connection/psrp.py#L1
    """

    def __init__(self, logger, connect_info, env):
        from pypsrp import exceptions
        from pypsrp.client import Client
        from pypsrp.powershell import PowerShell, RunspacePool
        from pypsrp.wsman import WSMan
        from spnego.exceptions import SpnegoError
        self.exceptions = exceptions
        self.Client = Client
        self.PowerShell = PowerShell
        self.RunspacePool = RunspacePool
        self.WSMan = WSMan
        self.SpnegoError = SpnegoError
        self.client = None
        self.wsman = None
        self.host = None
        self.runspace = None
        self.logger = logger
        self.connect_info = connect_info
        self.env = env
        self.error_handler = error_handler(logger)
        self.connect_server = None


    def prepare_connect(self):
        """
        Connect to the server
        """

        # For us, "encrypted" means HTTPS
        if self.connect_info["ps_encrypted"]:
            validate = self.connect_info["cert_validate"]
            ssl = True
        else:
            validate = CERT_VALIDATE_IGNORE
            ssl = False
            #self.connect_info["msg_encrypt"] = MSG_ENCRYPT_NEVER

        connect_server = self.connect_info["connect_server_host"] if len(self.connect_info["connect_server_host"]) > 0 else self.connect_info["connect_server"]
        host_from_cred = self.connect_info["cred_host"].replace("%D", connect_server)
        self.logger.debug(
            "Host information: %s" % host_from_cred
        )

        if host_from_cred.find(":") > 0:
            # WSMAN or HOST
            service = host_from_cred.split(":")[0]
            connect_server = host_from_cred.split(":")[1].replace("/", "")
        else:
            service = "HTTP"
            connect_server = host_from_cred

        self.connect_server = connect_server
        if connect_server not in SUMMARY_INFO:
            SUMMARY_INFO[connect_server] = {}

        self.logger.debug(
            "Using host: %s, service: %s" % (connect_server, service)
        )

        kwargs = {
            "server": connect_server,
            "ssl": ssl,
            "port": self.connect_info["cred_port"],
            "encryption":  self.connect_info["msg_encrypt"],
            "auth": self.connect_info["transport"],
            "negotiate_service": service,
            "cert_validation": validate,
            "operation_timeout": 20,
            "connection_timeout": 30,
            "read_timeout": 30,
        }

        display_password = "**********"

        if self.connect_info["ps_account_type"] == 1:
            _user = "%s@%s" % (self.connect_info["cred_user"], self.connect_info["ps_ad_domain"])
            display_user = "%s (kerberos ticket being used)" % _user
            cache = os.getenv("KRB5CCNAME")
        else:
            kwargs["username"] = self.connect_info["cred_user"]
            kwargs["password"] = self.connect_info["cred_pwd"]
            display_user = self.connect_info["cred_user"]
            cache = "N/A"

        if not args.sum:
            self.logger.info(
                "pypsrp Client information:\n"
                "      server:          %s\n"
                "      port:            %s\n"
                "      ssl:             %s\n"
                "      auth:            %s\n"
                "      username:        %s\n"
                "      password:        %s\n"
                "      cert validation: %s\n"
                "      service:         %s\n"
                "      msg encryption:  %s\n"
                "      oper timeout:    %s\n"
                "      conn timeout:    %s\n"
                "      read timeout     %s\n"
                "      cache:           %s"
                % (
                    kwargs["server"],
                    kwargs["port"],
                    ssl,
                    kwargs["auth"],
                    display_user,
                    display_password,
                    validate,
                    service,
                    kwargs["encryption"],
                    kwargs["operation_timeout"],
                    kwargs["connection_timeout"],
                    kwargs["read_timeout"],
                    cache
                )
            )

        SUMMARY_INFO[self.connect_server]["Result"] = True
        SUMMARY_INFO[self.connect_server]["Message"] = "Connect OK"

        try:
            if args.pool:
                self.logger.debug("Using pypsrp WSMan (pool) connection")
                self.wsman = self.WSMan(**kwargs)
                self.runspace = self.RunspacePool(self.wsman)
                self.runspace.open()
            else:
                self.logger.debug("Using pypsrp Client connection")
                self.client = self.Client(**kwargs)
        except Exception as e:
            self.logger.error(
                "Failed in establishing pypsrp connection to server %s. Error: %s"
                % (kwargs["server"], e)
            )
            SUMMARY_INFO[self.connect_server]["Result"] = False
            SUMMARY_INFO[self/connect_server]["Message"] = e

    def get_command(self):
        """
        Prepare the command
        """

        ch = command_handler(self.logger, self.connect_info, self.env, False)
        ch.prepare_command_list()


    def execute_client(self, command):
        """
        Actually execute the command and read the output
        """

        try:
            start = time.time()
            result = self.client.execute_ps(command)
            exec_time = time.time() - start
            DATA["total_time"] += exec_time
            timer_run = "{0:.2f}".format(exec_time)
            self.logger.info(
                "Command executed in %s seconds" % timer_run
            )
        except self.exceptions.AuthenticationError as e:
            self.error_handler.suggest_cred_rejected(str(e))
            DATA["total_errors"] +=1
            SUMMARY_INFO[self.connect_server]["Result"] = False
            SUMMARY_INFO[self.connect_server]["Message"] = str(e)
            return
        except self.SpnegoError as e:
            DATA["total_errors"] +=1
            self.error_handler.suggest_krb_exchange(str(e))
            SUMMARY_INFO[self.connect_server]["Result"] = False
            SUMMARY_INFO[self.connect_server]["Message"] = str(e)
            return
        except Exception as e:
            DATA["total_errors"] +=1
            self.logger.debug(
                "Exception of type: %s" % type(e)
            )
            SUMMARY_INFO[self.connect_server]["Result"] = False
            SUMMARY_INFO[self.connect_server]["Message"] = str(e)
            self.error_handler.suggest_shell(e)
            return

        stdout = result[0]
        has_errors = result[2]
    
        if stdout and not (args.sp or args.sum):
            self.logger.info("Command output:")
            print("\n%s\n" % stdout)

        if has_errors:
            DATA["total_errors"] +=1
            stderr = result[1].error[0]
            self.error_handler.suggest_execution_error(stderr)
            SUMMARY_INFO[connect_server]["Result"] = False
            SUMMARY_INFO[connect_server]["Message"] = stderr


    def run_command(self):
        """
        Wrapper to run command via Client or WSMan
        """

        if args.pool:
            self.logger.info("Running command(s) in a RunspacePool")
            self.run_command_wsman()
        else:
            self.logger.info("Running command(s) individually")
            self.run_command_client()


    def run_command_wsman(self):
        """
        Run commands together in a pool
        """

        # First we need to connect
        self.prepare_connect()

        if self.wsman is None or self.runspace is None:
            self.logger.info(
                "failed to prepare the connection, so exiting the process"
            )
            return

        self.get_command()
        DATA["total_commands"] = len(self.connect_info["command_list"])

        if DATA["total_commands"] == 0:
            self.logger.info("No commands to execute")
            return

        command_num = 1

        for command in self.connect_info["command_list"]:
            self.logger.info(
                "Executing command: %s of %s" %
                (command_num, DATA["total_commands"])
            )
            #self.logger.debug("Command: %s" % command)
            start = time.time()

            result = self.execute_script_in_pool(command)

            exec_time = time.time() - start
            DATA["total_time"] += exec_time
            timer_run = "{0:.2f}".format(exec_time)
            self.logger.info(
                "Executed command in %s seconds" % timer_run
            )

            stdout = result[0]
            has_errors = result[2]

            if stdout and not (args.sp or args.sum):
                self.logger.info("Command output:")
                print("\n%s\n" % stdout)

            if has_errors:
                DATA["total_errors"] += 1
                stderr = result[1].error[0]
                self.error_handler.suggest_execution_error(stderr)
                SUMMARY_INFO[self.connect_server]["Result"] = False
                SUMMARY_INFO[self.connect_server]["Message"] = stderr

            command_num +=1


    #def execute_script_in_pool(self, command) -> typing.Tuple[str, PSDataStreams, bool]:
    def execute_script_in_pool(self, command):

        ps = self.PowerShell(self.runspace)
        ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
        ps.add_cmdlet("Out-String").add_parameter("Stream")
        ps.invoke()
        return "\n".join(ps.output), ps.streams, ps.had_errors


    def run_command_client(self):
        """
        Run the command
        """

        # First we need to connect
        self.prepare_connect()

        if self.client is None:
            self.logger.info(
                "failed to prepare the connection, so exiting the process"
            )
            return

        #actual_command = self.get_command()
        self.get_command()
        DATA["total_commands"] = len(self.connect_info["command_list"])

        if DATA["total_commands"] > 0:
            command_num = 1

            for command in self.connect_info["command_list"]:
                self.logger.info(
                    "Executing command: %s of %s" %
                    (command_num, DATA["total_commands"])
                )
                self.execute_client(command)
                command_num +=1
        else:
            self.logger.info("No commands were found to execute")


#########################################################################################
# Class to handle pywinrm
#########################################################################################

class pywinrm_transport():
    """
    Connection using pywinrm
    """

    def __init__(self, logger, connect_info, env):
        # This "warnings" code ignores a deprecation message from kerberos for Cryptography
        # when using Python 2
        # import xml.etree.ElementTree as ET
        import warnings 
        warnings.filterwarnings(action='ignore',module='.*kerb.*')
        import winrm
        from kerberos import BasicAuthError
        self.winrm = winrm
        self.BasicAuthError = BasicAuthError
        self.logger = logger
        self.connect_info = connect_info
        self.env = env
        self.p = None
        self.shell_id = None
        self.command_id = None
        self.error_handler = error_handler(logger)
        self.connect_server = None


    def get_command(self):
        """
        Prepare the command
        """

        ch = command_handler(self.logger, self.connect_info, self.env)
        ch.prepare_command_list()



    def connect(self):
        """
        Establish the connection
        """
        from kerberos import BasicAuthError
        from winrm.exceptions import WinRMTransportError

        # For us, "encrypted" means HTTPS
        if self.connect_info["ps_encrypted"]:
            protocol = "HTTPS"
            validate = self.connect_info["cert_validate"]
        else:
            protocol = "HTTP"
            validate = CERT_VALIDATE_IGNORE

        connect_server = self.connect_info["connect_server_host"] if len(self.connect_info["connect_server_host"]) > 0 else self.connect_info["connect_server"]
        host_from_cred = self.connect_info["cred_host"].replace("%D", connect_server)
        self.logger.debug(
            "host string: %s" % host_from_cred
        )

        if host_from_cred.find(":") > 0:
            # WSMAN or HOST
            service = host_from_cred.split(":")[0]
            connect_server = host_from_cred.split(":")[1].replace("/", "")
        else:
            service = "HTTP"
            connect_server = host_from_cred

        self.connect_server = connect_server

        if connect_server not in SUMMARY_INFO:
            SUMMARY_INFO[connect_server] = {}

        self.logger.debug(
            "Using service: %s, host: %s" % (service, connect_server)
        )
        if args.fi and self.connect_info["actual_ip"] is not None:
            logger.debug("Using IP address for endpoint")
            connect_server = self.connect_info["actual_ip"]

        endpoint_page = "wsman" if args.ep is None else args.ep 

        endpoint = "%s://%s:%s/%s" % (protocol, connect_server, self.connect_info["cred_port"], endpoint_page)
        display_password = "**********"

        if self.connect_info["ps_account_type"] == 1:
            display_user = "%s@%s (kerberos ticket being used)" % (
                self.connect_info["cred_user"],
                self.connect_info["ps_ad_domain"]
            )
            user = ""
            password = ""
            cache = os.getenv("KRB5CCNAME")
        else:
            user = self.connect_info["cred_user"]
            password = self.connect_info["cred_pwd"]
            display_user = user
            cache = "N/A"

        connect_detail = (
            "WinRM Protocol information:\n"
            "      endpoint:        %s\n"
            "      transport:       %s\n"
            "      username:        %s\n"
            "      password:        %s\n"
            "      cert validation: %s\n"
            "      service:         %s\n"
            "      msg encryption:  %s\n"
            "      idle_timeout:    %s\n"
            "      cache:           %s"
            % (
                endpoint,
                self.connect_info["transport"],
                display_user,
                display_password,
                validate,
                service,
                self.connect_info["msg_encrypt"],
                self.connect_info["idle_timeout"],
                cache
            )
        )

        if not args.sum:
            self.logger.info(connect_detail)

        connect_ok = False

        try:
            self.p = self.winrm.protocol.Protocol(
                endpoint=str(endpoint),
                transport=str(self.connect_info["transport"]),
                username=str(user),
                password=str(password),
                server_cert_validation=str(validate),
                service=str(service),
                message_encryption=str(self.connect_info["msg_encrypt"]),
            )

            self.logger.debug("Protocol established, creating command shell")
            # Now create a remote shell
            start = time.time()
            self.shell_id = self.p.open_shell(codepage=65001, idle_timeout=self.connect_info["idle_timeout"])
            timer_shell = "{0:.2f}".format(time.time() - start)
            self.logger.info(
                "Command shell created in %s seconds"
                % timer_shell
            )
            connect_ok = True
        except self.winrm.exceptions.WinRMTransportError as e:
            self.error_handler.suggest_transport_error(str(e))
            connect_detail = e
        except self.winrm.vendor.requests_kerberos.exceptions.KerberosExchangeError as e:
            self.error_handler.suggest_krb_exchange(str(e))
            connect_detail = e
        except self.winrm.exceptions.InvalidCredentialsError as e:
            self.error_handler.suggest_cred_rejected(str(e))
            connect_detail = e
        except Exception as e:
            self.logger.debug(
                "General exception of type: %s" % type(e)
            )
            self.error_handler.suggest_shell(str(e))
            connect_detail = e
        finally:
            if connect_ok:
                _msg = "Connection OK"
            else:
                _msg = "Connection failed: %s" % connect_detail

            SUMMARY_INFO[self.connect_server]["Result"] = connect_ok
            SUMMARY_INFO[self.connect_server]["Message"] = _msg


    def execute(self, command):
        """
        Actually execute the command and read the output
        """

        start = time.time()
        location = 1

        try:
            run_id = self.p.run_command(self.shell_id, command)
            timer_run = "{0:.2f}".format(time.time() - start)
            self.logger.info(
                "Command execution in %s seconds" % timer_run
            )

            location = 2
            start = time.time()
            stdout_raw, stderr_raw, rc = self.p.get_command_output(self.shell_id, run_id)
            exec_time = time.time() - start
            DATA["total_time"] += exec_time
            timer_read = "{0:.2f}".format(exec_time)
            self.logger.info(
                "Command output received in %s seconds" % timer_read
            )
        except Exception as e:
            DATA["total_errors"] +=1
            _msg = "Error processing the command: %s" % e

            if location ==1:
                self.error_handler.suggest_shell(_msg)
            else:
                self.error_handler.suggest_read(_msg)

            return

        stdout = str(stdout_raw, encoding="utf-8") if self.env["python_version"] == ENV_PY3 else stdout_raw
        stderr = str(stderr_raw, encoding="utf-8") if self.env["python_version"] == ENV_PY3 else stderr_raw

        is_error, error_msg = self.error_handler.parse_cli_xml_error(stderr)

        if stdout and not (args.sp or args.sum):
            self.logger.info("Command output:")
            print("\n%s\n" % stdout)

        if rc != 0 or is_error:
            DATA["total_errors"] +=1
            self.error_handler.suggest_execution_error(error_msg)
            # Update summary to show false
            SUMMARY_INFO[self.connect_server]["Result"] = False
            SUMMARY_INFO[self.connect_server]["Message"] = error_msg


    def run_command(self):
        """
        Run the command
        """

        # First we need to connect
        self.connect()

        if self.shell_id is None:
            self.logger.info(
                "Unable to create a shell on the Windows device, so exiting the process"
            )
            return

        #actual_command = self.get_command()
        self.get_command()
        DATA["total_commands"] = len(self.connect_info["command_list"])

        if DATA["total_commands"] > 0:

            command_num = 1

            for command in self.connect_info["command_list"]:
                self.logger.info(
                    "Executing command: %s of %s" %
                    (command_num, DATA["total_commands"])
                     )
                self.execute(command)
                command_num += 1

        else:
            self.logger.info("No commands were found to execute")

        try:
            self.logger.debug("Closing Windows processes")

            if self.command_id is not None:
                self.logger.debug(
                    "Closing command id..."
                )
                self.p.cleanup_command(self.shell_id, self.command_id)

            self.p.close_shell(self.shell_id)
        except Exception as e:
            self.logger.error(
                "Failed to cleanup Windows shell process. Error: %s" % e
            )
        # Make sure we close down the connection...


#########################################################################################
# Class to verify the target device
#########################################################################################

class set_validate_target():
    """
    Class to verify we can connect to the target and establish whether the target accessed
    via a proxy. Make sure we connect to FQDN or host rather than IP
    """

    def __init__(self, logger, server, connect_info):
        import socket
        self.socket = socket
        self.logger = logger
        self.server = server
        self.args = args
        self.connect_info = connect_info
        self.error_handler = error_handler(logger)


    def get_fqdn_host_from_ip(self, ip):
        """
        If we can , get the FQDN or the host for an IP address
        """

        # Check this is an IP address

        try:
            self.socket.inet_aton(ip)
            is_ip = True
        except Exception as e:
            is_ip = False
            self.logger.debug("This is not an IP address: %s. Error: %s" % (ip, e))

        if is_ip:
            fqdn_host = self.socket.getfqdn(ip)
            
            if fqdn_host is not None and fqdn_host != ip:
                self.logger.debug(
                    "IP: %s is host: %s" % (ip, fqdn_host)
                )
                self.connect_info["connect_server_host"] = fqdn_host
        else:
                self.logger.debug(
                    "Unable to get fqdn/host for IP: %s" % ip
                )


    def ping(self, target_ip):
        """
        Unless "ping" was disabled then try to ping the server
        """

        if self.args.np:
            self.logger.debug("Ping test disabled, not checking ip: %s" % target_ip)
            return True
        else:
            self.logger.info(
                "Attempting a ping test to port %s on IP: %s (allow %s seconds)"
                % (self.connect_info["cred_port"], target_ip, self.connect_info["ping_timeout"])
            )
            s = self.socket.socket()
            s.settimeout(self.connect_info["ping_timeout"])
            r = s.connect_ex((target_ip, self.connect_info["cred_port"]))
            s.close()

            if r:
                return False
            else:
                self.logger.info("Ping test was successful")
                return True


    def get_ip(self, addr):
        """
        See if we can get the IP address of the server
        """

        ip = None

        try:
            ip = self.socket.gethostbyaddr(addr)
        except self.socket.timeout:
            self.error_handler.suggest_lookup("Timed out trying to resolve: %s" % addr)
        except self.socket.herror as e:
            self.error_handler.suggest_lookup(
                "Host lookup failed for %s. Error: %s"
                % (addr, e)
            )
        except Exception as e: 
            self.error_handler.suggest_lookup(
                "Unknown error resolving host %s. Error: %s"
                % (addr, e)
            )

        return ip


    def check_target_and_proxy(self, temp_target, temp_proxy):
        """
        Check the target and proxy are different
        """
 
        proxy_ip = None
        target_ip = None
        use_proxy = False
        fail = False

        if len(temp_proxy) > 0:
            proxy_detail = self.get_ip(temp_proxy)

            if proxy_detail is not None:
                proxy_host, proxy_alias, proxy_ip = (proxy_detail[0], proxy_detail[1], proxy_detail[2][0])
                self.logger.debug(
                    "Resolved proxy host %s to IP: %s"
                    % (temp_proxy, proxy_ip)
                )

        # Now the target
        target_detail = self.get_ip(temp_target)

        if target_detail is not None:
            target_host, target_alias, target_ip = (target_detail[0], target_detail[1], target_detail[2][0])
            self.logger.debug(
                "Resolved target host %s to IP: %s"
                % (temp_target, target_ip)
            )

        # If the target and proxy are the same, then we should not be using proxy. Also - if proy was specified
        # but we could not resolve it, then that is an issue. And it is a problem if there is no proxy and we
        # were unable to resolve the target. BUT if there is a proxy that we could resolve, it's OK not to be
        # able to resolve the target )because it's the proxy that has to resolve the target)

        if proxy_ip is not None and target_ip is not None:
            # The same?
            if proxy_ip != target_ip:
                use_proxy = True
        elif proxy_ip is not None:
            # We chacked for both being set - now we don't really care of the target was resolved, but if it 
            # wasn't we should use the input as the "ip"
            if target_ip is None:
                target_ip = temp_target

            use_proxy = True
        
        return use_proxy, target_ip, proxy_ip


    def set_target_and_proxy(self):
        """
        Driver to get the target name server from the inputs
        """

        temp_target = self.server.upper()
        temp_proxy = self.connect_info["ps_proxy_host"].upper()

        # Need to check to see if the target and proxy are the same (if proxy set)

        return self.check_target_and_proxy(temp_target, temp_proxy)
        

#########################################################################################
# Class to check execution environment
#########################################################################################

class setup_environment():
    """
    Get information about the environment we are running in
    """

    def __init__(self, logger, env):
        self.logger = logger
        self.env = env


    def run_cmd(self, input_cmd):
        """
        Execute commandline
        """
        p = subprocess.Popen(input_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]

        if type(p) == str:
            return p.split("\n")[0]
        else:
            return p.decode("utf-8")


    def release_version(self, filename):
        """
        Determine OS version from the "release" file
        """

        try:
            with open(filename, 'r') as f:
                first_line = f.read().splitlines()[0]
            f.close()
            return first_line
        except Exception as e:
            self.logger.error("Failed to open file %s with error: %s" % (filename, e))
            return None


    def get_environment(self):
        """
        Figure out if we are on the CU or in a container, and what version of Python is being used
        """

        # Is this a CU (oracle-release) or container (redhat-release or debuan-release)

        if os.path.exists(ORACLE_RELEASE) and os.path.exists(EM7_VERSION):
            self.logger.debug(
                "%s found, checking OL version" % ORACLE_RELEASE
            )
            self.env["os_version"] = self.release_version(ORACLE_RELEASE)
            self.env["collector_version"] = self.release_version(EM7_VERSION)
            self.env["host_type"] = ENV_CU
            # This is a host device, but is it a collector?
            cmd = "rpm -qa | grep %s" % CU_COLLECTOR
            result = self.run_cmd(cmd)
            
            if result is not None and len(result) > 1:
                self.env["is_collector"] = result.find(CU_COLLECTOR) > -1
            else:
                self.env["is_collector"] = False
        elif os.path.exists(REDHAT_RELEASE) or os.path.exists(DEBIAN_RELEASE):
            self.logger.debug(
                "%s not found, checking %s" %
                (
                    ORACLE_RELEASE,
                    REDHAT_RELEASE
                )
            )
            if os.path.exists(REDHAT_RELEASE):
                self.env["os_version"] = self.release_version(REDHAT_RELEASE)
            else:
                self.logger.debug(
                    "%s not found, checking %s" %
                    (
                        REDHAT_RELEASE,
                        DEBIAN_RELEASE
                    )
                )

                self.env["os_version"] = "Debian %s" % self.release_version(DEBIAN_RELEASE)

            self.env["collector_version"] = "N/A"

            try:
                import powershell_collector
                self.env["collector_version"] = powershell_collector.__version__
            except ImportError:
                pass
            except Error as e:
                _msg = "Failed when setting collector version: " % e
                self.logger.debug(_msg)

            self.env["host_type"] = ENV_CONTAINER
            self.env["is_collector"] = True
        else:
            self.logger.debug(
                "Unable to determine OS version - not running on a collector"
            )
            import platform
            self.env["os_version"] = "%s %s" % (platform.system(), platform.release())
            self.env["host_type"] = "Generic Linux"
            self.env["is_collector"] = False


#########################################################################################
# Class to handle credentials
#########################################################################################

class cred_info():
    """
    Class to read the credentials id - in a container use a sql query, otherwise use available module
    """

    def __init__(self, logger, connect_info, env):
        self.logger = logger
        self.connect_info = connect_info
        self.env = env

    
    def get_cred_info_id_legacy(self):
        """
        Read using built in libraries
        """

        self.logger.info("Reading credential information from legacy")
        location = "cred_array"

        try:
            from silo_common.credentials import cred_array_from_id

            location = "silo_cursor"
            from silo_common.database import silo_cursor

            location = "constants"
            from silo_common.global_definitions import CRED_POWERSHELL
        except ImportError:
            self.logger.error(
                "Failed to import a requeired library: %s" % location
            )
            return False
        except Exception as e:
            self.logger.error(
                "Failed whilst processing required libraries (%s). Error: %s"
                % (location, e)
            )
            return False

        dbc = silo_cursor.local_db()
        cred_array = cred_array_from_id(dbc)(args.c)

        if cred_array is None:
            self.logger.error(
                "There is no credential with id: %s" % args.c
            )
            return False

        if cred_array["cred_type"] != CRED_POWERSHELL:
            if "cred_name" in cred_array:
                _name = cred_array["cred_name"]
            else:
                _name = "UNKNOWN"

            self.logger.error(
                "The credential with id: %s (name: %s) is type: %s, and not a PowerShell Credential",
                args.c,
                _name,
                cred_array["cred_type"]
            )

            return False

        # Copy the data we just read into the final array we will be using

        for x in cred_array:

            if x in self.connect_info:
                if x == "ps_ad_domain" and not args.leave_domain:
                        self.connect_info[x] = cred_array[x].upper()
                else:
                    self.connect_info[x] = cred_array[x]

        return True


    def autofetchone_dict(self, dbc, query):
        """
        Fetch data into a list of dictionaries keyed on column names.

        Args:
            - dbc (object): The database connection object.
            - query (str): The query to execute.

        Returns:
            dict: Dictionary with all data or empty dictionary when no data found.
        """

        try:
            dbc.execute(query)
            row = dbc.fetchone()
            if dbc.description and row:
                desc = [n[0] for n in dbc.description]
            else:
                return {}
        except Exception:
            # We expect a fail now when we are handling schema changes, caller will try again
            return {}

        return dict(zip(desc, row))


    def db_lookup_powershell_cred_from_device_id(self, cred_id):
        """
        Query the credential details using the device_id

        Args:
            - dbc (object): The database connection object.
            - device_id (int): The id of the device to look up
        Returns:
            - dict: Dictionary of credential details.
        """

        location = "MySQLdb"

        try:
            import MySQLdb

            location = "config"
            from powershell_collector.config import config
        except ImportError:
            self.logger.error("Failed to import required library: %s" % location)
            return False
        except Exception as e:
            self.logger.error(
                "Failed in loading required module %s with error: %s"
                % (location, e)
            )
            return False

        try:
            db_conn = MySQLdb.connect(
                user=config.MARIADB_USER,
                passwd=config.MARIADB_PSWD,
                host=config.MARIADB_HOST,
                port=config.MARIADB_PORT,
                #ssl=None,
            )
            dbc = db_conn.cursor()
            dbc.execute("SET AUTOCOMMIT=1")
        except Exception as e:
            self.logger.error(
                "Unable to connect to the database with error: %s" %e
            )
        # Notice: the query return the host of the credentials so in many cases it will be %D
        cred = """
            SELECT  
                sc.cred_id,
                sc.cred_name as cred_name,
                sc.cred_user as cred_user,
                BINARY(sc.cred_pwd) as cred_pwd,
                sc.cred_host as cred_host,
                sc.cred_port as cred_port,
                sc.cred_timeout as cred_timeout,
                pscred.ps_account_type as ps_account_type,
                pscred.ps_ad_domain as ps_ad_domain,
                pscred.ps_ad_host as ps_ad_host,
                pscred.ps_encrypted as ps_encrypted,
                pscred.ps_proxy_host as ps_proxy_host
            FROM 
                %s sc
                INNER JOIN %s pscred
                    ON pscred.cred_id = sc.cred_id
            WHERE
                sc.cred_id = %s
                """ 
        tables = [
            ["collector_state.V_credential", "collector_state.V_credential_powershell"],
            ["master.system_credentials", "master.system_credentials_powershell"],
        ]

        return_data = {}

        # With new schema, the "V" views are sent to the collector as tables and the base tables
        # are not sent. So the loop will check for the "V" tables and if this fails, try the base
        # tables. This means that if the new schema is present and the credentials are there, we will
        # fetch them from the new tables. If the old schema is present we will fail on fetching from
        # "V" tables as they will be missing, and then fetch from the old tables.
        #
        # If the new schema is present and the credentials are filtered out because of an
        # organisation setting, we'll get no results on the query for the "V" tables and then nothing
        # on the query on the base tables.

        for table_group in tables:
            query = cred % (table_group[0], table_group[1], cred_id)
            return_data = self.autofetchone_dict(dbc, query)

            if return_data:
                break

        return return_data


    def get_cred_info_id_container(self):
        """
        In the container, query the db
        """

        db_data = self.db_lookup_powershell_cred_from_device_id(args.c)

        if db_data:
            for x in db_data:
                if x in self.connect_info:
                    if x == "cred_pwd":
                        from libem7 import _crypt
                        self.connect_info[x] = _crypt.cred_decode(db_data[x]).decode("utf-8")
                    elif x == "ps_ad_domain" and not args.leave_domain:
                        self.connect_info[x] = db_data[x].upper()
                    else:
                        self.connect_info[x] = db_data[x]
            
            return True
        else:
            self.logger.error("The credential with ID: %s could not be found, or is not PowerShell" % args.c)
            return False


    def get_cred_info(self):
        """
        If the cred id is provided then rea that information, otherwise use inputs
        """

        if args.c is not None:
            self.logger.info("Trying to read credentials from credential id")
            if self.env["host_type"] == ENV_CU:
                ok = self.get_cred_info_id_legacy()
            else:
                ok = self.get_cred_info_id_container()

            if ok:
                self.logger.info(
                    "Fetched credentials from credential \"%s\"" % self.connect_info["cred_name"]
                )

            # Allow inputs to override the credentials information we just read
            if args.pwd and len(args.pwd) > 0:
                self.logger.debug("Override credentials password with input")
                self.connect_info["cred_pwd"] = args.pwd

            if args.wsman or args.host:
                self.logger.debug("Override credentials host data with input")

                if args.wsman:
                    self.connect_info["cred_host"] = "%s%s" % ("WSMAN://", self.connect_info["cred_host"])
                else:
                    self.connect_info["cred_host"] = "%s%s" % ("HOST://", self.connect_info["cred_host"])

            if args.https:
                self.logger.debug("Override credentials HTTPS with input")
                self.connect_info["ps_encrypted"] = 1

            if args.http:
                self.logger.debug("Override credentials HTTPS with input")
                self.connect_info["ps_encrypted"] = 0

            if args.port and type(args.port) == int:
                self.logger.debug("Override credentials port data with input")
                self.connect_info["cred_port"] = args.port

            if args.proxy and len(args.proxy) > 0:
                self.logger.debug("Override credentials proxy with input")
                self.connect_info["ps_proxy"] = args.proxy

            if args.user and len(args.user) > 0:
                self.logger.debug("Override credentials user with input")
                # Figure out if a Domain user is entered as the creds store that
                # differently

                _user = args.user
                _domain = ""
                _type = 2

                if _user.find("@") > -1 or _user.find("\\") > -1:
                    if _user.find("@") > -1:
                        _domain = _user.split("@")[1]
                        _user = _user.split("@")[0]
                    else:
                        _domain = _user.split("\\")[0]
                        _user = _user.split("\\")[1]

                    _type = 1
                else:
                    self.connect_info["ps_ad_host"] = ""
                    self.connect_info["transport"] = PYWINRM_TRANSPORT_BASIC if args.new else PYWINRM_TRANSPORT_PLAINTEXT

                    if args.transport is not None:
                        self.connect_info["transport"] = args.transport

                self.connect_info["ps_account_type"] = _type
                self.connect_info["cred_user"] = _user
                self.connect_info["ps_ad_domain"] = _domain
                logger.debug("Set user to be: %s with domain: %s", _user, _domain)

        else:
            self.logger.info("Preparing user input details")
            ok = True

            if len(self.connect_info["cred_pwd"]) == 0:
                # Prompt for the password

                self.connect_info["cred_pwd"] = getpass.getpass("Provide the password for {0}: ".format(self.connect_info["cred_user"]))

                if len(self.connect_info["cred_pwd"]) == 0:
                    self.logger.error("No password supplied, cannot continue\n")
                    ok = False

        return ok

#########################################################################################
# Main routine
#########################################################################################

def main():
    """
    Main routine 
    """

    # Make sure the inputs are good or quit

    ok, msg = valid_args()
    if not ok:
        logger.error(
            "One or more inputs invalid, will quit now:\n%s\n" % msg
        )
        return

    # Get information about the environment we are running in
    my_env = setup_environment(logger, ENV)
    my_env.get_environment()
    dc = "Data Collector"

    if not ENV["is_collector"]:
        logger.warning("This server is not a Data Collector")
        dc = "Linux device"
        
        if not args.run_anyway:
            return

    logger.info(
        "Running on a %s (%s) running %s with Python %s"
        % (dc, ENV["host_type"], ENV["os_version"], ENV["python_version"])
    )
    if ENV["collector_version"] is not None:
        logger.info("Collector Version: %s\n" % ENV["collector_version"])

    creds = cred_info(logger, CONNECT_INFO, ENV)
    ok = creds.get_cred_info()

    if not ok:
        logger.error("Failed to fetch the credential information, unable to continue")
        return

    for x in CONNECT_INFO:
        if x == "cred_pwd":
            value = "**********"
        else:
            value = CONNECT_INFO[x]
        logger.debug("  %s: %s" % (x, value))

    for server in SERVER_LIST:
        logger.info(
            "Beginning test to target device %s with credential information:" % args.server
        )

        target = set_validate_target(logger, server, CONNECT_INFO)
        use_proxy, target_ip, proxy_ip = target.set_target_and_proxy()

        logger.debug(
            "Use Proxy: %s\n       Target: %s\n       Proxy: %s"
            % (use_proxy, target_ip, proxy_ip)
        )

        if target_ip is None:
            logger.error("Unable to continue with this server as it cannot be resolved")
            continue

        # Can we ping the server we will need to connect to?
        if use_proxy:
            server_or_proxy = "Proxy"
            actual_target = args.proxy
            actual_ip = proxy_ip
            CONNECT_INFO["target_server"] = target_ip
            CONNECT_INFO["connect_server"] = proxy_ip
        else:
            server_or_proxy = "Server"
            actual_target = args.server
            actual_ip = target_ip
            CONNECT_INFO["target_server"] = ''
            CONNECT_INFO["connect_server"] = target_ip

        # Best to use fqdn/host if we can - so try to set that

        target.get_fqdn_host_from_ip(CONNECT_INFO["connect_server"])
        CONNECT_INFO["actual_ip"] = actual_ip

        _msg_target = (
            "Checking %s server %s (ip: %s) is available"
            % (server_or_proxy, actual_target, actual_ip)
        )

        logger.info(_msg_target)
        ping_ok = target.ping(proxy_ip) if use_proxy else target.ping(target_ip)

        if not ping_ok:
            logger.error("Unable to communicate with the target server")
            return

        # Do the kerberos stuff
        k = kerberos(logger, CONNECT_INFO, ENV)
        k_ok = k.kinit()

        if not k_ok:
            return

        # Run pywinrm_transport
        try:

            if CONNECT_INFO["pypsrp"]:
                transport = pypsrp_transport(logger, CONNECT_INFO, ENV)
            else:
                transport = pywinrm_transport(logger, CONNECT_INFO, ENV)
        except Exception as e:
            logger.error(e)
            return

        transport.run_command()

    if SUMMARY_INFO:
        good_servers = {}
        bad_servers = {}

        for server in SUMMARY_INFO:
            if SUMMARY_INFO[server]["Result"]:
                good_servers[server] = SUMMARY_INFO[server]["Message"]
            else:
                bad_servers[server] = SUMMARY_INFO[server]["Message"]

        if good_servers:
            print("\nServers that are OK:")

            for server in good_servers:
                print("\t%s" % server)

        if bad_servers:
            print("\nServers that failed the tests:")

            for server in bad_servers:
                print("\t%s: %s" % (server, bad_servers[server]))

        print("")


# Start here

if __name__ == "__main__":
    main()
    exec_time = "{0:.2f}".format(DATA["total_time"])
    logger.info(
        "%s commands executed in %s seconds, %s commands failed\n" %
        (DATA["total_commands"], exec_time, DATA["total_errors"])
    )

    if args.lf:
        logger.info("Logged to file: %s" % log_file)
        logger.info("End: %s\n" % (datetime.now().strftime("%d-%h-%Y %H:%M:%S")))