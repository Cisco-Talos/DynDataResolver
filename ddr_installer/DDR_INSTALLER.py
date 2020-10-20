#-------------------------------------------------------------------------------
#
#   IDA Pro Plug-in: Dynamic Data Resolver (DDR) Server Installer script
#
#   Version 1.0 
#
#   Copyright (C) 2020 Cisco Talos
#   Author: Holger Unterbrink (hunterbr@cisco.com)
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   ------------------------------------------------------------------------------
#
#   Hint: This script does not have any dependencies. All non default dependencies 
#         will be installed into a virtual envirmoent at run time.
#
#   ------------------------------------------------------------------------------

import venv
import os
import sys
import subprocess 
import pathlib
import time
import os
import sys
import subprocess
import importlib
import tempfile
import zipfile
import glob
import shutil
import string
import random
import re
import platform
from distutils.dir_util import copy_tree

# IDA DDR plugin globals
IDA_PLUGIN_ZIP          = "ddr_plugin.zip"
DDR_PLUGIN_SRCPATH      = "ddr_plugin"
IDA_DEFAULT_INSTALL_DIR = os.getenv('ProgramW6432') + "\\IDA Pro 7.5"
IDA_DEFAULT_PLUGIN_DIR  = os.getenv('APPDATA')      + "\\Hex-Rays\\IDA Pro\\plugins"
IDA_DEFAULT_PYTHON_PATH = os.getenv('ProgramW6432') + "\\Python38"

# DDR Server
DYNRIO_DOWNLOAD_URL             = r"https://github.com/DynamoRIO/dynamorio/releases/download/release_8.0.0-1/DynamoRIO-Windows-8.0.0-1.zip"
DYNRIO_DOWNLOAD_URL_LATEST      = r"https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-8.0.18547/DynamoRIO-Windows-8.0.18547.zip"
DDRSERVER_CONFIG_FILE_TEMPLATE  = "templates\\ddr_server_template.json"
DDRSERVER_CONFIG_FILE           = "ddr_server.cfg"
DDRSERVER_VERSION               = "1.0 beta"
APILOGGING                      = "DEBUG"
DEBUG_API_JSON                  = "false"
MY_FQDN                         = "malwarehost.local" # only used as name in the certificate, no DNS required.
MAX_CFG_LINE_LENGTH             = 356
DDR_DLL32                       = "ddr32.dll"
DDR_DLL64                       = "ddr64.dll"
DDR_CERT_FILENAME               = "ddr_server.crt"
DDR_CERT_KEY_FILENAME           = "ddr_server.key"
DDR_APIKEY_FILE                 = "ddr_apikey.txt"
DDR_APIKEY                      = "not set" 
DDR_VIRTENV_NAME                = "ddr_venv"
MAX_INSTALL_DIR                 = 160
DDR_SERVER_IP                   = "0.0.0.0"
DDR_SERVER_PORT                 = "5000" 

def proceed(question):
    """
    Do you want to proceed [Y/n]. Returns True if 'yes' and False if 'no'
    """
    valid = ["y"]
        
    while True:
        sys.stdout.write(question)
        choice = input().lower()
        if choice == '':
            return True
        elif choice == 'y':
            return True
        else:
            return False

def is_venv():
    """
    Do we run in a virtual enviroment
    """
    return (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

def get_ida_dir():
    print("[DDR_PLUGIN_INSTALLER][INFO] Please enter the IDA installation directory.")
    print("[DDR_PLUGIN_INSTALLER][INFO] Default is {}".format(IDA_DEFAULT_INSTALL_DIR))
    ida_dir = input("[DDR_PLUGIN_INSTALLER][INFO] IDA installation directory: ") or IDA_DEFAULT_INSTALL_DIR
    print()
    return ida_dir

def get_ida_plugin_dir():
    print("[DDR_PLUGIN_INSTALLER][INFO] Please go to IDA and find out where the user plugin directory is.")
    print("[DDR_PLUGIN_INSTALLER][INFO] You can do that by entering the follwing into the Python command prompt of IDA:")
    print("[DDR_PLUGIN_INSTALLER][INFO] print(os.path.join(idaapi.get_user_idadir(), \"plugins\"))")
    print("[DDR_PLUGIN_INSTALLER][INFO] Default plugin directory is {}".format(IDA_DEFAULT_PLUGIN_DIR))
    ida_plugin_dir = input("[DDR_PLUGIN_INSTALLER][INFO] IDA plugin directory: ") or IDA_DEFAULT_PLUGIN_DIR
    print()
    return ida_plugin_dir

def get_ida_python_version():
    print("[DDR_PLUGIN_INSTALLER][INFO] Please go to IDA and find out which Python version IDA is using.")
    print("[DDR_PLUGIN_INSTALLER][INFO] You can do that by entering the follwing into the Python command prompt of IDA:")
    print("[DDR_PLUGIN_INSTALLER][INFO] print(sys.exec_prefix)")
    print("[DDR_PLUGIN_INSTALLER][INFO] Default plugin directory is {}".format(IDA_DEFAULT_PYTHON_PATH))
    ida_python_path = input("[DDR_PLUGIN_INSTALLER][INFO] Please enter the IDA Python directory path: ") or IDA_DEFAULT_PYTHON_PATH
    print()
    return ida_python_path

def create_apikey(apikey_file):
    """ 
    Generate API key
    """    
    global DDR_APIKEY

    try:
        DDR_APIKEY = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(24))
        with open(apikey_file, "w") as text_file:
            text_file.write("{}".format(DDR_APIKEY))
        print("[DDR_INSTALLER][INFO] --------------------------------------------------------------------------------")
        print("[DDR_INSTALLER][INFO] Generated new API Key and wrote it to {}".format(apikey_file))
        print("[DDR_INSTALLER][INFO] --------------------------------------------------------------------------------\n")
        return True
    except:
        print("[DDR_INSTALLER][ERROR] Genrating API Key file {} failed.".format(apikey_file))
        raise
        return False

def create_self_signed_cert(my_ipaddr, cert_file, key_file):
    """
    Create self signed certificate and key 
    """

    print("We need a serial number for the certificate.")
    print("If this is the first time you are generating and using the certificate,")
    print("you can use the default number (1001). If this is not the first time, ")
    print("you should pick a higher number than you used the last time. Otherwise,")
    print("you might run into serial number re-use issues with some browsers.")
    cert_serial = input("Please enter the serial number for the certificate (Default: 1001) :") or "1001"
    cert_serial = int(cert_serial)

    # create a key pair
    k = OpenSSL.crypto.PKey()
    k.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = OpenSSL.crypto.X509()
    cert.get_subject().C  = "DE"                                    # country of residence
    cert.get_subject().ST = "Berlin"                                # state of residence
    cert.get_subject().L  = "SomeLocality"                          # locality
    cert.get_subject().O  = "Talos"                                 # organization 
    cert.get_subject().OU = "Security"                              # organizational unit 
    cert.get_subject().CN = my_ipaddr                               # common name IP or FQDN
    san_list = ["IP:" + my_ipaddr, "DNS:" + my_ipaddr]              # subjectAltName list
    cert.add_extensions([ OpenSSL.crypto.X509Extension(b'subjectAltName', False, bytes(', '.join(san_list), 'utf-8'))])
    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')
    open(cert_file, "wt").write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode())
    open(key_file,  "wt").write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k).decode())

    print("")
    print("[DDR_INSTALLER][INFO] -------------------------------------------------------------")
    print("[DDR_INSTALLER][INFO] Individual self signed certificate and secret key generated. ")
    print("[DDR_INSTALLER][INFO] DDR will use these credentials to encrypt the HTTPS traffic  ")
    print("[DDR_INSTALLER][INFO] between the DDR IDA plugin and the DDR server.               ")
    print("[DDR_INSTALLER][INFO] -------------------------------------------------------------")
    

def load_mod(mod_name):
    """
    Load modules at runtime by name stored in variable
    """
    globals()[mod_name] = importlib.import_module(mod_name)

def runcmd(my_cmd):
    """ 
    Execute shell command
    """

    print("[DDR_INSTALLER][INFO] Executing cmd: \n{}\n".format(my_cmd))

    stdout = False
    stderr = False

    try:
        #process = subprocess.Popen(my_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #stdout, stderr = process.communicate()
        process = subprocess.run(my_cmd)

        if process.returncode != 0:
            print("\n[DDR_INSTALLER][WARNING] Command execution failed. Error code: {:d}".format(process.returncode))
            ret = False
        else:
            ret = True
            
        # if stderr:
        #     print("[DDR_INSTALLER][WARNING] Command execution failed. Stderr:")
        #     print("{}".format(stderr.decode("utf-8")))

        #     ret['stderr'] = stderr
        #     ret['status'] = False

        # if stdout:
        #     print("[DDR_INSTALLER][INFO] Command execution stdout:")
        #     print("{}".format(stdout.decode("utf-8")))

        #     ret['stdout'] = stdout
        #     ret['status'] = True
        
    except :
        print("[DDR_INSTALLER][ERROR] Exception: Command execution failed with unknown error.")
        ret = False
    
    return ret

def check_files_exist(files = [], dirs = []):
    """ 
    Verify if the files and dirs configured exist
    """
    ret = True
    
    for dir in dirs:
        if not os.path.isdir(dir):
            print("[DDR_INSTALLER][ERROR] Directory: {} not found.".format(dir))
            ret = False

    for fname in files:
        if not os.path.isfile(fname):
            print("[DDR_INSTALLER][ERROR] File: {} not found.".format(fname))
            ret = False

    return ret

def zip_is_valid(zipfilename):
    """
    Check if zipfilename is a valid zip file. Return True if valid. False if not valid.
    """

    if not os.path.isfile(zipfilename):
         print("[DDR_INSTALLER][ERROR] Zip file not found.")
         return False

    try:
        zip_file = zipfile.ZipFile(zipfilename)
        res = zip_file.testzip()

        if res is not None:
            print("[DDR_INSTALLER][ERROR] Bad file in zip archive: {}".format(res))
            return False
        else:
            return True
    except:
        print("[DDR_INSTALLER][ERROR] Zip file: {} is corrupt.".format(zipfilename))
        os.remove(zipfilename)
        print("[DDR_INSTALLER][ERROR] Corrupt zip file: {} deleted.".format(zipfilename))
        return False

def download_zip_and_unpack(unpack_dir, url):
    """
    Download zip file from url and unpack it to directory unpack_dir. Verify if zip file is valid.
    Return True if successfully downloaded file and deleted the temp. files.
    Return False if anything went wrong. 
    """
    print("Downloading from url: {}".format(url))
    zipfilename = tempfile.gettempdir() + "\\tmp.zip"

    with requests.get(url, stream=True) as res:
        if res.status_code == 200:
            with open(zipfilename, 'wb') as f:
                total_length = int(res.headers.get('content-length'))
                for chunk in clint.textui.progress.bar(res.iter_content(chunk_size=1024), expected_size=(total_length/1024) + 1): 
                    if chunk:
                        f.write(chunk)
                        f.flush()
            print("\n[DDR_INSTALLER] [INFO] File downloaded.")
        else:
            print("[DDR_INSTALLER] [ERROR] Download failed.")

    # Verify zip file is valid
    if not zip_is_valid(zipfilename):
        print("[DDR_INSTALLER] [ERROR] Zip file verification failed.")
        return False
        
    # check if unpack_dir exists otherwise create it
    pathlib.Path(unpack_dir).mkdir(parents=True, exist_ok=True)

    # Extract files from zip archive
    with zipfile.ZipFile(zipfilename, "r") as ziparchive:
        print("[DDR_INSTALLER] [INFO] Extracting files to {}".format(unpack_dir))
        ziparchive.extractall(unpack_dir)

    # Delete zip archive
    print("[DDR_INSTALLER] [INFO] Deleting downloaded archive: {}".format(zipfilename))
    try:
        os.remove(zipfilename)
    except:
        print("[DDR_INSTALLER] [ERROR] Failed to delete zip file: {}".format(zipfilename))
        pass

    return True

def cpu_is_AMD(): 
    """
    Check if CPU is from AMD
    """
    cpu = platform.processor()
    
    if "amd" in cpu.lower():
        return True
    
    return False


def install_deps(venv, ddr_default_dir):
    """
    Main installer routine to install all neccessary 
    dependencies for DDR
    """

    global DDR_SERVER_IP
    global DDR_SERVER_PORT

    # update pip in virtual enviroment
    print("[DDR_INSTALLER][INFO] Updating pip in virtual enviroment.")
    my_cmd = venv + "\\Scripts\\activate.bat && " + "python -m pip install --upgrade pip" 
    if runcmd(my_cmd):
        print("[DDR_INSTALLER][INFO] pip updated.")
    else:
        print("Failed to update pip.")
        return False

    # Install pip tools
    print("[DDR_INSTALLER][INFO] Installing pip-tools.")
    my_cmd = venv + "\\Scripts\\activate.bat && " + "pip install --upgrade pip-tools" 
    if runcmd(my_cmd):
        print("[DDR_INSTALLER][INFO] pip tools installed.")
    else:
        print("Failed to install pip tools.")
        return False
 
    # Sync DDR Python dependencies 
    # https://stackoverflow.com/questions/10333814/tell-pip-to-install-the-dependencies-of-packages-listed-in-a-requirement-file
    # 
    print("[DDR_INSTALLER][INFO] Installing DDR Python dependencies.")
    my_cmd = venv + "\\Scripts\\activate.bat && " + "pip-sync"
    if runcmd(my_cmd):
        print("[DDR_INSTALLER][INFO] DDR Python dependencies installed and synchronized.")
    else:
        print("Failed to install DDR Python dependencies.")
        return False
    
    # Load non standard modules
    load_mod("requests")
    load_mod("clint")

    # Install DynamoRio    
    if proceed("Should we proceed with downloading and installing DynamoRio to {} [Y/n] ?".format(ddr_default_dir)):
        if cpu_is_AMD():
            print("[DDR_INSTALLER][WARNING] It seems to be you have an AMD CPU. There is a AMD CPU which makes DynamoRio fail in WOW64 operations.")
            print("[DDR_INSTALLER][WARNING] Details can be found here: https://github.com/DynamoRIO/dynamorio/issues/4091#")
            print("[DDR_INSTALLER][WARNING] with an AMD processor it is highly recommend to use the latest DynamoRio GIT version.")

        if proceed("Should we install the weekly package (recommended - includes AMD CPU bug fix) or the latest stable release. [W/S] ? ".format(ddr_default_dir)):
            print("[DDR_INSTALLER][WARNING] Installing weekly DynamoRio package:\n{}".format(DYNRIO_DOWNLOAD_URL_LATEST))
            download_zip_and_unpack(ddr_default_dir, DYNRIO_DOWNLOAD_URL_LATEST)
        else:
            print("[DDR_INSTALLER][WARNING] Installing latest stable DynamoRio package:\n{}".format(DYNRIO_DOWNLOAD_URL_LATEST))
            download_zip_and_unpack(ddr_default_dir, DYNRIO_DOWNLOAD_URL)

    try:
        dynrio_path  = glob.glob(ddr_default_dir + '\\DynamoRIO-Windows*')[0]      
        dynrio_run32 = dynrio_path + "\\bin32\\drrun.exe"
        dynrio_run64 = dynrio_path + "\\bin64\\drrun.exe"
    except:
        print("[DDR_INSTALLER][ERROR] DynamoRio installation not found.")
        return False

    if not check_files_exist(dirs = [dynrio_path]):
        print("[DDR_INSTALLER][ERROR] DynamoRio directory does not exist. Installation failed.")
        return False
    else:
        print("[DDR_INSTALLER][INFO] DynamoRio directory found.")

    if not check_files_exist(files = [dynrio_run32, dynrio_run64]):
        print("[DDR_INSTALLER][ERROR] DynamoRio drrun file(s) do not exist. Installation failed.")
        return False
    else:
        print("[DDR_INSTALLER][INFO] DynamoRio run binaries found.\n")
    
    # Network setup
    print("[DDR_INSTALLER][INFO] Network setup:")
    
    DDR_SERVER_PORT = input("[DDR_INSTALLER][INFO] Please enter server PORT to listen on (Default is 5000) :") or "5000"

    process = subprocess.run("ipconfig",stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data = process.stdout.decode()
    ip_list = re.findall(r'IPv4 Address.*: (\d+\.\d+\.\d+\.\d+)',data)
    ip_list = [(ip) for ip in ip_list if not ip.startswith("255")]

    if not ip_list:
        print("[DDR_INSTALLER][WARNING] Didn't find any local IP addresses on this machine.")
        print("[DDR_INSTALLER][WARNING] Keep in mind this address needs to be reachable from the DDR IDA plugin.")
        DDR_SERVER_IP = input("[DDR_INSTALLER][INFO] Pls enter the server IP address manually: ")  

    else:
        print("[DDR_INSTALLER][INFO] Found the following IP addresses:")
        for num, ip in enumerate(ip_list):
            print("[{:d}] {}".format(num,ip))

        DDR_SERVER_IP = input("[DDR_INSTALLER][INFO] Please choose server IP address (Default is 0) :") or "0"
        DDR_SERVER_IP = ip_list[int(DDR_SERVER_IP)]

    if DDR_SERVER_IP == "":
         print("[DDR_INSTALLER][ERROR] No server IP address found.")
         exit(1)

    print("[DDR_INSTALLER][INFO] server will listen on {}:{}".format(DDR_SERVER_IP, DDR_SERVER_PORT))

    # Create Certificates and copy them to server directory
    ddr_escaped_default_dir = ddr_default_dir.replace("\\","\\\\")
    ddr_cert_file = ddr_escaped_default_dir + "\\\\" + DDR_CERT_FILENAME 
    ddr_key_file  = ddr_escaped_default_dir + "\\\\" + DDR_CERT_KEY_FILENAME 
    load_mod("OpenSSL")
    create_self_signed_cert(DDR_SERVER_IP, ddr_cert_file, ddr_key_file)

    # Create DDR server API key file    
    apikey_file = ddr_default_dir + "\\" + DDR_APIKEY_FILE
    escapced_apikey_file = apikey_file.replace("\\","\\\\")
    if not create_apikey(apikey_file):
        return False

    # Create DDR server config file
    with open(DDRSERVER_CONFIG_FILE_TEMPLATE, 'r') as f:
            ddrserver_cfg_file = f.read()

    escaped_dynrio_run32 = dynrio_run32.replace("\\","\\\\")
    escaped_dynrio_run64 = dynrio_run64.replace("\\","\\\\")
    escaped_venv         = venv.replace("\\","\\\\") 

    ddrserver_cfg_file = ddrserver_cfg_file.replace("<DDR_SERVER_VERSION>"       , DDRSERVER_VERSION)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<APILOGGING>"               , APILOGGING)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<DEBUG_API_JSON>"           , DEBUG_API_JSON)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<CERT_FILE>"                , DDR_CERT_FILENAME)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<KEY_FILE>"                 , DDR_CERT_KEY_FILENAME)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<APIKEY_FILE>"              , DDR_APIKEY_FILE)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<SERVER_IP>"                , DDR_SERVER_IP)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<SERVER_PORT>"              , DDR_SERVER_PORT)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<MY_FQDN>"                  , MY_FQDN)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<CONFDIR>"                  , ddr_escaped_default_dir)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<DDR_VIRTENV>"              , escaped_venv)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<MAX_CFG_LINE_LENGTH>"      , str(MAX_CFG_LINE_LENGTH))
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<CFG_DYNRIO_DRRUN_X32>"     , escaped_dynrio_run32)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<CFG_DYNRIO_CLIENTDLL_X32>" , ddr_escaped_default_dir + "\\\\" + DDR_DLL32)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<CFG_DYNRIO_DRRUN_X64>"     , escaped_dynrio_run64)
    ddrserver_cfg_file = ddrserver_cfg_file.replace("<CFG_DYNRIO_CLIENTDLL_X64>" , ddr_escaped_default_dir + "\\\\" + DDR_DLL64)

    # save individualized config file
    ddrserver_cfg_filename = ddr_default_dir + "\\" + DDRSERVER_CONFIG_FILE
    with open(ddrserver_cfg_filename, 'w') as f:
        f.write(ddrserver_cfg_file)
    print("[DDR_INSTALLER][INFO] Wrote DDR server configuration to {}".format(ddrserver_cfg_filename))

    # copy DDR files to installation directory
    filename_list = [ "ddr_server.py", DDR_DLL32, DDR_DLL64]
    for fn in filename_list:
        shutil.copyfile( "install_data\\" + fn, ddr_default_dir + "\\" + fn)
        print("[DDR_INSTALLER][INFO] Copied file: {}".format(fn))

    return True

def built_plugin_zip(ddr_default_dir):

    ida_plugin_tmp              = "install_data\\ddr_plugin" 
    ida_plugin_cfg_template     = "templates\\ddr_config_template.json"
    ida_plugin_install_template = "templates\\ida_plugin_installer_template.py"
    ida_install_dir             = get_ida_dir()
    ida_plugin_dir              = get_ida_plugin_dir()
    ida_python_path             = get_ida_python_version()

    print("[DDR_INSTALLER][INFO] Using the following directories:")
    print("[DDR_INSTALLER][INFO] IDA install dir: {}".format(ida_install_dir))
    print("[DDR_INSTALLER][INFO] IDA plugin dir : {}".format(ida_plugin_dir))
    print("[DDR_INSTALLER][INFO] IDA Python dir : {}\n".format(ida_python_path))

    if not proceed("[DDR_INSTALLER][INFO] Is this correct ? [Y/n]"):
        exit(1)

    # copy plugin, plugin config file and cert file
    filename_list = [ "ddr_server.crt" ]
    os.makedirs(ida_plugin_tmp + "\\ddr", exist_ok=True)
    for fn in filename_list:
        cf = shutil.copyfile(ddr_default_dir + "\\" + fn, ida_plugin_tmp + "\\ddr\\" + fn)
        print("[DDR_INSTALLER][INFO] Copied file: {}".format(cf))

    cf = shutil.copyfile("install_data\\ddr_plugin.py", ida_plugin_tmp + "\\ddr_plugin.py")
    print("[DDR_INSTALLER][INFO] Copied file: {}".format(cf))

    # Create DDR plugin config file
    with open(ida_plugin_cfg_template, 'r') as f:
            ddrplugin_cfg_file = f.read()

    ida_plugin_dir_escaped = ida_plugin_dir.replace("\\", "\\\\")

    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<WEBSERVER>"           , DDR_SERVER_IP)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<WEBSERVER_PORT>"      , DDR_SERVER_PORT)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<DDR_WEBAPI_KEY>"      , DDR_APIKEY)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<CA_CERT>"             , ida_plugin_dir_escaped + "\\\\ddr\\\\" + DDR_CERT_FILENAME)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<VERIFY_CERT>"         , "true")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<DUMP_CFG_FILE>"       , "tmp_dump.cfg")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_API_TIMEOUT>"     , "30.0")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<DBG_LEVEL>"           , "2")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_INSTR_TO_EXECUTE>", "20000")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_LOG_ROUNDS>"      , "5")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_CMT_ROUNDS>"      , "3")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_INSTR_COUNT>"     , "50")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_UPLOAD_ATTEMPTS>" , "3")

    ddrplugin_cfg_filename = ida_plugin_tmp + "\\ddr\\ddr_config.json" 

    with open(ddrplugin_cfg_filename, 'w') as f:
        f.write(ddrplugin_cfg_file)

    print("[DDR_INSTALLER][INFO] Created IDA DDR plugin config file: {}".format(ddrplugin_cfg_filename))

    # Create plugin installer python script
    with open(ida_plugin_install_template, 'r') as f:
            ddrplugin_install_script = f.read()

    ddrplugin_install_script = ddrplugin_install_script.replace("<IDA_INSTALL_DIR>" , ida_install_dir) 
    ddrplugin_install_script = ddrplugin_install_script.replace("<IDA_PLUGIN_DIR>"  , ida_plugin_dir) 
    ddrplugin_install_script = ddrplugin_install_script.replace("<IDA_PYTHON_PATH>" , ida_python_path)    

    ddrplugin_install_script_filename = ida_plugin_tmp + "\\ida_plugin_installer.py" 

    with open(ddrplugin_install_script_filename, 'w') as f:
        f.write(ddrplugin_install_script)
    print("[DDR_INSTALLER][INFO] Created IDA DDR plugin installer script: {}".format(ddrplugin_install_script_filename))

    #Copy test files
    test_samples_dir = ida_plugin_tmp + "\\ddr\\ddr_test_samples"
    os.makedirs(test_samples_dir, exist_ok=True)
    cf = copy_tree("ddr_test_samples", test_samples_dir)
    
    print("Copied test samples to:")
    for copied_file in cf:
        print(copied_file)

    # Create ZIP archive 
    res = shutil.make_archive(ida_plugin_tmp, 'zip', ida_plugin_tmp)

    print("\n[DDR_INSTALLER][INFO] Created IDA DDR plugin zip archive: {}\n".format(ddrplugin_cfg_filename))
    
def installer_done():
    """
    Finalize installation and start DDR server in virtual environment.
    """
    print("\n")
    print("[DDR_INSTALLER][INFO] ------------------- Installer is done ------------------------")
    print("[DDR_INSTALLER][INFO] You can now go to '{}' and run 'python ddr_server.py'".format(ddr_default_dir))
    print("[DDR_INSTALLER][INFO] This will start the DDR server.\n")
    print("[DDR_INSTALLER][INFO] Make sure to allow the Windows Firewall rule")
    print("[DDR_INSTALLER][INFO] the first time you start the DDR server\n")
    print("[DDR_INSTALLER][INFO] You can test connectifity by going to the")
    print("[DDR_INSTALLER][INFO] following test website:\n")
    print("[DDR_INSTALLER][INFO] https://{}:{} \n".format(DDR_SERVER_IP, DDR_SERVER_PORT))
    print("[DDR_INSTALLER][INFO] with your prefered browser.")
    print("[DDR_INSTALLER][INFO] Once the server is running, you can start using the")
    print("[DDR_INSTALLER][INFO] IDA DDR plugin.")
    print("[DDR_INSTALLER][INFO] --------------------------------------------------------------\n")

    if not proceed("[DDR_INSTALLER][INFO] Should we proceed with starting the DDR server (ddr_server.py) for you ? [Y/n]"):
        print("[DDR_INSTALLER][INFO] Good bye !")
        exit(0)

    print("")
    my_cmd = 'python "' + ddr_default_dir + '"\\ddr_server.py "' + ddr_default_dir + '"\\ddr_server.cfg'   
    try:
        print("[DDR_INSTALLER][INFO] Starting DDR server:")
        print("[DDR_INSTALLER][INFO] {}".format(my_cmd))
        subprocess.run(my_cmd)
    except KeyboardInterrupt:
        pass
    exit(0)

# --- Main ---
if __name__ == "__main__":

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    mydir = os.path.realpath(__file__)
    print("\n[DDR_INSTALLER][INFO] Running from directory {}\n".format(mydir))

    TMP_FILE1 = "ddr_install_dir.tmp"

    if not sys.version_info >= (3, 0):
        print("[DDR_INSTALLER][ERROR] This script only runs in Python 3. Please install Python 3 first")
        print("[DDR_INSTALLER][ERROR] Reminder: The same applies to the IDA server and plugin.")
        print("[DDR_INSTALLER][INFO] Due to an IDA bug it is recommended to use Python 3.7 in the moment")
        print("[DDR_INSTALLER][INFO] on the machine where IDA is running on. You should still use Python 3.8")
        print("[DDR_INSTALLER][INFO] for the DDR server machine (this one). If it is the same machine, go for 3.7")
        print("[DDR_INSTALLER][INFO] Again, the latter is NOT recommended, better use two separate machines !")
        exit(1)

    if not os.path.isfile(TMP_FILE1):
        print("\n[DDR_INSTALLER][INFO] --- Welcome to the DDR Server installer script ---")
        print("[DDR_INSTALLER][INFO] This script installs the DDR server and all its dependencies. It will create a virtual environment")
        print("[DDR_INSTALLER][INFO] for all Python dependencies to make sure that it will not interfere with your existing Python setup.")
        print("[DDR_INSTALLER][INFO] Both DDR server and the DDR plugin only support Python version 3 and higher.")
        print("[DDR_INSTALLER][INFO] ------------------------------------- READ THIS ----------------------------------------------------")
        print("[DDR_INSTALLER][INFO] If you are using IDA < 7.5 you should use Python 3.7 on the IDA machine. This is due to a")
        print("[DDR_INSTALLER][INFO] bug in IDA 7.4 which is fixed in 7.5. If you are using 7.5 we recommend to use Python 3.8.")
        print("[DDR_INSTALLER][INFO] In any case it is recommended to use Python 3.8 for the DDR server machine. If it is the")
        print("[DDR_INSTALLER][INFO] same machine, go for 3.7. Again, the latter setup is NOT recommended, better use two separate")
        print("[DDR_INSTALLER][INFO] machines !")
        print("[DDR_INSTALLER][INFO] ----------------------------------------------------------------------------------------------------")
        if not proceed("[DDR_INSTALLER][INFO] Do you want to proceed ? [Y/n] ? "):
            print("[DDR_INSTALLER][INFO] Good bye!")
            exit(0)

        print("[DDR_INSTALLER][INFO] Please enter installation directory for DDR server or hit enter for default directory.")
        ddr_default_dir = input("[DDR_INSTALLER][INFO] Default is C:\\tools\\DDR : ") or "C:\\tools\\DDR"
        if ddr_default_dir[-1:] == "\\":
            ddr_default_dir = ddr_default_dir[:-1]

        if len(ddr_default_dir) > MAX_INSTALL_DIR:
            print("[DDR_INSTALLER][ERROR] Max. install directory length is {:d}. Please use a shorter path.".format(MAX_INSTALL_DIR))
            print("[DDR_INSTALLER][ERROR] Your DDR installation path is {:d} characters long.".format(len(ddr_default_dir)))
            exit(1)

        if os.path.exists(ddr_default_dir):
            print("[DDR_INSTALLER][INFO] Directory '{}' exists.".format(ddr_default_dir))
            print("[DDR_INSTALLER][INFO] If this is an update it is recommended to delete the old installation first.")
            if proceed("[DDR_INSTALLER][INFO] Should we delete the Directory '{}' [Y/n] ?"):
                shutil.rmtree(ddr_default_dir)

        print("[DDR_INSTALLER][INFO] Installing DDR server to directory: {}".format(ddr_default_dir))

        try:
            pathlib.Path(ddr_default_dir).mkdir(parents=True, exist_ok=True) 
        except PermissionError:
            print("[DDR_INSTALLER][ERROR] You do not have the access rights to create this directory.")
            exit(1)

        with open(TMP_FILE1, 'w') as f:
            f.write(ddr_default_dir)
    else:
        with open(TMP_FILE1, 'r') as f:
            ddr_default_dir = f.read()
        print("[DDR_INSTALLER][INFO] Found DDR directory: {} for phase 2.".format(ddr_default_dir))

    venv=ddr_default_dir + "\\" + DDR_VIRTENV_NAME 
    
    if not os.path.isdir(venv):
        # Phase 1: Create virtual enviroment
        if proceed("[DDR_INSTALLER][INFO] Installing virtual enviroment to '{}' Proceed [Y/n] ? ".format(venv) ):
            print("[DDR_INSTALLER][INFO] Phase 1: Create virtual enviroment.")
            runcmd("python -m venv \"" + venv + "\"")
        else:
            print("[DDR_INSTALLER][ERROR] Installation aborted.")
            exit(1)

    if not is_venv():
        # Phase 2: Activate virtual enviroment and restart this script in it
        print("[DDR_INSTALLER][INFO] Phase 2: Activating virtual enviroment.")
        python_bin = venv + "\\Scripts\\python.exe"
        script_file = os.path.realpath(__file__)
        try:
            subprocess.run([python_bin, script_file])
        except KeyboardInterrupt:
            pass
        exit(0)
    else:
        if sys.prefix == venv:  
            print("[DDR_INSTALLER][INFO] We are running in the right virtual enviroment : {}".format(sys.prefix))
            os.remove(TMP_FILE1)
            print("[DDR_INSTALLER][INFO] Temp. file: {} deleted. Starting main installation routine.".format(TMP_FILE1))

            # Main installation routine
            # Install virtual enviroment and dependancies 
            if install_deps(venv, ddr_default_dir):
                print("[DDR_INSTALLER][INFO] Successfully installed DDR server to {}".format(ddr_default_dir)) 
                
                if not proceed("[DDR_INSTALLER][INFO] Should we proceed with the installation of the plugin ? [Y/n]"):
                    print("[DDR_INSTALLER][INFO] IDA Plugin installation skipped.")
                    installer_done()
                    exit(0)

                #Prepare IDA plugin files and config and built zip file
                built_plugin_zip(ddr_default_dir)

                # start web server 
                python_bin  = venv + "\\Scripts\\python.exe"
                script_file = "install_data\\installer_web_server.py"
                args        = "{}".format(DDR_SERVER_IP)  
                try:
                    subprocess.run([python_bin, script_file, args])
                except KeyboardInterrupt:
                    pass
                
                installer_done()
            else:
                print("[DDR_INSTALLER][ERROR] Failed installing dependencies.")
                exit(1)
        else:
            print("[DDR_INSTALLER][ERROR] We are in a different virtual enviroment : {}".format(sys.prefix))
            exit(1)

    exit(0)






