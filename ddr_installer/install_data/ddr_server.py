#-------------------------------------------------------------------------------
#
#   IDA Pro Plug-in: Dynamic Data Resolver (DDR) Server 
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
#   Requirements
#   ------------
# 
#   DynamoRio Framework (https://www.dynamorio.org/)
#   Nginx               (http://nginx.org/en/docs/windows.html)   
#
#   Python:         
#      Flask       (http://flask.pocoo.org/)               
#      PyOpenSSL   (https://pyopenssl.org/en/stable/)           
#      Werkzeug    (https://palletsprojects.com/p/werkzeug/)
#      Cheroot     (https://github.com/cherrypy/cheroot)
#
#   Installation:                                            
#   -------------
#      
#   Just run the installation script (DDR_INSTALLER.py). It downloads and  
#   configures everything for you, including the dependencies. Run it on the DDR 
#   server machine and follow the instructions.
# 
#   Common setup:
#   -------------
#
#   Analyst PC (IDA, ddr_plugin.py) 
#              | 
#              | IP network (allow port DDR_CONFIG_SETTINGS.WEBSERVER_PORT (Default: 5000))
#              |
#              | IP addr = [DDR_CONFIG_SETTINGS.WEBSERVER/DDR_CONFIG_SETTINGS.WEBSERVER_PORT variable]
#              V
#   Malware PC (DynamoRio, ddr32.dll, ddr64.dll, ddr_server.py)
#          
#-----------------------------------------------------------------------------------


# try-except module loading to allow script to be run from outside the 
# virtual enviroment.
try:
    import sys
    import subprocess
    import os
    import time
    import socket
    import string
    import random
    import tempfile
    import traceback
    import zipfile
    import werkzeug
    import traceback
    import json
    import ssl
    import re
    import hashlib
    import time
    import struct
    import binascii
    import logging
    import OpenSSL
    import uvicorn
    import shutil
    import ctypes
    import glob
    import pprint
    import psutil
    import signal
    from fastapi                import Body, FastAPI, File, Form, UploadFile, HTTPException, Query
    from pydantic               import BaseModel, Field
    from pydantic.json          import pydantic_encoder     
    from starlette.responses    import RedirectResponse, StreamingResponse, FileResponse, Response, HTMLResponse, JSONResponse
    from starlette.requests     import Request 
    from cheroot.wsgi           import Server as WSGIServer
    from datetime               import datetime
    MODULE_IMPORT_SUCCESS = True
except:
    MODULE_IMPORT_SUCCESS = False
    pass

# DDR server configuration file
DDR_SERVER_CFG          = "ddr_server.cfg"
DDR_PROCESS_TRACE_FILE  = "ddr_processtrace.txt"
DDR_THREAD_NAME_STUB    = "ddr_threads_"
DDR_DEBUG_CONSOLE_LEVEL = "INFO"
DDR_DEBUG_FILE_LEVEL    = "DEBUG"
try:
    DDR_SERVER_CFG = sys.argv[1]
except:
    pass

# Are we running in a virtual enviroment ?
def is_venv():
    return (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

# We are running in a virtual enviroment:
if is_venv():
    print("[DDRSERVER][INFO] We are running in virtual enviroment : {}".format(sys.prefix))
    if MODULE_IMPORT_SUCCESS == False:
        print("[DDRSERVER][ERROR] Module import failed. Pls check if you have installed all dependencies.")
        print("[DDRSERVER][ERROR] Run installation script again.")
        exit(1)

# We are NOT running in a virtual enviroment:
else:
    print("[DDRSERVER][INFO] We are NOT running in virtual enviroment.")
    # Quick n dirty parser without any module dependencies to find DDR_VIRTENV in config file
    with open(DDR_SERVER_CFG, 'r') as fp:
        for line in fp:
            if "DDR_VIRTENV" in line:
                offset = line.find(': "') 
                DDR_VIRTENV = line[offset+3:-3].replace("\\\\","\\") 
    try:
        print("[DDRSERVER][INFO] Trying to restart script in virtual enviroment: {}".format(DDR_VIRTENV))
    except:
        print("[DDRSERVER][ERROR] Couldn't find virtual enviroment name in configuration file: {}.".format(DDR_SERVER_CFG))
        print("[DDRSERVER][ERROR] If you run DDR server from another directory you need to specify the")
        print("[DDRSERVER][ERROR] configuration file as first argument. ")
        print("[DDRSERVER][ERROR] E.g. ddr_server.py C:\\tools\\ddr\\ddr_server.cfg")
        exit(1)
    
    # Restart script in virtual enviroment
    python_bin  = DDR_VIRTENV + "\\Scripts\\python.exe"
    script_file = os.path.realpath(__file__) 
    try:
        subprocess.run([python_bin, script_file, DDR_SERVER_CFG])     
    except KeyboardInterrupt:
        pass
    exit(0)


# Read global configuration file
if not os.path.isfile(DDR_SERVER_CFG):
    print("[DDRSERVER][ERROR] Configuration file: {} not found.".format(DDR_SERVER_CFG))
    exit(1)

with open(DDR_SERVER_CFG, 'r') as handle:
    try:
        ddrserver_cfg = json.load(handle)
    except:
        print("[DDRSERVER][ERROR] Couldn't load JSON configuration file: {}.".format(DDR_SERVER_CFG))
        exit(1)
try:
    DDR_SERVER_VERSION       = ddrserver_cfg["DDR_SERVER_VERSION"]          # e.g. "1.0"
    APILOGGING               = ddrserver_cfg["APILOGGING"]                # e.g. (NORMAL,MEDIUM,DEBUG)
    DEBUG_API_JSON           = ddrserver_cfg["DEBUG_API_JSON"]              # e.g. False
    CERT_FILE                = ddrserver_cfg["CERT_FILE"]                   # e.g "ddr_server.crt"
    KEY_FILE                 = ddrserver_cfg["KEY_FILE"]                    # e.g "ddr_server.key"
    APIKEY_FILE              = ddrserver_cfg["APIKEY_FILE"]                 # e.g "ddr_apikey.txt"
    SERVER_IP                = ddrserver_cfg["SERVER_IP"]                   # e.g "192.168.50.21"
    SERVER_PORT              = ddrserver_cfg["SERVER_PORT"]                 # e.g "5000"
    MY_FQDN                  = ddrserver_cfg["MY_FQDN"]                     # e.g "malwarehost.local"  # only for the certificate, no DNS needed
    CONFDIR                  = ddrserver_cfg["CONFDIR"]                     # e.g "C:\tools\DDR"
    DDR_VIRTENV              = ddrserver_cfg["DDR_VIRTENV"]                 # e.g. "C:\\tools\\DDR\\ddr_venv"
    MAX_CFG_LINE_LENGTH      = ddrserver_cfg["MAX_CFG_LINE_LENGTH"]         # e.g. 356
    CFG_DYNRIO_DRRUN_X32     = ddrserver_cfg["CFG_DYNRIO_DRRUN_X32"]        # e.g. "C:\tools\DynamoRIO-Windows-7.1.0-1\bin32\drrun.exe"
    CFG_DYNRIO_CLIENTDLL_X32 = ddrserver_cfg["CFG_DYNRIO_CLIENTDLL_X32"]    # e.g. "C:\tools\DDR\ddr32.dll"
    CFG_DYNRIO_DRRUN_X64     = ddrserver_cfg["CFG_DYNRIO_DRRUN_X64"]        # e.g. "C:\tools\DynamoRIO-Windows-7.1.0-1\bin64\drrun.exe" 
    CFG_DYNRIO_CLIENTDLL_X64 = ddrserver_cfg["CFG_DYNRIO_CLIENTDLL_X64"]    # e.g. "C:\tools\DDR\ddr64.dll"
except:
    print("[DDRSERVER][ERROR] Couldn't parse JSON configuration file: {}.".format(DDR_SERVER_CFG))
    exit(1)

app = FastAPI()

# verify directory ends with backslash
if not CONFDIR.endswith("\\"):
    CONFDIR += "\\"

tmpdir = tempfile.gettempdir()
samplesdir = CONFDIR + "samples\\"

cert_file = CONFDIR + CERT_FILE
cert_key  = CONFDIR + KEY_FILE

testcounter = 0

LOG_FILE = CONFDIR + "ddr_server.log"
MAX_LOGFILE_SIZE = 1048576 * 5 # Max. size 5MB

# -------------------- x64dbg Script templates ------------------------
x64dbg_script = r'''
log "----------DDR x64dbg script started -----------"

init <SAMPLE_NAME>

msgyn "Sample loaded. Should we skip breaking at the entry point?"
cmp $result, 1
jne break_at_entry

// Delete all exiting bp
bc
bphc
bpmc

break_at_entry:
// get real and org base image to calculate relocated addresses
mov $org_base, <ORG_IMAGE_BASE>
mov $true_base,mod.main()
log "Org. image base {$org_base}"
log "True image base {p:$true_base}"

// Set bp at IDA ea
mov $org_bp_addr, <BREAK_ADDR>
mov $bp_addr, $true_base - $org_base + $org_bp_addr
bp $bp_addr
SetBreakpointCommand $bp_addr, "log \"IDA breakpoint reached.\"; msg \"IDA breakpoint reached.\"
'''

nop_x64_script = r'''
// NOP out
mov $nop_orgaddr, <NOP_ORG_ADDR> 
mov $nop_size, .<NOP_SIZE_DEC> 
mov $nop_addr, $true_base - $org_base + $nop_orgaddr
memset $nop_addr,90,$nop_size; 
log "NOP'ed out {$nop_size} bytes at {p:$nop_addr}"
'''

patch_eflag_init = r'''
// set bp for EFLAGS (toggle <EFLAG_STR> flag)
mov $CF,0x0001
mov $PF,0x0004
mov $AF,0x0010
mov $ZF,0x0040
mov $SF,0x0080
mov $TF,0x0100
mov $IF,0x0200
mov $DF,0x0400
mov $OF,0x0800
'''

patch_eflag_main = r'''
mov $org_bp_addr,<PATCH_AT_ADDR>
mov $bp_addr, $true_base - $org_base + $org_bp_addr
bp $bp_addr
SetBreakpointSingleshoot $bp_addr
SetBreakpointCommand $bp_addr, "log \"org. EFLAGS: \"{eflags}; eflags=eflags^$<EFLAG_STR>; log \"Toggled <EFLAG_STR> EFLAGS\""
log "EFLAGS <EFLAG_STR> flag will be toggled at PC {$bp_addr}"
'''

patch_calls = r'''
// Skip calls to function 
mov $call_orgaddr, <PATCH_FUNC_ADDR> 
mov $call_org, $true_base - $org_base + $call_orgaddr

memset $call_org,b8,1;      // B8 05 00 00 00   mov eax,5
memset $call_org+1,<PATCH_FUNC_RET1>,1;     
memset $call_org+2,<PATCH_FUNC_RET2>,1;
memset $call_org+3,<PATCH_FUNC_RET3>,1;
memset $call_org+4,<PATCH_FUNC_RET4>,1;
memset $call_org+5,c3,1;    // ret

log "Function at {$call_org} will be skipped. Return value set to {$call_ret}"
'''

patch_calls_x64 = r'''
// Skip calls to function 
mov $call_orgaddr, <PATCH_FUNC_ADDR> 
mov $call_org, $true_base - $org_base + $call_orgaddr

memset $call_org,48,1;      // 48 B8 05 00 00 00 00 00 00 00  mov rax,5
memset $call_org+1,b8,1;
memset $call_org+2,<PATCH_FUNC_RET1>,1;     
memset $call_org+3,<PATCH_FUNC_RET2>,1;
memset $call_org+4,<PATCH_FUNC_RET3>,1;
memset $call_org+5,<PATCH_FUNC_RET4>,1;
memset $call_org+6,<PATCH_FUNC_RET5>,1;     
memset $call_org+7,<PATCH_FUNC_RET6>,1;
memset $call_org+8,<PATCH_FUNC_RET7>,1;
memset $call_org+9,<PATCH_FUNC_RET8>,1;
memset $call_org+A,c3,1;    // ret

log "Function at {$call_org} will be skipped. Return value set to {$call_ret}"
'''

exit_x64dbg_script = r'''
// Exit
exit:
log "----------DDR x64dbg script done -----------"
erun
ret
'''
# ---------------------------------------------------

class Item(BaseModel):
    apikey: str = Field(..., description="Secret key to access API", max_length=30)

def ddr_exception_handler_to_console_only(msg, ex):
    """ DDR exception handler. Handle exceptions without killing the plugin """
    print("[DDRSERVER][ERROR] ================================================= Exception ===========================================================")
    print("[DDRSERVER][ERROR] {}".format(msg))
    print("[DDRSERVER][ERROR] -----------------------------------------------------------------------------------------------------------------------")
    ex_type, ex_value, ex_traceback = sys.exc_info()
    trace_back = traceback.extract_tb(ex_traceback)
    stack_trace = []
    for trace in trace_back:
        stack_trace.append("[DDRSERVER][ERROR] File  : {}, Func.Name: {}, Line: {:d} \n[DDRSERVER][ERROR] Issue : {}".format(trace[0], trace[2], trace[1], trace[3]))
    print("[DDRSERVER][ERROR] Exception type : {} ".format(ex_type.__name__))
    print("[DDRSERVER][ERROR] Exception message : {}".format(ex_value))
    for msg in stack_trace:
        print("[DDRSERVER][ERROR] Stack trace : \n{}".format(msg))
    print("[DDRSERVER][ERROR] =======================================================================================================================")

def ddr_exception_handler_to_logger(msg, ex):
    """ DDR exception handler. Handle exceptions without killing the plugin """
    log.error("================================================= Exception ===========================================================")
    log.error(msg)
    log.error("-----------------------------------------------------------------------------------------------------------------------")
    ex_type, ex_value, ex_traceback = sys.exc_info()
    trace_back = traceback.extract_tb(ex_traceback)
    stack_trace = []
    for trace in trace_back:
        stack_trace.append("  File  : {}, Func.Name: {}, Line: {:d} \n  Issue : {}".format(trace[0], trace[2], trace[1], trace[3]))
    log.error(" Exception type : {} ".format(ex_type.__name__))
    log.error(" Exception message : {}".format(ex_value))
    for msg in stack_trace:
        log.error(" Stack trace : \n{}\n".format(msg))
    log.error("=======================================================================================================================")

def set_logging():

    global log
    log_file_writable = False

    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'w') as f:
            pass
        log_file_writable = True
    except Exception as ex:
        ex_type = sys.exc_info()[0]
        if ex_type.__name__ == 'PermissionError':
            print("[DDRSERVER][WARNING] No permission to write to logfile. Logging to file disabled.")
        else:
            msg = "Can't access log file. Logging to file disabled."
            ddr_exception_handler_to_console_only(msg, ex)

    if log_file_writable:
        # Log to file and console
        print("[DDRSERVER][INFO] Logging to console and logfile: {}".format(LOG_FILE))
        logging_config = {
            'version': 1,
            'disable_existing_loggers': True,
            'formatters': {
                'verbose': {
                    'format': '%(asctime)s %(levelname)s -- %(message)s  [Module:%(module)s Proc:%(process)d Thread:%(thread)d Handler:%(name)s]' 
                },
                'verbose_console': {
                    'format': '[DDRSERVER][%(levelname)s] %(asctime)s -- %(message)s  [Module:%(module)s Proc:%(process)d Thread:%(thread)d Handler:%(name)s]'  
                },
                'simple': {
                    'format': '%(levelname)s %(message)s'
                },
                'simple_console': {
                    'format': '[DDRSERVER][%(levelname)s] %(message)s'
                },
            },
            'handlers': {
                'to_console': {
                    'level': DDR_DEBUG_CONSOLE_LEVEL,
                    'class': 'logging.StreamHandler',
                    'formatter': 'verbose_console'
                },
                'to_file': {
                    'level': DDR_DEBUG_FILE_LEVEL,
                    'formatter': 'verbose',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': LOG_FILE,
                    'mode': 'a',
                    'maxBytes': MAX_LOGFILE_SIZE    
                    #'backupCount': 3           # no backups
                },
            },    
            'loggers': {
                'uvicorn': {
                    'propagate': False,
                    'handlers': ['to_console', 'to_file'],
                    'level': 'DEBUG',
                },
                'uvicorn.error': {
                    'propagate': False,
                    'handlers': ['to_console', 'to_file'],
                    'level': 'DEBUG',
                },
                'uvicorn.access': {
                    'propagate': False,
                    'handlers': ['to_console', 'to_file'],
                    'level': 'DEBUG',
                },
                'uvicorn.asgi': {
                    'propagate': False,
                    'handlers': ['to_console', 'to_file'],
                    'level': 'DEBUG',
                },
                'fastapi': {
                    'propagate': False,
                    'handlers': ['to_console', 'to_file'],
                    'level': 'DEBUG',
                },
                'app': {
                    'handlers': ['to_console', 'to_file'],
                    'propagate': False,
                    'level': 'DEBUG',
                },
            },
        } 
    else:
        # Log to console only
        print("[DDRSERVER][INFO] Logging to console only")
        logging_config = {
            'version': 1,
            'disable_existing_loggers': True,
            'formatters': {
                'verbose_console': {
                    'format': '[DDRSERVER][%(levelname)s] %(asctime)s -- %(message)s  [Module:%(module)s Proc:%(process)d Thread:%(thread)d Handler:%(name)s]'  
                },
                'simple': {
                    'format': '%(levelname)s %(message)s'
                },
            },
            'handlers': {
                'to_console': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'verbose_console'
                },
            },    
            'loggers': {
                'uvicorn': {
                    'propagate': False,
                    'handlers': ['to_console'],
                    'level': 'DEBUG',
                },
                'uvicorn.error': {
                    'propagate': False,
                    'handlers': ['to_console'],
                    'level': 'DEBUG',
                },
                'uvicorn.access': {
                    'propagate': False,
                    'handlers': ['to_console'],
                    'level': 'DEBUG',
                },
                'uvicorn.asgi': {
                    'propagate': False,
                    'handlers': ['to_console', 'to_file'],
                    'level': 'DEBUG',
                },
                'fastapi': {
                    'propagate': False,
                    'handlers': ['to_console'],
                    'level': 'DEBUG',
                },
                'app': {
                    'handlers': ['to_console'],
                    'propagate': False,
                    'level': 'DEBUG',
                },
            },
        }
    
    logging.config.dictConfig(logging_config)
    log = logging.getLogger('app')
    # --- Debug ---
    #loggers = [logging.getLogger()]  # get the root logger
    #loggers = loggers + [logging.getLogger(name) for name in logging.root.manager.loggerDict]
    #pprint(loggers)


class ddr_api_v1_parameter(BaseModel):
    """ JSON API Fields """
    #
    # TBD: set max. length and description
    #
    # (...) = Required / None = optional
    apikey              : str = None
    cmd_id              : int = Query(None, alias="id")                  
    arch_bits           : int = None   
    sample_file         : str = None   
    sample_sha256       : str = None   
    buf_size_addr       : dict = {}   
    buf_size_op         : dict = {}   
    buf_addr_addr       : dict = {}   
    buf_addr_op         : dict = {}   
    buf_dump_addr       : dict = {}   
    nop_start_addr      : dict = {}   
    nop_end_addr        : dict = {}   
    eflag_name          : dict = {}   
    eflag_addr          : dict = {}   
    call_addr           : dict = {}   
    call_ret            : dict = {}   
    trace_light         : dict = {}   
    trace_start         : dict = {}   
    trace_end           : dict = {}   
    trace_max_instr     : dict = {}   
    trace_breakaddress  : dict = {}   
    filelist2del        : list = []   
    dl_file             : list = []   
    run_opt             : str  = None   
    other               : dict = {}
    
  
# Executed at startup 
@app.on_event("startup")
async def startup():
    set_logging()
    log.info("*** DDR server started ***")
    log.info("Using configuration file: {}".format(DDR_SERVER_CFG))
    pass

# ---------------------------------------------------
# Test Website to detect connection issues
@app.get("/")
async def webtest():
    """ 
    Optional test website for debugging SSL issues via 
    browser
    """
    log.info("HTTP Ping received.")
    global testcounter
    testcounter += 1
    content = """
<html>
<header><title>DDR Server Test Website</title></header>
<body>
DDR server Test website. Counter: <TESTCOUNTER>
</body>
</html>
    """.replace('<TESTCOUNTER>', str(testcounter))
    return HTMLResponse(content=content)
# ---------------------------------------------------

@app.post("/uploadsample")
async def uploadsample(*, file: UploadFile = File(...), apikey: str = Form(...)):
    """
    Receive the malware sample from the DDR plugin
    """
    log.info("Received file upload request")

    if apikey != DDR_WEBAPI_KEY:
        return JSONResponse(status_code=201, content={ "return_status" : "Error: Wrong API key" })

    if file.filename == '':
        log.error("No file selected in request.")
        return JSONResponse(status_code=201, content={ "return_status" : "Error: No file selected in request." })

    if not os.path.isdir(samplesdir):
        os.mkdir(samplesdir)
        log.info("Created directory: {}.".format(samplesdir))

    filename=werkzeug.utils.secure_filename(file.filename) 
    sample_filename = samplesdir + filename
    
    log.info("Received file {}".format(sample_filename))
    log.info("Trying to save file: {} to directory: {}".format(sample_filename, samplesdir))

    try:
        with open(sample_filename, 'wb') as sample_fp:
            shutil.copyfileobj(file.file, sample_fp)
    except Exception as ex:
        ddr_exception_handler_to_logger("Failed to save file to malware machine.",ex)
        return JSONResponse(status_code=201, content={ "return_status" : "Failed to copying file to malware machine." })

    log.info("File: {} saved.".format(sample_filename))
    return { "return_status" : "Success: Copied file to malware machine." }


@app.post("/api/v1/json")
async def json_api_v1(ddr_api_req: ddr_api_v1_parameter):
    """
    JSON API handler
    """

    log.info("Incoming JSON API request.");

    json_content = json.loads(ddr_api_req.json()) 

    global last_trace_filenames
    global last_trace_filename
    global last_trace_filename_api
    global last_zipfilename

    log.debug("Received JSON string:\n{}".format(json.dumps(json_content,indent=4, sort_keys=True)))

    if ddr_api_req.apikey:
        apikey = ddr_api_req.apikey
        if apikey != DDR_WEBAPI_KEY:
            log.error("Wrong API key.")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Wrong API key." })
    else:
        log.error("Error: API key missing.")
        return JSONResponse(status_code=201, content={ "return_status" : "Error: API key missing." })

    if ddr_api_req.cmd_id:
        try:
            cmd_id = int(ddr_api_req.cmd_id)
            log.info("API command id = {:d}".format(cmd_id))
        except:
            log.error("Failed to convert command id number.")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to convert command id number." })
    else:
        log.error("No 'id' field provided. Please specify an id.")
        return JSONResponse(status_code=201, content={ "return_status" : "Error: No 'id' field provided. Please specify an id." })

    if ddr_api_req.arch_bits:
        try:
            arch_bits = int(ddr_api_req.arch_bits)
        except:
            log.error("Failed to read arch_bits.")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to read arch_bits." })
    else:
        log.error("No 'arch_bits' field provided. Please specify an id.")
        return JSONResponse(status_code=201, content={ "return_status" : "Error: No 'arch_bits' field provided. Please specify an id." })

    if ddr_api_req.sample_file:
        try:
            sample_file           = ddr_api_req.sample_file
            sample_sha256         = ddr_api_req.sample_sha256
            sample_file_with_path = samplesdir + sample_file
            dynrio_cfg_file  = samplesdir + os.path.splitext(sample_file)[0] + ".cfg"  

            if not os.path.isfile(sample_file_with_path):
                log.info("Sample file not found. Telling client to upload it.")
                return JSONResponse(status_code=201, content={ "return_status" : "Error: Sample file not found." })

            sample_on_disk_sha256 = get_hash(sample_file_with_path)['sha256_sum']
            if not sample_sha256 == sample_on_disk_sha256:
                log.info("Sample file has the same name ({}), but wrong hash.".format(sample_file_with_path))
                log.info("SHA256 of file on disk: {}".format(sample_on_disk_sha256))
                log.info("SHA256 of API request : {}".format(sample_sha256))
                log.info("Requesting fresh download...")
                return JSONResponse(status_code=201, content={ "return_status" : "Error: Sample file not found." })
            else:
                log.info("Sample file found: {}".format(sample_file_with_path))
        except Exception as ex:
            ddr_exception_handler_to_logger("Failed to convert dynrio_sample name.",ex)
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to convert dynrio_sample name." })
    else:
        log.error("Mandatory dynrio_sample field missing.")
        return JSONResponse(status_code=201, content={ "return_status" : "Error: dynrio_sample field missing." })

    # write dynrio cfg file and execute sample
    if cmd_id == 5:
        log.info("Received API Command: Dump buffer.")
        result = write_dump_cfg(json_content, dynrio_cfg_file)
        if not result:
            log.error("Failed to generating the DDR config file")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to generating the DDR config file."})

        dump_filename = result["dump_filename"]
        if not dump_filename:
            log.error("Failed writing JSON data to DDR config file.")
            return JSONResponse(status_code=201, content={ "return_status" : "Failed writing JSON data to DDR config file. See server site for details."})

        dyn_full_cmd = build_dynRio_full_run_cmd_dump(dynrio_sample=sample_file_with_path, arch_bits=arch_bits, cfgfile=dynrio_cfg_file, cmd_opts=None)
        
        if dyn_full_cmd:
            runstatus = runcmd(dyn_full_cmd)
            if runstatus['status'] == 'success':
                text      = runstatus['stdout'].decode()
                try:
                    regex = r'\[DDR\] \[INFO\] \[FINAL\] Done\. Written [01234567890]+ bytes from address (.+?) to file:'
                    #buffer_address = re.search(regex, text, re.M).group(1)
                    buffer_address = re.findall(regex, text, re.M)
                except AttributeError:
                    log.warning("Buffer address not found in DDR client output") 
                    buffer_address = None 
                try:
                    regex = r'\[DDR\] \[INFO\] \[FINAL\] Done\. Written (.+?) bytes from address '
                    #buffer_size = re.search(regex, text, re.M).group(1)
                    buffer_size = re.findall(regex, text, re.M)
                except AttributeError:
                    log.warning("Buffer size not found in DDR client output")
                    buffer_size = None 
                try:
                    regex = r'\[DDR\] \[INFO\] \[FINAL\] Done\. Written [01234567890]+ bytes from address 0x[01234567890abcdefABCDEF]+ to file: (.+?.bin)'
                    dumped_file = re.findall(regex, text, re.M)
                except AttributeError:
                    log.warning("Dumped file not found in DDR client output") 
                    dumped_file = None 

                successful_dumpfiles     = []
                successful_dumpfile_size = []
                successful_dumpfile_addr = []
                if buffer_address and buffer_size and dumped_file:
                    for num, df in enumerate(dumped_file):
                        log.info("Dump file '{}' successfully generated. Buffer found at address: {} with size: {}.".format(df, buffer_address[num], buffer_size[num]))    
                        if os.path.isfile(df):
                            dumpfile_size = os.path.getsize(df)
                            if dumpfile_size > 0:                               
                                log.info("Dumped buffer '{}' seems to be valid, adding it to file list.".format(df))
                                successful_dumpfiles.append(df)
                                successful_dumpfile_size.append(buffer_size[num])
                                successful_dumpfile_addr.append(buffer_address[num])  
                            else:
                                log.error("Something went wrong. Dump file has 0 bytes length. Buffer likely not found at runtime. Check DDR client output above.") 
                                return JSONResponse(status_code=201, content={ "return_status" : "Error: Something went wrong. Dump file has 0 bytes length. Buffer likely not found at runtime."})
                        else:
                            log.error("Something went wrong. Dump file is not a file. Buffer likely not found at runtime. Check DDR client output above.") 
                            return JSONResponse(status_code=201, content={ "return_status" : "Error: Something went wrong. Dump file is not a file. Buffer likely not found at runtime. Check DDR client output above."})
                else:
                    log.error("Something went wrong. Failed to find dump filename and/or dump address and size in output.")          
                    return JSONResponse(status_code=201, content={ "return_status" : "Error: Something went wrong. Failed to find dump filename and/or dump address and size. Buffer likely not found at runtime."})
            else:
                log.error("Something went wrong. DynRio client command execution failed.")
                return JSONResponse(status_code=201, content={ "return_status" : "Error: DynRio client command execution failed."})
        else:
            log.error("Failed to build DynRio client cmd line")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to build DynRio cmd line."})

        if successful_dumpfiles:
            log.info("Done. Successfully dumped buffer to file.")
            return { "return_status" : "Success" , "files" : successful_dumpfiles , "fileaddrs" : successful_dumpfile_addr, "filesizes" : successful_dumpfile_size }

    # delete tmp. dump file(s)
    if cmd_id == 6:
        log.info("Received API Command: Delete file.")
        try:
            if delete_files(json_content['filelist2del']):
                log.info("Successfully deleted temp. dump files.")
                return { "return_status" : "Successfully deleted temp. dump files" }
            else:
                log.warning("Deleting temp. dump file failed. This is normal if the last API trace run failed.")
                return JSONResponse(status_code=201, content={ "return_status" : "Error: Deleting temp. dump file failed. This is normal if the last API trace run failed."})

        except:
            log.error("Failed to delete temp. dump file.")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to delete temp. dump file."})
        
    # run trace
    if cmd_id == 7:
        log.info("Received API Command: Run trace.")
        result = write_dump_cfg(json_content, dynrio_cfg_file)
        if not result:
            log.error("Failed to generating the DDR config file")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to generating the DDR config file" })

        trace_filename = result["trace_filename"] 
        last_trace_filename     = trace_filename
        last_trace_filename_api = trace_filename_api = os.path.splitext(trace_filename)[0] + "_apicalls.json"
        last_zipfilename        = zipfilename        = os.path.splitext(trace_filename)[0] + ".zip"

        dyn_full_cmd = build_dynRio_full_run_cmd_dump(dynrio_sample=sample_file_with_path, arch_bits=arch_bits, cfgfile=dynrio_cfg_file, cmd_opts=None)

        if dyn_full_cmd:
            runstatus = runcmd(dyn_full_cmd)
            if runstatus['status'] == 'success':
                log.info("Trace logfile written to     : {}".format(trace_filename))
                log.info("API trace logfile written to : {}".format(trace_filename_api))

                #filelist = [ trace_filename, trace_filename_api ]                      # old single process logic. TBD delete
                filelist = get_all_tracefiles(os.path.splitext(trace_filename)[0])      # new logic for multi-process samples transfer all zip files
                last_trace_filenames = filelist

                # Check if file list was filled with files from sample directory
                if len(filelist) == 0:
                    log.error("Failed to generate trace file list for zip file")
                    return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to generate trace file list for zip file" })

                # Check if trace and trace APi file are in the list
                if trace_filename in filelist:
                   log.debug("Trace file ({}) found in directory.".format(trace_filename))
                else:
                   log.error("Trace file ({}) NOT found in directory.".format(trace_filename))
                   return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to generate trace file list for zip file. Trace file not found." })  

                if trace_filename_api in filelist:
                   log.debug("Trace file ({}) found in directory.".format(trace_filename_api))
                else:
                   log.error("Trace file ({}) NOT found in directory.".format(trace_filename_api))  
                   return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to generate trace file list for zip file. Trace API file not found." })
                
                # Debug
                log.debug("Going to zip following files:")
                for n in filelist:
                    log.debug("Filename: {}".format(n))

                # Zip file list and send to IDA plugin
                if zip_files(filelist, zipfilename):
                    log.info("Start sending zip file back to client...")
                    return FileResponse(zipfilename, media_type='application/x-binary', filename="test.bin" )

                else:
                    log.error("Failed to zip files")
                    return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to zip files on server side. Pls restart server and IDA" })
        else:
            log.error("Generating trace failed.")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Generating trace failed."})

    # delete tmp. trace files
    if cmd_id == 8:
        log.info("Received API Command: Delete tmp. trace files.")
        try:
            #lastfiles = [ last_trace_filename, last_trace_filename_api, last_zipfilename ]     # old logic.TBD delete.
            
            #if delete_files(lastfiles):                                                        # old logic.TBD delete.
            last_trace_filenames.append(last_zipfilename)

            if delete_files(last_trace_filenames):
                log.info("Temp. trace files successfully deleted.")
                return JSONResponse(status_code=200, content={ "return_status" : "Successfully deleted temp. trace files."})
            else:
                log.warning("Deleting temp. files failed. This is normal if the last API trace run failed.")
                return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to deleted temp. trace file"})
        except:
            log.error("Failed to delete temp. files.")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to delete temp. dump buffer files."})

    # Download (dump) file
    if cmd_id == 9:  
        log.info("Received API Command: Download dump file.")
        try:
            dl_file = json_content['dl_file'][0]

            if dl_file:
                log.info("Downloading file: {}".format(dl_file)) 
                return FileResponse(dl_file, media_type='application/x-binary', filename=dl_file )
            else:
                log.warning("No file found to download.")
                return JSONResponse(status_code=201, content={ "return_status" : "Error: Download failed. No file found to download."})

        except Exception as ex:
            ddr_exception_handler_to_logger("'dl_file' field not found in JSON data.",ex)
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Download failed. 'dl_file' field not found in JSON data."})

    # Execute sample only
    if cmd_id == 10:
        log.info("Received API Command: Only execute sample.")
        result = write_dump_cfg(json_content, dynrio_cfg_file)
        if not result:
            log.error("Failed to generating the DDR config file")
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to generating the DDR config file"})

        dyn_full_cmd = build_dynRio_full_run_cmd_dump(dynrio_sample=sample_file_with_path, arch_bits=arch_bits, cfgfile=dynrio_cfg_file, cmd_opts=None)

        if dyn_full_cmd:
            runstatus = runcmd(dyn_full_cmd)
            if runstatus['status'] == 'success':
                log.info("Successfully executed sample.")
                return {"return_status" : "Successfully executed sample."}
            else:
                log.info("Failed to execute sample file.")
                return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to execute sample file."})

    # Patch sample with endless loop on disk (w/o DynRio)
    if cmd_id == 11:
        log.info("Received API Command: Patch sample with endless loop.")
        offset_disk = json_content['other']['offset_disk']
        loop_addr   = json_content['other']['loop_addr']

        sample_file_with_path = samplesdir + sample_file
        patchfilename = samplesdir + os.path.splitext(sample_file)[0] + "_patched" + os.path.splitext(sample_file)[1]
        with open(sample_file_with_path, 'rb') as samplefd, \
                        open(patchfilename, 'wb') as patchedfd:

            patched_data = bytearray(samplefd.read())

            # jmp loop
            org_bytes = ":".join("{:02x}".format(x) for x in patched_data[offset_disk:offset_disk+2])
            log.info("Patching binary with endless loop at offset {}.".format(offset_disk))
            log.info("Org. bytes: {} (replace the loop bytes (eb fe) in your debugger with these values).".format(org_bytes))
            log.info("e.g. x64dbg: memset <addr>,{:02x},1; memset <addr>+1,{:02x},1".format(patched_data[offset_disk], patched_data[offset_disk+1]))

            patched_data[offset_disk]   = 0xeb      # jmp -2
            patched_data[offset_disk+1] = 0xfe

            patchedfd.write(patched_data)

        log.info("Wrote patched file to {}".format(patchfilename))
        return { "return_status" : "Successfully created patched sample: {} (on server)".format(patchfilename)}

    # Create x64dbg script (script loads the sample and sets all patch parameters.) 
    if cmd_id == 12:
        log.info("Received API Command: Create x64dbg script.")
        try:
            global x64dbg_script
            global nop_x64_script
            global patch_eflag_init
            global patch_eflag_main
            global patch_calls
            global patch_calls_x64
            global exit_x64dbg_script
            breakaddr     = json_content['other']['breakaddr']
            org_imagebase = json_content['other']['imagebase']
            sample_file_with_path  = samplesdir + sample_file
            x64dbg_script_filename = samplesdir + os.path.splitext(sample_file)[0] + "_x64dbg_script.txt"   

            log.info("Setting breakpoint at : {}".format(breakaddr))
            log.info("Org. imagebase        : {}".format(org_imagebase))

            x64dbg_script_tmp = x64dbg_script.replace('<BREAK_ADDR>', breakaddr)
            x64dbg_script_tmp = x64dbg_script_tmp.replace('<ORG_IMAGE_BASE>', org_imagebase)
            x64dbg_script_tmp = x64dbg_script_tmp.replace('<SAMPLE_NAME>', sample_file_with_path)
            
            # NOP'out set ?
            try:
                nop_start = json_content['nop_start_addr']
                nop_end   = json_content['nop_end_addr']
            except:
                nop_start = False
                pass

            if (nop_start):
                for num in nop_start:
                    log.info("NOP'ing start address: {}".format(nop_start[num]))
                    log.info("NOP'ing end address  : {}".format(nop_end[num]))

                    nop_x64_script_tmp  = nop_x64_script.replace    ('<NOP_ORG_ADDR>', nop_start[num])
                    nop_x64_script_tmp  = nop_x64_script_tmp.replace('<NOP_SIZE_DEC>', str(int(nop_end[num],16)-int(nop_start[num],16)))
                    x64dbg_script_tmp  += nop_x64_script_tmp

            # Toggle EFLAGS ?
            try:
                eflag_addr = json_content['eflag_addr']
                eflag_str  = json_content['eflag_name']
            except:
                eflag_addr = False
                pass

            if (eflag_addr):
                x64dbg_script_tmp += patch_eflag_init
                for num in eflag_addr:
                    log.info("Toggle EFLAG {} at address: {}".format(eflag_str[num], eflag_addr[num]))    
                    patch_eflag_main_tmp = patch_eflag_main.replace    ('<PATCH_AT_ADDR>', eflag_addr[num]) 
                    patch_eflag_main_tmp = patch_eflag_main_tmp.replace('<EFLAG_STR>', eflag_str[num])
                    x64dbg_script_tmp += patch_eflag_main_tmp

            # patch calls
            try:
                call_addr = json_content['call_addr']
                call_ret  = json_content['call_ret']
            except:
                call_addr = False
                pass

            if (call_addr):
                
                for num in call_addr:
                    log.info("Skipping call at address: {}".format(call_addr[num]))
                    log.info("Setting return value to : {}".format(call_ret[num]))
                    log.info("Arch bits               : {:d}".format(arch_bits))
                    if arch_bits == 32:
                        patch_calls_tmp    = patch_calls.replace('<PATCH_FUNC_ADDR>', call_addr[num])
                        # convert ret value to little endian
                        call_ret_bin       = bytearray(struct.pack("I", int(call_ret[num],16)))
                        patch_calls_tmp    = patch_calls_tmp.replace('<PATCH_FUNC_RET1>', "{:x}".format(call_ret_bin[0])) 
                        patch_calls_tmp    = patch_calls_tmp.replace('<PATCH_FUNC_RET2>', "{:x}".format(call_ret_bin[1])) 
                        patch_calls_tmp    = patch_calls_tmp.replace('<PATCH_FUNC_RET3>', "{:x}".format(call_ret_bin[2])) 
                        patch_calls_tmp    = patch_calls_tmp.replace('<PATCH_FUNC_RET4>', "{:x}".format(call_ret_bin[3])) 
                        x64dbg_script_tmp += patch_calls_tmp
                    elif arch_bits == 64:
                        patch_calls_x64_tmp    = patch_calls_x64.replace('<PATCH_FUNC_ADDR>', call_addr[num])
                        # convert ret value to little endian
                        call_ret_bin           = bytearray(struct.pack("Q", int(call_ret[num],16)))
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET1>', "{:x}".format(call_ret_bin[0])) 
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET2>', "{:x}".format(call_ret_bin[1])) 
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET3>', "{:x}".format(call_ret_bin[2])) 
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET4>', "{:x}".format(call_ret_bin[3]))
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET5>', "{:x}".format(call_ret_bin[4])) 
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET6>', "{:x}".format(call_ret_bin[5])) 
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET7>', "{:x}".format(call_ret_bin[6])) 
                        patch_calls_x64_tmp    = patch_calls_x64_tmp.replace('<PATCH_FUNC_RET8>', "{:x}".format(call_ret_bin[7]))  
                        x64dbg_script_tmp     += patch_calls_x64_tmp
                    else:
                        log.error("Call patching failed. Unkown architecture.")

            # write footer to x64dbg script
            x64dbg_script_tmp += exit_x64dbg_script
            with open(x64dbg_script_filename, 'w') as scriptfd:
                scriptfd.write(x64dbg_script_tmp)

            log.info("Script file written to {}".format(x64dbg_script_filename))
            return { "return_status" : "Successfully built x64dbg script: {} (on server)".format(x64dbg_script_filename)}
        except Exception as ex:
            ddr_exception_handler_to_logger("Exception while generating DDR config file.",ex)
            return JSONResponse(status_code=201, content={ "return_status" : "Error: Failed to built x64dbg script: {} (on server)".format(x64dbg_script_filename)})


    # unkown cmd_id
    log.error("Unkown error. Likely unknown command id sent. This should not happen.")
    return JSONResponse(status_code=201, content={ "return_status" : "Unkown error: Likely unknown id sent. This should not happen."})

def kill_proc_tree(pid, procname, include_parent=True,
                   timeout=None, on_terminate=None):

    assert str(pid) != os.getpid(), "I won't kill myself"

    process_dict = { str(pid) : procname }
    parent = psutil.Process(pid)
    
    children = parent.children(recursive=True)
    if include_parent:
        children.append(parent)

    for p in children:
        process_dict[str(p.pid)] = p.exe()
        p.kill()

    gone, alive = psutil.wait_procs(children, timeout=timeout,
                                    callback=on_terminate)

    return (gone, alive, process_dict)


def kill_proctree_if_running(procname, pid):
    pid = int(pid)
    log.info("Trying to kill: {} ({})".format(procname, str(pid)))
    try:
        process = psutil.Process(pid)
    except:
        log.info("Process already killed: {} ({})".format(procname, str(pid)))
        return False

    process_name = process.name()
    if process_name == procname:
        try:
            gone, alive, process_dict = kill_proc_tree(pid, procname, timeout=3)
            for p in gone:
                log.info("Process killed: {} ({})".format(p.pid, process_dict[str(p.pid)]))
            for p in alive:
                log.warning("Process still alive: {} ({})".format(p.pid, process_dict[str(p.pid)]))
                return False
        except Exception as ex:
            ddr_exception_handler_to_logger("Exception while trying to kill processes which were still running after analysis.",ex)
            return False

        return True
    else:
        log.info("Process already killed, PID {} has a different filename now: {}".format(str(pid), process_name))
    
    return False
    

def get_all_tracefiles(trace_filename_stub):
    proc_filename = samplesdir + DDR_PROCESS_TRACE_FILE
    trace_flist = [proc_filename]

    with open(proc_filename) as f:          # get list of processes from DDR process file
        lines = f.readlines()

    for line in lines:
        procname = line.split("[")[0]       # get name only e.g. "sample.exe [2536]"
        procname = procname[:-1]            # remove space after name
        procnum  = line.split("[")[1]       # get processes pid
        procnum  = procnum.split("]")[0]    # remove last bracket

        kill_proctree_if_running(procname,procnum) # If there are still processes running, kill them and their children

        procname = samplesdir + DDR_THREAD_NAME_STUB + procname + "_" + procnum + ".txt"
        trace_flist.append(procname)
        

    search = trace_filename_stub + "*.json"
    for fname in glob.glob(search):
        trace_flist.append(fname)
    
    return(trace_flist)

def get_hash(filename):
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
    return {"md5_sum"   :md5.hexdigest().upper(),
            "sha1_sum"  :sha1.hexdigest().upper(), 
            "sha256_sum":sha256.hexdigest().upper()}

def get_hash_from_str(s):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256() 
    md5.update(s.encode())
    sha1.update(s.encode())
    sha256.update(s.encode())
    return {"md5_sum"   :md5.hexdigest().upper(),
            "sha1_sum"  :sha1.hexdigest().upper(), 
            "sha256_sum":sha256.hexdigest().upper()}


def write_cfg_line(line, cfgfile):
    """
    Santity check(s) for config line
    """
    if len(line) <= MAX_CFG_LINE_LENGTH:
        cfgfile.write(line)
        log.debug("Writing line to config: {}".format(line[:-1]))
        return True
    else:
        log.error("Config Line: {}".format(line[:-1]))
        log.error("Not written to config file {}.".format(cfgfile.name))
        log.error("Line is too long. Max. {:d} characters are allowed".format(MAX_CFG_LINE_LENGTH)) 
        return False

def write_dump_cfg(json_cfg, cfgfilename):
    """
    write JSON data to config file
    """
    ret = {}

    log.info("Writing configuration to {}".format(cfgfilename))

    try:
        with open(cfgfilename, "w") as cfgfile:
            try:
                nop_start_addr = json_cfg['nop_start_addr']
                nop_end_addr   = json_cfg['nop_end_addr']
                for num in nop_start_addr:
                    line = "N {} {}\n".format(nop_start_addr[num],nop_end_addr[num])
                    if not write_cfg_line(line, cfgfile): 
                        return False
            except:
                pass

            try:
                eflag_name = json_cfg['eflag_name']
                eflag_addr   = json_cfg['eflag_addr']
                for num in eflag_name:
                    line = "T {} {}\n".format(eflag_name[num],eflag_addr[num])
                    if not write_cfg_line(line, cfgfile): 
                        return False
            except:
                pass

            try:
                call_addr = json_cfg['call_addr']
                call_ret   = json_cfg['call_ret']
                for num in call_addr:
                    line = "C {} {}\n".format(call_addr[num],call_ret[num])
                    if not write_cfg_line(line, cfgfile): 
                        return False
            except:
                pass

            trace_set = False
            try:
                trace_start    = json_cfg['trace_start']
                trace_end      = json_cfg['trace_end']
                trace_light    = json_cfg['trace_light']
                if trace_start and trace_end and trace_light:
                    trace_set      = True
            except:
                log.info("No trace parameter found.")
                pass

            dump_buf_set = False
            try:
                buf_size_addr = json_cfg['buf_size_addr']
                buf_size_op   = json_cfg['buf_size_op']
                buf_addr_addr = json_cfg['buf_addr_addr']
                buf_addr_op   = json_cfg['buf_addr_op']
                buf_dump_addr = json_cfg['buf_dump_addr']             

                if buf_size_addr and buf_size_op and buf_addr_addr and buf_addr_op and buf_dump_addr:
                    dump_buf_set  = True
            except:
                log.info("No dump buffer parameter found.")
                pass

            run_only = False
            try:
                if json_cfg['run_opt'] == "RUN_ONLY":
                    run_only = True
            except:
                pass

            if trace_set:
                log.info("Parsing trace configuration")
                hash_list = []
                hash_list.append(json.dumps(trace_start))
                hash_list.append(json.dumps(trace_end))
                hash_list.append(json.dumps(trace_light))
                hash_str = "".join(hash_list)
                #log.debug("Hash_list: {}".format(hash_str))
                trace_filename = samplesdir + "trace_tmp_" + get_hash_from_str(hash_str)["md5_sum"] + ".json"
                #log.debug("Using trace filename: {}".format(trace_filename))
                for num in trace_start:
                    try:
                        trace_max_instr_num = json_cfg['trace_max_instr'][num]
                    except:
                        trace_max_instr_num = "na"

                    try:
                        trace_breakaddress_num = json_cfg['trace_breakaddress'][num]
                    except:
                        trace_breakaddress_num = "na"

                    line = "L {} {} {} {} {} \"{}\"\n".format(trace_start[num],trace_end[num],trace_max_instr_num,trace_breakaddress_num,trace_light[num],trace_filename)
                    log.debug("Config line built: {}".format(line[:-1]))
                    if not write_cfg_line(line, cfgfile): 
                        return False
                ret.update({ "status" : True, "trace_filename" : trace_filename})

            if dump_buf_set:
                log.info("Parsing dump buffer configuration")
                for num in buf_size_addr:
                    dump_filename = samplesdir + "dump{}_tmp.bin".format(num)
                    line = "D {} {} {} {} {} \"{}\"\n".format(buf_size_addr[num], buf_size_op[num], buf_addr_addr[num], buf_addr_op[num], buf_dump_addr[num], dump_filename)
                    log.info("writing line to cfg:\n{}".format(line[:-1]))
                    if not write_cfg_line(line, cfgfile): 
                        return False
                    ret.update({ "status" : True, "dump_filename" : dump_filename}) 

            if run_only:
                log.info("Run sample only configuration found.")
                ret.update({ "status" : True })

    except Exception as ex:
        ddr_exception_handler_to_logger("Exception while generating DDR config file.",ex)
        ret = False
            
    return ret

def delete_target_file(targetfile):
    """ 
    Delete target file
    """

    if not os.path.isfile(targetfile):
        log.error("Parameter is not a file")
        return False

    log.debug("Trying to delete file: {}".format(targetfile))

    try:
        os.remove(targetfile)
    except:
        log.error("File: {} not deleted.".format(targetfile))
        return False

    log.debug("File: {} deleted.".format(targetfile))
    return True

def delete_files(files2del_list):
    """
    Delete list of files
    """
    try:
        for fns in files2del_list:
            if not delete_target_file(fns):
                return False
        return True
    except:
        return False


def zip_files(filelist, zipfilename):
    """ 
    Create ZIP file archive
    """
    with zipfile.ZipFile(zipfilename, "w") as newzip:
        for filename in filelist:
            newzip.write(filename, os.path.basename(filename))

    return True


def check_self_signed_cert():
    """
    check for self signed certificate and key if they do not exists
    """
    if not os.path.exists(cert_file) or not os.path.exists(cert_key):
        print("")
        print("[DDRSERVER][ERROR] -------------------------------------------------------")
        print("[DDRSERVER][ERROR] Self signed certificate and/or secret key not found.")
        print("[DDRSERVER][ERROR] Please use the install script to generate them.")
        print("[DDRSERVER][ERROR] -------------------------------------------------------\n")
    else:
        print("")
        print("[DDRSERVER][INFO] --------------------------------------------------------------------------------")
        print("[DDRSERVER][INFO] Existing certificate and key file found.")
        print("[DDRSERVER][INFO] Using Certificate file : '{}'".format(cert_file))
        print("[DDRSERVER][INFO] and key file           : '{}'".format(cert_key))
        print("[DDRSERVER][INFO] --------------------------------------------------------------------------------\n")

def get_apikey():
    """ 
    Read or generate API key
    """
    apikey_file = CONFDIR + APIKEY_FILE

    try:    
        with open(apikey_file, 'r') as myfile:
            key=myfile.read().replace('\n', '')
        print("[DDRSERVER][INFO] --------------------------------------------------------------------------------")
        print("[DDRSERVER][INFO] API Key file found.")
        print("[DDRSERVER][INFO] Using API key file: {}".format(apikey_file))
        print("[DDRSERVER][INFO] --------------------------------------------------------------------------------\n")

    except:
        print("[DDRSERVER][ERROR] ----------------------------------------------------------")
        print("[DDRSERVER][ERROR] API key file not found.")
        print("[DDRSERVER][ERROR] Please use install script to generate an API Key file ")
        print("[DDRSERVER][ERROR] ----------------------------------------------------------\n")
        return False

    return key

def runcmd(my_cmd):
    """ 
    Execute shell command
    """

    log.info("Executing DDR client with cmd:\n\n{}".format( " ".join(my_cmd)))

    start_time = time.time()

    stdout = False
    stderr = False

    cmd_ret = { 'status' : False, 'stdout' : None, 'stderr' : None}
    cmd_ret['status'] = 'success'

    try:
        process = subprocess.Popen(" ".join(my_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            log.warning("Command execution failed. Error code: {:d}".format(process.returncode))

        if stderr:
            log.warning("Command execution failed. Stderr:\n----\n{}\n----".format(stderr))

        if stdout:
            log.info("Command executed. Stdout was:\n---- Start Stdout ----\n{}\n---- End Stdout ----".format(stdout.decode("utf-8")))
            cmd_ret['stdout'] =  stdout
        
    except :
        log.error("Exception: Command execution failed with unknown error")
        cmd_ret['status'] = 'failed - unknown error/exception'
    
    end_time = time.time()
    log.info("Analysis run for {:f} seconds".format(end_time - start_time))

    return cmd_ret

def build_dynRio_full_run_cmd_trace(start_addr=None, end_addr=None, break_addr=None, instr_count=None, jsonfile_name=None, dynrio_sample=None, arch_bits=None, cmd_opts=None):
    """ 
    Build shell cmd line for DynamoRIO drrun.exe -c DDR.dll ...
    """
    if start_addr == None or end_addr == None or instr_count == None or jsonfile_name==None or arch_bits==None:
        log.error("jsonfile_name, start_addr, end_addr, arch_bits or instr_count not set")
        return False

    if arch_bits == 32:
        dynrio_client_x32        = CFG_DYNRIO_CLIENTDLL_X32
        dynrio_cmd_x32           = [CFG_DYNRIO_DRRUN_X32]
        dynrio_cmd_x32.append("-c")
        dynrio_cmd_x32.append("\"" + dynrio_client_x32 + "\"")
        dynrio_cmd_x32.append("-s")
        dynrio_cmd_x32.append("0x{:x}".format(start_addr))
        dynrio_cmd_x32.append("-e")
        dynrio_cmd_x32.append("0x{:x}".format(end_addr))
        dynrio_cmd_x32.append("-c {:d}".format(instr_count))
        dynrio_cmd_x32.append("-f")
        dynrio_cmd_x32.append("\"" + jsonfile_name + "\"")
        if cmd_opts: 
            dynrio_cmd_x32.append(cmd_opts)
        dynrio_cmd_x32.append("--")
        dynrio_cmd_x32.append("\"" + dynrio_sample + "\"")
        return dynrio_cmd_x32

    elif arch_bits == 64:
        dynrio_client_x64        = CFG_DYNRIO_CLIENTDLL_X64
        dynrio_cmd_x64           = [CFG_DYNRIO_DRRUN_X64]
        dynrio_cmd_x64.append("-c")
        dynrio_cmd_x64.append("\"" + dynrio_client_x64 + "\"")
        dynrio_cmd_x64.append("-s")
        dynrio_cmd_x64.append("0x{:x}".format(start_addr))
        dynrio_cmd_x64.append("-e")
        dynrio_cmd_x64.append("0x{:x}".format(end_addr))
        dynrio_cmd_x64.append("-c {:d}".format(instr_count))
        dynrio_cmd_x64.append("-f")
        dynrio_cmd_x64.append("\"" + jsonfile_name + "\"")
        if cmd_opts:
            dynrio_cmd_x64.append(cmd_opts)
        dynrio_cmd_x64.append("--")
        dynrio_cmd_x64.append("\"" + dynrio_sample + "\"")
        return dynrio_cmd_x64

def build_dynRio_full_run_cmd_dump(dynrio_sample=None, arch_bits=None, cfgfile=None, cmd_opts=None):
    """ 
    Build shell cmd line for DynamoRIO drrun.exe -c DDR.dll ...
    """
    if cfgfile == None or arch_bits==None or dynrio_sample == None:
        log.error("cfgfile, arch_bits or dynrio_sample not set")
        return False

    if arch_bits == 32:
        dynrio_client_x32        = CFG_DYNRIO_CLIENTDLL_X32
        dynrio_cmd_x32           = [CFG_DYNRIO_DRRUN_X32]
        dynrio_cmd_x32.append("-c")
        dynrio_cmd_x32.append("\"{}\"".format(dynrio_client_x32))
        dynrio_cmd_x32.append("-c")
        dynrio_cmd_x32.append("\"{}\"".format(cfgfile))
        if cmd_opts: 
            dynrio_cmd_x32.append(cmd_opts)
        dynrio_cmd_x32.append("--")
        dynrio_cmd_x32.append("\"{}\"".format(dynrio_sample))
        return dynrio_cmd_x32

    elif arch_bits == 64:
        dynrio_client_x64        = CFG_DYNRIO_CLIENTDLL_X64
        dynrio_cmd_x64           = [CFG_DYNRIO_DRRUN_X64]
        dynrio_cmd_x64.append("-c")
        dynrio_cmd_x64.append("\"{}\"".format(dynrio_client_x64))
        dynrio_cmd_x64.append("-c")
        dynrio_cmd_x64.append("\"{}\"".format(cfgfile))
        if cmd_opts:
            dynrio_cmd_x64.append(cmd_opts)
        dynrio_cmd_x64.append("--")
        dynrio_cmd_x64.append("\"" + dynrio_sample + "\"")
        return dynrio_cmd_x64

def check_config_files_exist(files, dirs):
    """ 
    Verify if the files and dirs configured in the config exist
    """
    ret = True
    
    for dir in dirs:
        if not os.path.isdir(dir):
            log.error("Directory: {} not found.".format(dir))
            ret = False

    for fname in files:
        if not os.path.isfile(fname):
            log.error("File: {} not found.".format(fname))
            ret = False

    return ret


def allowed_file(filename, allowed_ext):
    """ 
    Function to check if the submitted file has one of the
    allowed extentions (allowed_ext) 
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_ext


if __name__ == "__main__":

    if not sys.version_info >= (3, 0):
        print("[DDRSERVER][ERROR] This script only runs in Python 3. Please install Python 3 first")
        exit(1)

    msg =  "Remember if you mark any text in the console window, "
    msg += "Windows will pause the Python app in this console window. "
    msg += "In other words, our DDR server will be paused until you hit ESCAPE. "
    msg += "If you ever mark text, e.g. DDR output, never forget to hit "
    msg += "ESCAPE before proceeding to work with DDR. "
    msg += "If you forget to do that, you will likely run into timeout errors "
    msg += "when the DDR IDA plugin tries to access the DDR server."

    ctypes.windll.user32.MessageBoxW(0, msg, "DDR - !!! READ THIS !!!" , 0)

    print("\n[DDRSERVER][INFO] --------------------------------------------------------------------------------")
    print("[DDRSERVER][INFO] Starting DDR server version {}".format(DDR_SERVER_VERSION)) 
    print("[DDRSERVER][INFO] --------------------------------------------------------------------------------")
    print("[DDRSERVER][INFO] Python version is:")
    print("[DDRSERVER][INFO] {}".format(sys.version))
    print("[DDRSERVER][INFO] --------------------------------------------------------------------------------")

    # check for config errors
    if not check_config_files_exist([CFG_DYNRIO_DRRUN_X32,CFG_DYNRIO_CLIENTDLL_X32,CFG_DYNRIO_DRRUN_X64,CFG_DYNRIO_CLIENTDLL_X64], [CONFDIR]):
        exit(1)

    # Create self signed certificate for TLS communication 
    check_self_signed_cert()

    # Get API key
    webkey = get_apikey()

    if not webkey:
        exit(1)

    global DDR_WEBAPI_KEY 
    DDR_WEBAPI_KEY = webkey

    uvicorn.run(
        app,
        host=SERVER_IP,
        port=int(SERVER_PORT),
        #ssl_version=ssl.PROTOCOL_TLSv1_2,   # or PROTOCOL_TLS for TLS and SSL
        ssl_cert_reqs=ssl.CERT_OPTIONAL,     # https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLS
        ssl_keyfile=cert_key,        
        ssl_certfile=cert_file,
        log_level='error' 
    )

        


