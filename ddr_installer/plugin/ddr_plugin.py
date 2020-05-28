#-------------------------------------------------------------------------------
#
#   IDA Pro Plug-in: Dynamic Data Resolver (DDR) Front End
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
#   Requests    (http://docs.python-requests.org)       
#   PEfile      (https://github.com/erocarrera/pefile)
#
#   e.g.:
#   python -m pip install --upgrade pip                     
#   pip install -U Requests   
#   pip install -U pefile
#
#   Hint: *Make sure you install these requirements for the same Python version IDA is using. 
# 
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

import sys            
import idaapi
import ida_kernwin
import ida_nalt
import ida_ua
import idautils
import idc
import logging
import tempfile
import os
import glob
import errno
import json
import subprocess    
import zipfile
import hashlib
import time
import traceback
from datetime import datetime
from pprint import pprint
from collections import Counter, OrderedDict

# IDA version below 7.5 and Python equal or higher than 3.8 doesn't work
if idaapi.IDA_SDK_VERSION < 750 and sys.version_info >= (3, 8):
    print("[DDR][ERROR] Python version > 3.7 found. Problematic Python modules not loaded.")
    print("[DDR][ERROR] Python 3.8+ and DDR only works in IDA 7.5 and above.")
else:
    # these modules crash IDA if Python version > 3.7 is installed.
    from PyQt5 import QtCore, QtGui, QtWidgets
    import requests
    import pefile
        
# Setup Logging to file in %TEMP% --- Not used itm ---
# tmpdir = tempfile.gettempdir()
# ddr_logdir    = tmpdir + '\DDR'

# try:
#     os.makedirs(ddr_logdir, exist_ok=True)    # Python >3.2
# except TypeError:
#     try:
#         os.makedirs(ddr_logdir)               # Python >2.5
#     except OSError as e:
#         if e.errno == errno.EEXIST and os.path.isdir(ddr_logdir):
#             pass
#         else:
#             idaapi.warning("[DDR] Failed to make logging directory")

# ddr_logfilename = ddr_logdir + '\DDR-{:%Y-%m-%d-%H-%M-%S}.log'.format(datetime.now())
# logger = logging.getLogger("DDR")
# logger.setLevel(logging.DEBUG)
# fh = logging.FileHandler(ddr_logfilename)
# fh.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# fh.setFormatter(formatter)
# logger.addHandler(fh)

# Globals
# -------
DDR_PLUGIN_VERSION = "1.0 beta"
# Global DDR plugin configuration file
DDR_CFG_FILE = idaapi.idadir("plugins\\ddr\\ddr_config.json") 

# Colors used for highlighting the building blocks. If you want to change this, change the assignment to COLOR1-5 below.                                                     
GREEN                   = [0xa0ffa0, 0x70ff70, 0x00ff00, 0x00ef00, 0x00df00, 0x00cf00, 0x00bf00, 0x00af00]      
YELLOW                  = [0xd0ffff, 0xa0ffff, 0x70ffff, 0x00ffff, 0x00efff, 0x00dfff, 0x00cfff, 0x00bfff]      
RED                     = [0xC0C0ff, 0xB0B0ff, 0xA0A0ff, 0x8080ff, 0x6060ff, 0x4040ff, 0x2020ff, 0x0000ff]      
LIGHT_PURPLE            = 0xFF60FF                                                                              
PURPLE                  = 0xFF00FF                                                                                  
                                             # Number of times instruction executed                                                                                                                     
COLOR1                  = GREEN              # 0x0     - 0xF                             list [] of 8 colors
COLOR2                  = YELLOW             # 0x10    - 0xff                            list [] of 8 colors
COLOR3                  = RED                # 0x100   - 0xfff                           list [] of 8 colors
COLOR4                  = LIGHT_PURPLE       # 0x1000  - 0xffff                          color value
COLOR5                  = PURPLE             # 0x10000 - infinity                        color value
                 
EFLAGS                  = [ "CF", "PF", "AF", "ZF", "SF", "DF", "OF" ]

SAMPLE_FILENAME         = None
SAMPLE_SHA256           = None
SAMPLE_DIR              = None

JSONDATA                = None
JSONFILE_LOADED         = False
APIFILE_LOADED          = False
        
API_CALLS               = {}              
REG_LIST                = []

# Setup menu/action items: 
menu_items = OrderedDict([
("DDR_Action_Load_file"                   , { "menu_str":"Load DDR trace file"                              , "hotkey":"Ctrl+Shift+F11", "submenu":""              , "ah_id":"LoadFile"                   , "x64only":False, "hide_in_context":True }),
("DDR_Action_Load_api_file"               , { "menu_str":"Load DDR trace API file"                          , "hotkey":"Ctrl+Shift+F12", "submenu":""              , "ah_id":"LoadAPIFile"                , "x64only":False, "hide_in_context":True }),
("DDR_Action_Add_BB2List"                 , { "menu_str":"Add basic block to basic block list"              , "hotkey":"Ctrl+Shift+A"  , "submenu":"Select/"       , "ah_id":"Select_Add_BB2List"         , "x64only":False, "hide_in_context":False}),
("DDR_Action_Remove_BB2List"              , { "menu_str":"Remove basic block from basic block list"         , "hotkey":"Ctrl+Shift+D"  , "submenu":"Select/"       , "ah_id":"Select_Remove_BB2List"      , "x64only":False, "hide_in_context":False}),
("DDR_Action_Print_BB2List"               , { "menu_str":"Show basic block list"                            , "hotkey":None            , "submenu":"Select/"       , "ah_id":"Select_Print_BB2List"       , "x64only":False, "hide_in_context":False}),
("DDR_Action_Clear_BB2List"               , { "menu_str":"Clear basic block list"                           , "hotkey":None            , "submenu":"Select/"       , "ah_id":"Select_Clear_BB2List"       , "x64only":False, "hide_in_context":False}),
("DDR_Action_Trace_On_Range"              , { "menu_str":"Run full trace for marked address range"          , "hotkey":None            , "submenu":"Trace/"        , "ah_id":"Run_Trace_On_Range"         , "x64only":False, "hide_in_context":False}),
("DDR_Action_Run_Trace_On_BB"             , { "menu_str":"Run full trace for marked basic block"            , "hotkey":None            , "submenu":"Trace/"        , "ah_id":"Run_Trace_On_BB"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Run_Trace_On_BBList"         , { "menu_str":"Run full trace for basic block list"              , "hotkey":None            , "submenu":"Trace/"        , "ah_id":"Run_Trace_On_BB_list"       , "x64only":False, "hide_in_context":False}),
("DDR_Action_Run_Trace_On_Seg"            , { "menu_str":"Run full trace for segment"                       , "hotkey":None            , "submenu":"Trace/"        , "ah_id":"Run_Trace_On_Seg"           , "x64only":False, "hide_in_context":False}),
("DDR_Action_Run_Light_Trace_On_Seg"      , { "menu_str":"Run light trace for segment"                      , "hotkey":None            , "submenu":"Trace/"        , "ah_id":"Run_Light_Trace_On_Seg"     , "x64only":False, "hide_in_context":False}),
#("DDR_Action_Delete_Cached_Files"         , { "menu_str":"Delete cached traces"                             , "hotkey":None            , "submenu":"Trace/"        , "ah_id":"Delete_Cached_Files"        , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_size"            , { "menu_str":"Use marked operand to get buffer size"            , "hotkey":None            , "submenu":"Dump/"         , "ah_id":"Dump_buffer_size_op"        , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_addr"            , { "menu_str":"Use marked operand to get buffer address"         , "hotkey":None            , "submenu":"Dump/"         , "ah_id":"Dump_buffer_addr_op"        , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_dump"            , { "menu_str":"Use marked address to dump buffer to file"        , "hotkey":None            , "submenu":"Dump/"         , "ah_id":"Dump_buffer_dump_addr"      , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer"                 , { "menu_str":"Execute sample and dump buffer"                   , "hotkey":None            , "submenu":"Dump/"         , "ah_id":"Dump_buffer"                , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_nop"             , { "menu_str":"NOP out marked instruction at runtime"            , "hotkey":None            , "submenu":"Patch/"        , "ah_id":"Dump_buffer_nop_instr"      , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_eflag"           , { "menu_str":"Toggle EFLAG at runtime"                          , "hotkey":None            , "submenu":"Patch/"        , "ah_id":"Dump_buffer_eflag_instr"    , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_call"            , { "menu_str":"Skip function at marked address at runtime"       , "hotkey":None            , "submenu":"Patch/"        , "ah_id":"Dump_buffer_skip_call"      , "x64only":False, "hide_in_context":False}),
("DDR_Action_sample_run_only"             , { "menu_str":"Run patched sample"                               , "hotkey":None            , "submenu":"Patch/"        , "ah_id":"Sample_run_only"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_sample_to_x64dbg"            , { "menu_str":"Create x64dbg script with bp at marked address"   , "hotkey":None            , "submenu":"Debugger/"     , "ah_id":"Sample_to_x64dbg"           , "x64only":False, "hide_in_context":False}),
("DDR_Action_sample_loop_addr"            , { "menu_str":"Create executable with loop at marked address"    , "hotkey":None            , "submenu":"Debugger/"     , "ah_id":"Sample_loop_addr"           , "x64only":False, "hide_in_context":False}),
("DDR_Action_Set_Num_Hits_for_Cmt"        , { "menu_str":"Set number of trace hits for IDA DISASM View"     , "hotkey":None            , "submenu":"Config/"       , "ah_id":"Get_Set_Num_Hits_Cmt"       , "x64only":False, "hide_in_context":False}),
("DDR_Action_Set_Num_Hits_for_IdaLog"     , { "menu_str":"Set number of trace hits for IDA log window"      , "hotkey":None            , "submenu":"Config/"       , "ah_id":"Get_Set_Num_Hits_IdaLog"    , "x64only":False, "hide_in_context":False}),
("DDR_Action_Set_Num_Max_Instr"           , { "menu_str":"Set number of instructions to log at runtime"     , "hotkey":None            , "submenu":"Config/"       , "ah_id":"Get_Set_Max_Instr"          , "x64only":False, "hide_in_context":False}),
("DDR_Action_Set_Num_API_timeout"         , { "menu_str":"Set number of seconds for API timeout"            , "hotkey":None            , "submenu":"Config/"       , "ah_id":"Get_Set_API_timeout"        , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_edit_cfg"        , { "menu_str":"Edit DDR request (Experts only)"                   , "hotkey":None            , "submenu":"Config/"       , "ah_id":"Dump_buffer_edit_cfg"       , "x64only":False, "hide_in_context":False}),
("DDR_Action_Dump_buffer_clear_cfg"       , { "menu_str":"Clear configured DDR request"                     , "hotkey":None            , "submenu":"Config/"       , "ah_id":"Dump_buffer_clear_cfg"      , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xax"             , { "menu_str":"Get memory for ptr in xax"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xax"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xbx"             , { "menu_str":"Get memory for ptr in xbx"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xbx"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xcx"             , { "menu_str":"Get memory for ptr in xcx"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xcx"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xdx"             , { "menu_str":"Get memory for ptr in xdx"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xdx"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xsp"             , { "menu_str":"Get memory for ptr in xsp"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xsp"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xbp"             , { "menu_str":"Get memory for ptr in xbp"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xbp"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xsi"             , { "menu_str":"Get memory for ptr in xsi"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xsi"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_xdi"             , { "menu_str":"Get memory for ptr in xdi"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_xdi"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r8"              , { "menu_str":"Get memory for ptr in r8"                         , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r8"             , "x64only":True , "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r9"              , { "menu_str":"Get memory for ptr in r9"                         , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r9"             , "x64only":True , "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r10"             , { "menu_str":"Get memory for ptr in r10"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r10"            , "x64only":True , "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r11"             , { "menu_str":"Get memory for ptr in r11"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r11"            , "x64only":True , "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r12"             , { "menu_str":"Get memory for ptr in r12"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r12"            , "x64only":True , "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r13"             , { "menu_str":"Get memory for ptr in r13"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r13"            , "x64only":True , "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r14"             , { "menu_str":"Get memory for ptr in r14"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r14"            , "x64only":True , "hide_in_context":False}),
("DDR_Action_Get_Mem_Ptr_r15"             , { "menu_str":"Get memory for ptr in r15"                        , "hotkey":None            , "submenu":"Get Register/" , "ah_id":"Get_Mem_Ptr_r15"            , "x64only":True , "hide_in_context":False}),
("DDR_Action_GetSrcOpValue"               , { "menu_str":"Get values for source operand"                    , "hotkey":None            , "submenu":""              , "ah_id":"GetSrcOpValue"              , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetDstOpValue"               , { "menu_str":"Get values for destination operand"               , "hotkey":None            , "submenu":""              , "ah_id":"GetDstOpValue"              , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetSrcOpPtrValue"            , { "menu_str":"Get values for ptr in source operand"             , "hotkey":None            , "submenu":""              , "ah_id":"GetSrcOpPtrValue"           , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetDstOpPtrValue"            , { "menu_str":"Get values for ptr in destination operand"        , "hotkey":None            , "submenu":""              , "ah_id":"GetDstOpPtrValue"           , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetSrcOpPtrPtrValue"         , { "menu_str":"Get values for ptr ptr in source operand"         , "hotkey":None            , "submenu":""              , "ah_id":"GetSrcOpPtrPtrValue"        , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetDstOpPtrPtrValue"         , { "menu_str":"Get values for ptr ptr in destination operand"    , "hotkey":None            , "submenu":""              , "ah_id":"GetDstOpPtrPtrValue"        , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetSrcPtrMem"                , { "menu_str":"Get memory for ptr in source operand"             , "hotkey":None            , "submenu":""              , "ah_id":"GetSrcPtrMem"               , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetDstPtrMem"                , { "menu_str":"Get memory for ptr in destination operand"        , "hotkey":None            , "submenu":""              , "ah_id":"GetDstPtrMem"               , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetSrcPtrPtrMem"             , { "menu_str":"Get memory for ptr ptr in source operand"         , "hotkey":None            , "submenu":""              , "ah_id":"GetSrcPtrPtrMem"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_GetDstPtrPtrMem"             , { "menu_str":"Get memory for ptr ptr in destination operand"    , "hotkey":None            , "submenu":""              , "ah_id":"GetDstPtrPtrMem"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Highlight_trace"             , { "menu_str":"Highlight traced instructions"                    , "hotkey":None            , "submenu":""              , "ah_id":"Highlight_trace"            , "x64only":False, "hide_in_context":False}),
("DDR_Action_Clear_Highlight_trace"       , { "menu_str":"Clear highlighted instructions"                   , "hotkey":None            , "submenu":""              , "ah_id":"Clear_highlighted_blocks"     , "x64only":False, "hide_in_context":False}),
("DDR_Action_Strings_View"                , { "menu_str":"Show strings trace"                               , "hotkey":None            , "submenu":""              , "ah_id":"Display_Strings_View"       , "x64only":False, "hide_in_context":False}),
("DDR_Action_Call_View"                   , { "menu_str":"Show API calls trace"                             , "hotkey":None            , "submenu":""              , "ah_id":"Display_Calls_View"         , "x64only":False, "hide_in_context":False}),
("DDR_Action_DeleteNonRepeatableComments" , { "menu_str":"Delete non-repeatable comments"                   , "hotkey":None            , "submenu":""              , "ah_id":"DeleteNonRepeatableComments", "x64only":False, "hide_in_context":False})
])

def PLUGIN_ENTRY():
    """ Set plugin entry class """
    return ddrPlugin()

def ddr_exception_handler1(msg, ex):
    """ DDR exception handler. Handle exceptions without killing the plugin """
    print("================================================= Exception ===========================================================")
    print(msg)
    print("-----------------------------------------------------------------------------------------------------------------------")
    ex_type, ex_value, ex_traceback = sys.exc_info()
    trace_back = traceback.extract_tb(ex_traceback)
    stack_trace = []
    for trace in trace_back:
        stack_trace.append("[DDR][ERROR] File: {}, Func.Name: {}, Line: {:d} \n[DDR][ERROR] Issue : {}".format(trace[0], trace[2], trace[1], trace[3]))
    print("[DDR][ERROR] Exception type : {} ".format(ex_type.__name__))
    print("[DDR][ERROR] Exception message : {}".format(ex_value))
    for msg in stack_trace:
        print("[DDR][ERROR] Stack trace : \n{}".format(msg))
    print("=======================================================================================================================")

class ddr_plugin_cfg():
    """ Class storing the global DDR configuration """  

    def __init__(self, ddr_cfg_file_json):
        self.reload(ddr_cfg_file_json)

    def reload(self, ddr_cfg_file_json):
        try:
            # IP address of host ddr_server.py is running on
            keyword = "WEBSERVER"
            self.WEBSERVER               = ddr_cfg_file_json[keyword]
            print("[DDR][INFO] Configured DDR server is      : {}".format(self.WEBSERVER))
            # Port DDRserver.py is using 
            keyword = "WEBSERVER_PORT"
            self.WEBSERVER_PORT          = ddr_cfg_file_json[keyword]
            print("[DDR][INFO] Configured DDR server port is : {}".format(self.WEBSERVER_PORT))
            # API key, check ddr_server.py start messages, generated by the ddr_server.py script at first startup
            keyword = "DDR_WEBAPI_KEY"
            self.DDR_WEBAPI_KEY          = ddr_cfg_file_json[keyword]
            # CA certificate
            keyword = "CA_CERT"
            self.CA_CERT                 = ddr_cfg_file_json[keyword]
            # Verify certificates
            keyword = "VERIFY_CERT"
            self.VERIFY_CERT             = ddr_cfg_file_json[keyword]
            # Config filename for dump buffer function. This file will be written into the sample directory
            keyword = "DUMP_CFG_FILE"
            self.DUMP_CFG_FILE           = ddr_cfg_file_json[keyword]
            # Max. timeout the ddr_server.py has for answering in seconds, before we kill the request.
            # Don't set this too low, it should be long enough to run the DynamoRio client analysis.
            keyword = "MAX_API_TIMEOUT"
            self.MAX_API_TIMEOUT         = ddr_cfg_file_json[keyword]
            # Debug Level, the higher the more is printed to the IDA log window. See DDR_print_mesg() for details.
            keyword = "DBG_LEVEL"
            self.DBG_LEVEL               = ddr_cfg_file_json[keyword]
            # Default max. number of instructions to execute before Dynamorio stops logging.  
            keyword = "MAX_INSTR_TO_EXECUTE"
            self.MAX_INSTR_TO_EXECUTE    = ddr_cfg_file_json[keyword]
            # Default max. number of found instruction values added to the IDA log window (max. 50, see below). 
            keyword = "MAX_LOG_ROUNDS"
            self.MAX_LOG_ROUNDS          = ddr_cfg_file_json[keyword]
            # Default max. number of found instruction values added to the IDA DISASM view as comments (max. 50, see below).
            keyword = "MAX_CMT_ROUNDS"
            self.MAX_CMT_ROUNDS          = ddr_cfg_file_json[keyword]
            # Max. number of instruction addresses wich will be added to the trace_instr_num_list list.  
            # This list holds all the occurences of instruction numbers which match the ea address.    
            # This is the max value for the MAX_LOG_ROUNDS and MAX_CMT_ROUNDS variables.       
            keyword = "MAX_INSTR_COUNT"
            self.MAX_INSTR_COUNT         = ddr_cfg_file_json[keyword]
            # Max. number of attempts to copy the sample file over to the DDR server
            keyword = "MAX_UPLOAD_ATTEMPTS"
            self.MAX_UPLOAD_ATTEMPTS     = ddr_cfg_file_json[keyword]
            # Sample architecture
            self.ARCH_BITS               = None
            # Config is successful initalized
            self.is_initalized = "PHASE1"
            print("[DDR][INFO] Configuration successfully parsed.")
        except:
            print("[DDR][ERROR] Failed to initalize {} settings.".format(keyword))
            self.is_initalized = False

# Load global DDR configuration
try:
    print("[DDR][INFO] Initalizing DDR plugin version {}.".format(DDR_PLUGIN_VERSION))
    with open(DDR_CFG_FILE) as json_file:
        ddr_cfg_file_json = json.load(json_file)
        print("[DDR][INFO] Configuration loaded from {}".format(DDR_CFG_FILE))
        DDR_CONFIG_SETTINGS = ddr_plugin_cfg(ddr_cfg_file_json)
except:
    if DDR_CFG_FILE: 
        print("[DDR][ERROR] Failed loading DDR configuration file: {}".format(DDR_CFG_FILE))
        raise
    else:
        print("[DDR][ERROR] Failed loading DDR configuration file.")
        raise


def DDR_print_mesg(msg, debuglevel=0, printout=False):
    """ Print msg to output window in IDA """
    func = "not implemented"

    if printout:
        if debuglevel == 0 and DDR_CONFIG_SETTINGS.DBG_LEVEL == 8:
            print("[DDR][INFO] {}".format(msg))
        if debuglevel == 1 and DDR_CONFIG_SETTINGS.DBG_LEVEL == 9:
            print("[DDR][WARNING] {}".format(msg))
        if debuglevel == 2 and DDR_CONFIG_SETTINGS.DBG_LEVEL == 10:
            print("[DDR][ERROR] {}".format(msg))
        return

    if debuglevel == 0 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 0:
        print("[DDR][INFO] {}".format(msg))
    if debuglevel == 1 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 1:
        print("[DDR][WARNING] {}".format(msg))
    if debuglevel == 2 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 2:
        print("[DDR][ERROR] {}".format(msg))
    if debuglevel == 3 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 3:                           
        print("[DDR][DEBUG_L1][{}] {}".format(func, msg))
    if debuglevel == 4 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 4:
        print("[DDR][DEBUG_L2][{}] {}".format(func, msg))
    if debuglevel == 5 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 5:
        print("[DDR][DEBUG_L3][{}] {}".format(func, msg))
    if debuglevel == 6 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 6:
        print("[DDR][DEBUG_L4][{}] {}".format(func, msg))  
    if debuglevel == 7 and DDR_CONFIG_SETTINGS.DBG_LEVEL >= 7:
        print("[DDR][DEBUG_L5][{}] {}".format(func, msg))

def DDR_upload_sample(filename):
    """ Upload sample to DDR server """
    url = "https://" + DDR_CONFIG_SETTINGS.WEBSERVER + ":" + DDR_CONFIG_SETTINGS.WEBSERVER_PORT + "/" +  "uploadsample"
    files = {'file': open(filename, 'rb')}
    postpara = { 'apikey' : DDR_CONFIG_SETTINGS.DDR_WEBAPI_KEY, 'id' : '0' }

    DDR_print_mesg("Uploading file: {} ...".format(filename))

    if DDR_CONFIG_SETTINGS.VERIFY_CERT:
        res = requests.post(url, verify=DDR_CONFIG_SETTINGS.CA_CERT, files=files, data=postpara, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT)
    else:
        res = requests.post(url, verify=False, files=files, data=postpara, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT) 
    
    DDR_print_mesg("File upload status: {}".format(res.json()["return_status"]))

    if res.status_code == 200:
        return True
    else:
        return False

def get_hash(filename):
    """ Calculate MD5,SHA1,SHA256 hash for given file """
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


class basicblock_obj(object):
    """ Basic Block class """
    num         = 0
    start_addr  = 0
    end_addr    = 0

    def __init__(self, start_addr, end_addr):
        self.start      = start_addr
        self.end        = end_addr

    def __eq__(self, other):
        if self.start == other.start and self.end == other.end:
            return True
        else:
            return False

class basicblock_list(object):
    """ Global basic block list class """
    blocks      = []
    count       = 0

    def __init__(self):
        pass

    def __iter__(self):
        for bb in self.blocks:
            yield bb

    def add(self, start_addr, end_addr):
        new_bb = basicblock_obj(start_addr, end_addr)
        for bb in self.blocks:
            if bb.start == new_bb.start:
                DDR_print_mesg("Basicblock already in list. Not added.",1)
                return
        self.count += 1
        DDR_print_mesg("Basicblock added to list.")
        self.blocks.append(new_bb)

    def remove(self, start_addr, end_addr):
        new_bb = basicblock_obj(start_addr, end_addr)
        for bb in self.blocks:
           if bb.start == new_bb.start:
              self.blocks.remove(bb)
              self.count -= 1
              DDR_print_mesg("Basicblock removed from list.")
              return
        DDR_print_mesg("Basicblock not found in list.",1)

    def show(self):
        DDR_print_mesg("Basicblocks list({:d} entries):".format(self.count))
        for b in self.blocks:
            DDR_print_mesg("{:x} - {:x}".format(b.start, b.end))
        return True

    def clear(self, dont_ask=False):
        if dont_ask:
            self.blocks = []
            self.count = 0
            DDR_print_mesg("Basicblock list cleared.")
            return True
        else:
            ok = ida_kernwin.ask_yn(0,"Do you really want to clear the basicblocks list ?")
            if ok == 1:
                self.blocks = []
                self.count = 0
                DDR_print_mesg("Basicblock list cleared.")
                return True
            else:
                DDR_print_mesg("Clearing basicblock list canceled.")
                return False


    def get_bblist_from_json(self, jsoncfg):
        tmpcfg = json.loads(jsoncfg)
        for n in tmpcfg["trace_start"]:
            DDR_print_mesg("n={}  trace_start={}    trace_end={}".format(n, tmpcfg["trace_start"][n],tmpcfg["trace_end"][n]),8)
            self.add(int(tmpcfg["trace_start"][n],16), int(tmpcfg["trace_end"][n],16))

BB_LIST = basicblock_list()


class ddr_api_v1_cfg(object):
    """ JSON API configuration """
    def __init__(self, BB_LIST=None): 
        self.cfg = { "apikey"                : DDR_CONFIG_SETTINGS.DDR_WEBAPI_KEY,
                     "id"                    : None,
                     "arch_bits"             : None,
                     "sample_file"           : SAMPLE_FILENAME,
                     "sample_sha256"         : SAMPLE_SHA256,
                     "buf_size_addr"         : {},
                     "buf_size_op"           : {},
                     "buf_addr_addr"         : {},
                     "buf_addr_op"           : {},
                     "buf_dump_addr"         : {},
                     "nop_start_addr"        : {},
                     "nop_end_addr"          : {},
                     "eflag_name"            : {},
                     "eflag_addr"            : {},
                     "call_addr"             : {},
                     "call_ret"              : {},
                     "trace_light"           : {},
                     "trace_start"           : {},
                     "trace_end"             : {},
                     "trace_max_instr"       : {},
                     "trace_breakaddress"    : {},
                     "filelist2del"          : [],
                     "dl_file"               : [],
                     "run_opt"               : None,
                     "other"                 : {}
                    }

        self.clear_cfg()

    def set_cfg_para(self, para, value1=None, value2=None, value3=None, value4=None, value5=None):
        
        if para.upper().startswith("0X"):
            para = para[2:]
        try:
            if value1.upper().startswith("0X"):
                value1 = value1[2:]
        except:
            pass 

        try:
            if value2.upper().startswith("0X"):
                value2 = value2[2:]
        except:
            pass

        try:
            if value3.upper().startswith("0X"):
                value3 = value3[2:]
        except:
            pass

        try:
            if value4.upper().startswith("0X"):
                value4 = value4[2:]
        except:
            pass

        try:
            if value5.upper().startswith("0X"):
                value5 = value5[2:]
        except:
            pass

        if para == "dumpbuffer":
            if value1:
                self.cfg["buf_size_addr"].update({"{}".format(self.counter_bufdump) : "{}".format(value1.upper())})
            if value2:
                self.cfg["buf_size_op"].update({"{}".format(self.counter_bufdump) : "{}".format(value2.upper())})
            if value3:
                self.cfg["buf_addr_addr"].update({"{}".format(self.counter_bufdump) : "{}".format(value3.upper())})
            if value4:
                self.cfg["buf_addr_op"].update({"{}".format(self.counter_bufdump) : "{}".format(value4.upper())})
            if value5:
                self.cfg["buf_dump_addr"].update({"{}".format(self.counter_bufdump) : "{}".format(value5.upper())})
            self.set_buffer_counter()

        elif para == "trace":
            self.cfg["trace_start"].update({"{}".format(self.counter_traces) : "{}".format(value1.upper())})
            self.cfg["trace_end"].update({"{}".format(self.counter_traces) : "{}".format(value2.upper())})
            if value3:
                self.cfg["trace_max_instr"].update({"{}".format(self.counter_traces) : "{}".format(value3.upper())})
            if value4:
                self.cfg["trace_breakaddress"].update({"{}".format(self.counter_traces) : "{}".format(value4.upper())})
            if value5:
                self.cfg["trace_light"].update({"{}".format(self.counter_traces) : "{}".format(value5.upper())})
            else:
                self.cfg["trace_light"].update({"{}".format(self.counter_traces) : "{}".format("FALSE")})
            self.set_traces_counter()

        elif para == "nops":
            self.cfg["nop_start_addr"].update({"{}".format(self.counter_nops) : "{}".format(value1.upper())})
            self.cfg["nop_end_addr"].update({"{}".format(self.counter_nops) : "{}".format(value2.upper())})
            self.counter_nops += 1

        elif para == "eflags":
            self.cfg["eflag_name"].update({"{}".format(self.counter_eflags) : "{}".format(value1)})
            self.cfg["eflag_addr"].update({"{}".format(self.counter_eflags) : "{}".format(value2.upper())})
            self.counter_eflags += 1

        elif para == "calls":
            self.cfg["call_addr"].update({"{}".format(self.counter_calls) : "{}".format(value1.upper())})
            self.cfg["call_ret"].update({"{}".format(self.counter_calls) : "{}".format(value2.upper())})
            self.counter_calls += 1

        else:
            DDR_print_mesg("Unknown error setting a config value.")
            return

    def set_buffer_counter(self):
        try:
            # all values set ?
            n = str(self.counter_bufdump)
            if not self.cfg["buf_size_addr"][n] or not \
                   self.cfg["buf_size_op"][n]   or not \
                   self.cfg["buf_addr_addr"][n] or not \
                   self.cfg["buf_addr_op"][n]   or not \
                   self.cfg["buf_dump_addr"][n]:
                return
        except:
            return

        self.counter_bufdump = len(self.cfg["buf_size_addr"]) 
        if self.cfg_all_buf_set():
            DDR_print_mesg("All mandatory buffer parameters set. Number of buffers to dump: {:d}".format(self.counter_bufdump))

    def set_traces_counter(self):
        try:
            # all mandatory values set ?
            n = str(self.counter_traces)
            if not self.cfg["trace_start"][n] or not \
                   self.cfg["trace_end"][n]:
                return
        except:
            return

        self.counter_traces = len(self.cfg["trace_start"]) 
        if self.cfg_all_trace_set():
            DDR_print_mesg("All mandatory trace parameters found. Number of traces: {:d}".format(self.counter_traces))

    def clear_cfg_para(self, para):
        if para == "dumpbuffer":
            self.cfg["buf_size_addr"] = {}
            self.cfg["buf_size_op"]   = {}
            self.cfg["buf_addr_addr"] = {}
            self.cfg["buf_addr_op"]   = {}
            self.cfg["buf_dump_addr"] = {}
            self.counter_bufdump = 0
        elif para == "trace":
            self.cfg["trace_start"]        = {}
            self.cfg["trace_end"]          = {}
            self.cfg["trace_max_instr"]    = {}
            self.cfg["trace_breakaddress"] = {}
            self.cfg["trace_light"]        = {}
            self.counter_traces = 0
        elif para == "nops":
            self.cfg["nop_start_addr"] = {}
            self.cfg["nop_end_addr"]   = {}
            self.counter_nops = 0
        elif para == "eflags":
            self.cfg["eflag_name"] = {}
            self.cfg["eflag_addr"] = {}
            self.counter_eflags = 0
        elif para == "calls":
            self.cfg["call_addr"] = {}
            self.cfg["call_ret"]  = {}
            self.counter_calls = 0
        else:
            DDR_print_mesg("Something went wrong clearing the config setting. This should not happen",2)
            return

    def cfg_all_trace_set(self, printout=False):
        
        # check start and end address
        for n in range(0, self.counter_traces):
           
            # check if any madatory values are hex, if not exception
            try:
                int(self.cfg["trace_start"][str(n)], 16)  
            except:
                DDR_print_mesg("'trace_start' value is not a hex value.",10, printout=True)
            try:
                int(self.cfg["trace_end"][str(n)], 16) 
            except:
                DDR_print_mesg("'trace_end' value is not a hex value.",10, printout=True)
           
        # is max instr set ?
        if self.cfg["trace_max_instr"]:
            # check if max instr is a number
            for n in range(0, self.counter_traces):
                if not all(c in "0123456789" for c in self.cfg["trace_max_instr"][str(n)]):
                    DDR_print_mesg("'trace_max_instr' value error. Should be something similar to SP0 or DP0",10, printout=True)
                    return False

        # is break addr set ?
        if self.cfg["trace_breakaddress"]:
            for n in range(0, self.counter_traces+1):
                # check if values are hex, if not exception
                try:
                    int(self.cfg["trace_breakaddress"][str(n)], 16)
                except:
                    DDR_print_mesg("'trace_breakaddress' value is not a hex value.", 10, printout=True)

        # is light trace set ? 
        if self.cfg["trace_light"]:
            # if not "TRUE" or "FALSE" aka {} empty
            for n in range(0, self.counter_traces):
                if not self.cfg["trace_light"][str(n)] == "TRUE" and \
                   not self.cfg["trace_light"][str(n)] == "FALSE":
                    DDR_print_mesg("'trace_light' value error. Should be 'TRUE' or 'FALSE' string", 10, printout=True)
                    return False
    
        return True

    def cfg_all_buf_set(self, printout=False):
                    
        for n in range(0, self.counter_bufdump):
            # check if values are hex
            try:
                int(self.cfg["buf_size_addr"][str(n)], 16) 
            except:
                DDR_print_mesg("'buf_size_addr' value is not a hex value.",10, printout=True)
                return False

            if not all(c in "SDP012345" for c in self.cfg["buf_size_op"][str(n)]):
                DDR_print_mesg("'buf_size_op' value error. Should be something similar to SP0 or DP0", 10, printout=True)
                return False

            try:
                int(self.cfg["buf_addr_addr"][str(n)], 16) 
            except:
                DDR_print_mesg("'buf_addr_addr' value is not a hex value.",10, printout=True)
                return False

            if not all(c in "SDP012345" for c in self.cfg["buf_addr_op"][str(n)]):
                DDR_print_mesg("'buf_addr_op' value error. Should be something similar to SP0 or DP0", 10, printout=True)
                return False

            try:
                int(self.cfg["buf_dump_addr"][str(n)], 16) 
            except:
                DDR_print_mesg("'buf_dump_addr' value is not a hex value.", 10, printout=True)
                return False
        
        return True
       
    def cfg_all_nop_set(self, printout=False):
        if not self.cfg["nop_start_addr"] or not self.cfg["nop_end_addr"]:
            return False
        for key in self.cfg["nop_start_addr"]:
            if not self.cfg["nop_start_addr"][key]:
                return False
        for key in self.cfg["nop_end_addr"]:
            if not self.cfg["nop_end_addr"][key]:
                return False
        return True

    def cfg_all_eflag_set(self, printout=False):
        if not self.cfg["eflag_name"] or not self.cfg["eflag_addr"]:
            return False
        for key in self.cfg["eflag_name"]:
            if not self.cfg["eflag_addr"][key]:
                return False
        for key in self.cfg["eflag_name"]:
            if not self.cfg["eflag_addr"][key]:
                return False
        return True

    def cfg_all_call_set(self, printout=False):
        if not self.cfg["call_addr"] or not self.cfg["call_ret"]:
            return False
        for key in self.cfg["call_addr"]:
            if not self.cfg["call_ret"][key]:
                return False
        for key in self.cfg["call_addr"]:
            if not self.cfg["call_ret"][key]:
                return False
        return True

    def cfg_is_empty(self):
        if not self.cfg["buf_size_addr"]    and not \
           self.cfg["buf_size_op"]          and not \
           self.cfg["buf_addr_addr"]        and not \
           self.cfg["buf_addr_op"]          and not \
           self.cfg["buf_dump_addr"]        and not \
           self.cfg["trace_start"]          and not \
           self.cfg["trace_end"]            and not \
           self.cfg["trace_max_instr"]      and not \
           self.cfg["trace_breakaddress"]   and not \
           self.cfg["trace_light"]          and not \
           self.cfg["nop_start_addr"]       and not \
           self.cfg["nop_end_addr"]         and not \
           self.cfg["eflag_name"]           and not \
           self.cfg["eflag_addr"]           and not \
           self.cfg["call_addr"]            and not \
           self.cfg["call_ret"]:
           return True
        return False

    def cfg_bufdump_not_set(self):
        if not self.cfg["buf_size_addr"]    and not \
           self.cfg["buf_size_op"]          and not \
           self.cfg["buf_addr_addr"]        and not \
           self.cfg["buf_addr_op"]          and not \
           self.cfg["buf_dump_addr"]:
           return True
        return False

    def cfg_trace_not_set(self):
        if not self.cfg["trace_end"]        and not \
           self.cfg["trace_max_instr"]      and not \
           self.cfg["trace_breakaddress"]:
           return True
        return False

    def cfg_verified(self, printout=False, empty_cfg_not_accepted=True):   
        ret = True
        # is cfg empty:
        if self.cfg_is_empty() and empty_cfg_not_accepted:
            DDR_print_mesg("Configuration is empty.", 2)
            return False

        # if any dump buffer value is set, check dump buffer config
        if self.cfg["buf_size_addr"] or \
           self.cfg["buf_size_op"]   or \
           self.cfg["buf_addr_addr"] or \
           self.cfg["buf_addr_op"]   or \
           self.cfg["buf_dump_addr"]:
           ret = self.cfg_all_buf_set(printout)
        # if any trace value is set, check trace config
        if self.cfg["trace_start"]          or \
           self.cfg["trace_end"]            or \
           self.cfg["trace_max_instr"]      or \
           self.cfg["trace_breakaddress"]   or \
           self.cfg["trace_light"]:
           ret = self.cfg_all_trace_set(printout)
        # if any NOP value is set, check NOP config
        if self.cfg["nop_start_addr"] or \
           self.cfg["nop_end_addr"]:
           ret = self.cfg_all_nop_set(printout)
        # if any EFLAG value is set, check EFLAG config
        if self.cfg["eflag_name"]     or \
           self.cfg["eflag_addr"]:
           ret = self.cfg_all_eflag_set(printout)
        # if any CALL value is set, check CALL config
        if self.cfg["call_addr"]      or \
           self.cfg["call_ret"]:
           ret = self.cfg_all_call_set(printout)

        return ret

    def get_missing_cfg_values(self, values):
        
        missing_values = []
        if "buf_dump" in values:
            missing_values = [k for k in ['buf_size_addr', 'buf_size_op', 'buf_addr_addr', 'buf_addr_op','buf_dump_addr'] if self.cfg[k] == {}]  
        if "trace" in values:
            missing_values += [k for k in ['trace_start', 'trace_end'] if self.cfg[k] == {}] 
        if "nop" in values:
            missing_values += [k for k in ['nop_start_addr', 'nop_end_addr'] if self.cfg[k] == {}] 
        if "eflag" in values:
            missing_values += [k for k in ['eflag_name', 'eflag_addr'] if self.cfg[k] == {}] 
        if "call" in values:
            missing_values += [k for k in ['call_addr', 'call_ret'] if self.cfg[k] == {}] 
          
        return missing_values 

    def get_missing_cfg_values_msg(self, values):
        msg = {'buf_size_addr' : "Buffer size PC address",
               'buf_size_op'   : "Buffer size operand",
               'buf_addr_addr' : "Buffer address PC address",
               'buf_addr_op'   : "Buffer address operand",
               'buf_dump_addr' : "Buffer dump PC address",
               'nop_start_addr': "NOP PC start address",
               'nop_end_addr'  : "NOP PC end address",
               'eflag_name'    : "EFLAG name",
               'eflag_addr'    : "EFLAG PC address",
               'call_addr'     : "Call PC address",
               'call_ret'      : "Call return value", 
               'trace_start'   : "Trace start",
               'trace_end'     : "Trace end",
               'trace_light'   : "Trace light switch" }

        missing_values = self.get_missing_cfg_values(values)

        missing_values_msg = []
        for x in missing_values:
            missing_values_msg.append("{}{}{}{}".format(msg[x],"(",x,")"))

        return missing_values_msg

    def get_cfg_json_str_formatted(self): 
        cfg_json = json.dumps(self.cfg,indent=4, sort_keys=True)
        return cfg_json

    def print_cfg(self):
        DDR_print_mesg("{}".format(self.get_cfg_json_str_formatted()))

    def edit_cfg(self):

        for block in BB_LIST:
            DDR_print_mesg("block [0x{:x} - 0x{:x}]".format(block.start, block.end))
            self.set_cfg_para("trace", hex(block.start), hex(block.end), str(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE)) 

        old_cfg = self.get_cfg_json_str_formatted()

        DDR_print_mesg("Config length: {:d}".format(len(old_cfg)),7)

        new_cfg = ida_kernwin.ask_text(5000, old_cfg, "Edit configuration (Expert only - Use at own risk)")

        if not new_cfg:
            DDR_print_mesg("User canceled edit configuration dialog. Nothing changed",2)
            return

        try:
            self.cfg = json.loads(new_cfg)

            try:
                BB_LIST.clear(dont_ask=True)
                BB_LIST.get_bblist_from_json(new_cfg)
            except:
                raise

            try:
                self.counter_bufdump = len(self.cfg["buf_size_addr"]) 
                DDR_print_mesg("counter_bufdump: {:d}".format(self.counter_bufdump),8)
            except:
                self.counter_bufdump = 0
                DDR_print_mesg("Except: counter_bufdump: {:d}".format(self.counter_bufdump),8)

            try:
                self.counter_nops    = len(self.cfg["nop_start_addr"]) 
                DDR_print_mesg("counter_nops: {:d}".format(self.counter_nops))
            except:
                self.counter_nops    = 0
                DDR_print_mesg("Except: counter_nops: {:d}".format(self.counter_nops),8)

            try:
                self.counter_eflags  = len(self.cfg["eflag_name"]) 
                DDR_print_mesg("counter_eflags: {:d}".format(self.counter_eflags),8)
            except:
                self.counter_eflags  = 0
                DDR_print_mesg("Except:counter_eflags: {:d}".format(self.counter_eflags),8)

            try:
                self.counter_calls   = len(self.cfg["call_addr"]) 
                DDR_print_mesg("counter_calls: {:d}".format(self.counter_calls),8)
            except:
                self.counter_calls   = 0
                DDR_print_mesg("Except: counter_calls: {:d}".format(self.counter_calls),8)

            try:
                self.counter_traces  = len(self.cfg["trace_start"]) 
                DDR_print_mesg("counter_traces: {:d}".format(self.counter_traces),8)
            except:
                self.counter_traces  = 0
                DDR_print_mesg("Except: counter_traces: {:d}".format(self.counter_traces),8)

            if not self.cfg_verified(printout=True):
                self.cfg = json.loads(old_cfg)
                DDR_print_mesg("Config check failed. Old config restored.",2)
            else:
                DDR_print_mesg("Changed configuration:")
                self.print_cfg()

        except ValueError as e:
            DDR_print_mesg("Failed to parse JSON config",2)
            DDR_print_mesg("{}".format(e),2)

    def clear_cfg(self):
        self.cfg = { "apikey"             : DDR_CONFIG_SETTINGS.DDR_WEBAPI_KEY,
                     "id"                 : None,
                     "arch_bits"          : None,
                     "sample_file"        : SAMPLE_FILENAME,
                     "sample_sha256"      : SAMPLE_SHA256,
                     "buf_size_addr"      : {},
                     "buf_size_op"        : {},
                     "buf_addr_addr"      : {},
                     "buf_addr_op"        : {},
                     "buf_dump_addr"      : {},
                     "nop_start_addr"     : {},
                     "nop_end_addr"       : {},
                     "eflag_name"         : {},
                     "eflag_addr"         : {},
                     "call_addr"          : {},
                     "call_ret"           : {},
                     "trace_light"        : {},
                     "trace_start"        : {},
                     "trace_end"          : {},
                     "trace_max_instr"    : {},
                     "trace_breakaddress" : {},
                     "run_opt"            : None,
                     "other"              : {}
                    }  

        self.counter_nops    = 0
        self.counter_eflags  = 0
        self.counter_calls   = 0
        self.counter_traces  = 0
        self.counter_bufdump = 0

        BB_LIST.clear(dont_ask=True)

        info = idaapi.get_inf_structure()
        if info.is_64bit():
            self.cfg["arch_bits"] = 64
        elif info.is_32bit():
            self.cfg["arch_bits"] = 32

        DDR_print_mesg("Configuration cleared.")        

class DDR_ida_action_handler(idaapi.action_handler_t):
    """
    DDR Action handler for all menu entries, gets created when user picks menu 
    """

    def __init__(self, usrcmd):
        idaapi.action_handler_t.__init__(self)
        self.cmd = usrcmd
        DDR_print_mesg("cmd = {}".format(self.cmd), 7)

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        DDR_print_mesg("[{}] updated.".format(self.cmd), 7)
        return idaapi.AST_ENABLE_ALWAYS

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        DDR_print_mesg("Command selected by user: [{}]".format(self.cmd), 7)
        
        global JSONDATA
        global JSONFILE_LOADED
        global APIFILE_LOADED
        global BB_LIST
        global EFLAGS
      
        ea = idc.get_screen_ea()

        # Command handler
        if self.cmd == ("Select_Add_BB2List"):
            DDR_print_mesg("Adding basic block to basic blocks list",7)
            if self._Add_BB2BBlist(ea):
                DDR_print_mesg("Done. Basic block added to basic block list.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            else:
                DDR_print_mesg("Done. Failed to add basic block to basic block list.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            return 1

        if self.cmd == ("Select_Remove_BB2List"):
            DDR_print_mesg("Removing basic block to basic blocks list",7)
            if self._Remove_BB2BBlist(ea):
                DDR_print_mesg("Done. Basic block removed from basic block list.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            else:
                DDR_print_mesg("Done. Failed to remove basic block from basic block list.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            return 1

        if self.cmd == ("Select_Print_BB2List"):
            DDR_print_mesg("Show basic blocks list",7)
            if BB_LIST.show():
                DDR_print_mesg("Done. Basic block list printed.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            else:
                DDR_print_mesg("Done. Failed to print basic block list.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            return 1

        if self.cmd == ("Select_Clear_BB2List"):
            DDR_print_mesg("Show basic blocks list",7)
            if BB_LIST.clear():
                DDR_print_mesg("Done. Basic block list cleared.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            else:
                DDR_print_mesg("Done. Failed to clear basic block list.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
            return 1

        if self.cmd == ("Dump_buffer_size_op"):
            try:
                op_str = ida_kernwin.get_highlight(idaapi.get_current_viewer())[0]
            except:
                idaapi.warning("No operand highlighted. Please highlight the operand you want to use for finding the buffer size")
                DDR_print_mesg("No operand highlighted. Please highlight the operand you want to use for finding the buffer size",2)
                return 1

            dump_size_addr, dump_size_op = self._get_dump_para_addr_n_op(op_str, ea)
            if (dump_size_addr and dump_size_op):
                DDR_print_mesg("Using operand {} at PC address 0x{:x} to find size of buffer to dump".format(dump_size_op, dump_size_addr))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("dumpbuffer", value1=hex(dump_size_addr))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("dumpbuffer", value2=dump_size_op)
            return 1

        if self.cmd == ("Dump_buffer_addr_op"):
            try:
                op_str = ida_kernwin.get_highlight(idaapi.get_current_viewer())[0]
            except:
                idaapi.warning("No operand highlighted. Please highlight the operand you want to use for finding the buffer address")
                DDR_print_mesg("No operand highlighted. Please highlight the operand you want to use for finding the buffer address",2)
                return 1

            dump_addr_addr, dump_addr_op = self._get_dump_para_addr_n_op(op_str, ea)
            try:
                DDR_print_mesg("Using operand {} at PC address 0x{:x} to find memory address of buffer to dump".format(dump_addr_op, dump_addr_addr))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("dumpbuffer", value3=hex(dump_addr_addr))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("dumpbuffer", value4=dump_addr_op)
            except:
                DDR_print_mesg("No config parameters set.",2)
            return 1

        if self.cmd == ("Dump_buffer_dump_addr"):
            DDR_print_mesg("Using PC address 0x{:x} to finally dump the buffer to file".format(ea))
            DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("dumpbuffer", value5=hex(ea))
            return 1

        if self.cmd == ("Dump_buffer_edit_cfg"):
            DDR_print_mesg("Manually edit config",7)
            try:
                DDR_API_V1_CONFIG_SETTINGS.edit_cfg();
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace") # clean the trace cfg, to load BB_LIST at execution
            except:
                DDR_print_mesg("Edit configuration failed.",2)
                raise
            return 1

        if self.cmd == ("Dump_buffer_clear_cfg"):
            DDR_print_mesg("Clear config",7)
            try:
                ok = ida_kernwin.ask_yn(0,"Do you really want to clear the configuration ?")
                if ok == 1:
                    DDR_API_V1_CONFIG_SETTINGS.clear_cfg();
                else:
                    DDR_print_mesg("Clearing configuration canceled.")
            except:
                DDR_print_mesg("Clear configuration failed.",2)
                raise
            return 1

        if self.cmd == ("Dump_buffer"):
            DDR_print_mesg("Executing sample and trying to dump the buffer",7)
            # --------------------
            if not DDR_API_V1_CONFIG_SETTINGS.cfg_verified():
                idaapi.warning("Dump config verification failed. Please first set the buffer size, buffer address and dump address via the 'Dump' menu.")
                DDR_print_mesg("Dump configuration verification failed.",2)
                DDR_print_mesg("Missing mandatory values: {}".format(DDR_API_V1_CONFIG_SETTINGS.get_missing_cfg_values_msg("buf_dump")),2)
                DDR_print_mesg("Please first set the buffer size, buffer address and dump address via the 'Dump' menu.",2)
            else:
                # We can either dump a buffer or trace the file itm.
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace") # clear trace config, we have it still saved in the BB list

                DDR_print_mesg("Sending following config to server:")
                DDR_API_V1_CONFIG_SETTINGS.print_cfg()

                if not self._call_api(cmd_id=5, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Problem detected while dumping buffer. Check log above.",2)
                else:
                    DDR_print_mesg("Done. Buffer dumped to file.")
                    DDR_print_mesg("-------------------------------------------------------------------------------")
            return 1

        if self.cmd == ("Dump_buffer_nop_instr"):  
            try:
                start = idc.read_selection_start()
                end   = idc.prev_head(idc.read_selection_end())

                # User selected multiple lines
                if start != idc.BADADDR and end != idc.BADADDR:
                    DDR_print_mesg("NOP'ing out instructions from instruction 0x{:x} to 0x{:x}".format(start, end))
                    DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("nops", hex(start), hex(end))
                # User selected single line
                else: 
                    DDR_print_mesg("NOP'ing out instruction at 0x{:x}".format(ea))
                    DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("nops", hex(ea), hex(ea))
                return 1
            except:
                raise

        if self.cmd == ("Dump_buffer_eflag_instr"):  
            try:
                eflag_str = ida_kernwin.ask_text(2, "ZF", "Please enter EFLAG name:").upper()
            except:
                DDR_print_mesg("EFLAG dialog canceled.")
                return 1

            DDR_print_mesg("EFLAG: {} entered.".format(eflag_str))

            if not eflag_str in EFLAGS:
                DDR_print_mesg("EFLAG is not a valid EFLAG. Please use one from this list: {}".format(",".join(EFLAGS)))
                idaapi.warning("EFLAG is not a valid EFLAG. Please use one from this list: {}".format(",".join(EFLAGS)))
                return 1

            try:
                start = idc.read_selection_start()
                end   = idc.read_selection_end()

                # User selected multiple lines
                if start != idc.BADADDR and end != idc.BADADDR:
                    ea=start
                    while(ea < end):  
                         DDR_print_mesg("Toggle EFLAG {} at 0x{:x}".format(eflag_str, ea)) 
                         DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("eflags", eflag_str, hex(ea))         
                         ea = idc.next_head(ea)
                # User selected single line
                else: 
                    DDR_print_mesg("Toggle EFLAG {} at line 0x{:x}".format(eflag_str, ea))
                    DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("eflags", eflag_str, hex(ea)) 
                return 1
            except:
                raise

        if self.cmd == ("Dump_buffer_skip_call"):  

            if idaapi.get_inf_structure().is_64bit():
                max_size = 64 + 2
            else:
                max_size = 32 + 2

            try:
                start = idc.read_selection_start()
                end   = idc.read_selection_end()

                # User selected multiple lines
                if start != idc.BADADDR and end != idc.BADADDR:
                    idaapi.warning("Selecting a range for function skipping is not supported. Pls select a single line.")
                    DDR_print_mesg("Selecting a range for function skipping is not supported. Pls select a single line.",2)
                # User selected single line
                else: 
                    call_retval = ida_kernwin.ask_text(max_size, "D0D0", "Please enter return value (in hex) for skipped function:")
                    try:
                        if call_retval:
                            r = int(call_retval,16)
                        else:
                            DDR_print_mesg("Return value dialog canceled.")
                            return 1
                    except:
                        DDR_print_mesg("Return value is not a hex value. You need to enter a hex value. Skip function operation not executed.",1)
                        idaapi.warning("Return value is not a hex value. Skip function operation not executed.")
                        return 1

                    DDR_print_mesg("Skipping function at 0x{:x} at runtime. Return value set to: {}".format(ea, call_retval))
                    DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("calls", hex(ea), call_retval)
                return 1
            except:
                raise

        if self.cmd == ("Sample_to_x64dbg"):

            DDR_print_mesg("Creating x64dbg script.")

            DDR_API_V1_CONFIG_SETTINGS.cfg["other"].update({"breakaddr" : hex(ea)})
            DDR_API_V1_CONFIG_SETTINGS.cfg["other"].update({"imagebase" : hex(idaapi.get_imagebase())})  

            try:
                # Fixing nop_end_addr + 1 
                org_nop_end_addr = DDR_API_V1_CONFIG_SETTINGS.cfg["nop_end_addr"]['0']
                new_nop_end_addr = idc.next_head(int(org_nop_end_addr,16))
                DDR_API_V1_CONFIG_SETTINGS.cfg["nop_end_addr"]['0'] = hex(new_nop_end_addr)
            except:
                pass

            DDR_API_V1_CONFIG_SETTINGS.print_cfg()

            if not self._call_api(cmd_id=12, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Problem detected while patching sample. Check log above.",2)
            else:
                DDR_print_mesg("Done. x64dbg Script created.")
                DDR_print_mesg("-------------------------------------------------------------------------------")

            try:
                DDR_API_V1_CONFIG_SETTINGS.cfg["nop_end_addr"]['0'] = org_nop_end_addr
            except:
                pass

            return 1


        if self.cmd == ("Sample_loop_addr"):
            offset_on_disk = idaapi.get_fileregion_offset(ea)
            DDR_print_mesg("Create binary with and endless loop at: 0x{:x}".format(ea))
            DDR_print_mesg("Address offset on disk                : 0x{:x}".format(offset_on_disk))

            DDR_API_V1_CONFIG_SETTINGS.cfg["other"].update({"offset_disk" : offset_on_disk})
            DDR_API_V1_CONFIG_SETTINGS.cfg["other"].update({"loop_addr"   : ea})

            if not self._call_api(cmd_id=11, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Problem detected while patching sample with endless loop. Check log above.",2)
            else:
                DDR_print_mesg("Done. Binary with endless loop created.")
                DDR_print_mesg("-------------------------------------------------------------------------------")

            return 1

        if self.cmd == ("Sample_run_only"):

            if DDR_API_V1_CONFIG_SETTINGS.cfg_verified(empty_cfg_not_accepted=False):
                DDR_print_mesg("Executing sample on server in DynamoRio incl. all patches.")
                old_cfg = DDR_API_V1_CONFIG_SETTINGS.get_cfg_json_str_formatted()
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("dumpbuffer") 
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")
                DDR_API_V1_CONFIG_SETTINGS.cfg["run_opt"] = "RUN_ONLY"

                DDR_print_mesg("Sending following config to server:")
                DDR_API_V1_CONFIG_SETTINGS.print_cfg()

                if not self._call_api(cmd_id=10, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Problem detected while running sample on server. Check log above.",2)
                else:
                    DDR_print_mesg("Done. Sample executed.")
                    DDR_print_mesg("-------------------------------------------------------------------------------")

                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")
                DDR_API_V1_CONFIG_SETTINGS.cfg = json.loads(old_cfg)
                DDR_API_V1_CONFIG_SETTINGS.cfg["run_opt"] = None
            else:
                idaapi.warning("Config verification failed.")
                DDR_print_mesg("Config verification failed.",2)

            return 1

        if self.cmd == ("Delete_Cached_Files"):
            jsonfile_name =  JSONFILE_DIR + "\\" + "DDR_log_" + '.'.join(idaapi.get_root_filename().split('.')[:-1]) + "*"
            for filename_to_delete in glob.glob(jsonfile_name):
                DDR_print_mesg("Deleting file(s): {}".format(filename_to_delete))
                os.remove(filename_to_delete)
            return 1

        if self.cmd == ("Run_Light_Trace_On_Seg"):
            b_start        = idc.get_segm_start(ea)
            b_end          = idc.get_segm_end(ea)

            if b_start != idc.BADADDR and b_end != idc.BADADDR:
                old_cfg = DDR_API_V1_CONFIG_SETTINGS.get_cfg_json_str_formatted()
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("dumpbuffer") 
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")

                DDR_print_mesg("Running trace on segment: [0x{:x} - 0x{:x}]".format(b_start, b_end))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("trace", hex(b_start), hex(b_end), str(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE), value5="TRUE")


                DDR_print_mesg("Sending following config to server:")
                DDR_API_V1_CONFIG_SETTINGS.print_cfg()

                if not self._call_api(cmd_id=7, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Failed to run light trace for segment",2)
                    idaapi.warning("Failed to run light trace for segment.")
                else:
                    DDR_print_mesg("Done. Light trace on segment executed.")
                    DDR_print_mesg("-------------------------------------------------------------------------------")

                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")
                DDR_API_V1_CONFIG_SETTINGS.cfg = json.loads(old_cfg)

            else:
                DDR_print_mesg("Failed finding segment.")
           
            # old: DDR_print_mesg("Running instruction address trace only for selected segment range: {:x} - {:x}.".format(start, end))
            # old: self._exec_dynRio(start_addr=start, end_addr=end, instr_count=DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE, options='light_trace_only')
            return 1

        if self.cmd == ("Run_Trace_On_Seg"):
            b_start        = idc.get_segm_start(ea)
            b_end          = idc.get_segm_end(ea)
            
            if b_start != idc.BADADDR and b_end != idc.BADADDR:
                old_cfg = DDR_API_V1_CONFIG_SETTINGS.get_cfg_json_str_formatted()
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("dumpbuffer") 
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")

                DDR_print_mesg("Running trace on segment: [0x{:x} - 0x{:x}]".format(b_start, b_end))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("trace", hex(b_start), hex(b_end), str(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE))

                DDR_print_mesg("Sending following config to server:")
                DDR_API_V1_CONFIG_SETTINGS.print_cfg()

                if not self._call_api(cmd_id=7, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Failed to run full trace for segment",2)
                    idaapi.warning("Failed to run full trace for segment.")
                else:
                    DDR_print_mesg("Done. Full trace on segment executed.")
                    DDR_print_mesg("-------------------------------------------------------------------------------")

                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")
                DDR_API_V1_CONFIG_SETTINGS.cfg = json.loads(old_cfg)

            else:
                DDR_print_mesg("Failed finding segment.")

            return 1

        if self.cmd == ("Run_Trace_On_Range"):
            b_start = idc.read_selection_start()
            b_end   = idc.prev_head(idc.read_selection_end())

            if b_start != idc.BADADDR and b_end != idc.BADADDR:

                old_cfg = DDR_API_V1_CONFIG_SETTINGS.get_cfg_json_str_formatted()
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("dumpbuffer") 
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")

                DDR_print_mesg("Running trace on address range: [0x{:x} - 0x{:x}]".format(b_start, b_end))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("trace", hex(b_start), hex(b_end), str(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE))

                DDR_print_mesg("Sending following config to server:")
                DDR_API_V1_CONFIG_SETTINGS.print_cfg()

                if not self._call_api(cmd_id=7, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Failed to run full trace for selected range.",2)
                    idaapi.warning("Failed to run full trace for selected range.")
                DDR_print_mesg("Done. Full trace on address range executed.")
                DDR_print_mesg("-------------------------------------------------------------------------------")

                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")
                DDR_API_V1_CONFIG_SETTINGS.cfg = json.loads(old_cfg)

            else:
                DDR_print_mesg("Failed finding address range.")
            return 1

        if self.cmd == ("Run_Trace_On_BB"):
            DDR_print_mesg("Running trace for selected basic block.")
    
            f = idaapi.get_func(ea)

            if not f:
                DDR_print_mesg("No function found at 0x{:x}. This only works inside of functions.".format(ea))
                idaapi.warning("No function found at 0x{:x}. This only works inside of functions.".format(ea))
                return

            fc = idaapi.FlowChart(f)
            for block in fc:
                if block.start_ea <= ea:
                    if block.end_ea > ea:
                        b_start = block.start_ea
                        b_end   = idc.prev_head(block.end_ea) 

            if b_start and b_end and b_start != idc.BADADDR and b_end != idc.BADADDR:
                old_cfg = DDR_API_V1_CONFIG_SETTINGS.get_cfg_json_str_formatted()
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("dumpbuffer") 
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")

                DDR_print_mesg("Running trace on basic block [0x{:x} - 0x{:x}]".format(b_start, b_end))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("trace", hex(b_start), hex(b_end), str(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE)) 

                DDR_print_mesg("Sending following config to server:")
                DDR_API_V1_CONFIG_SETTINGS.print_cfg()  

                if not self._call_api(cmd_id=7, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Failed to run full trace for selected basic block.",2)
                    idaapi.warning("Failed to run full trace for selected basic block.")
                else:
                    DDR_print_mesg("Done. Full trace on basic block executed.")
                    DDR_print_mesg("-------------------------------------------------------------------------------")

                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace")
                DDR_API_V1_CONFIG_SETTINGS.cfg = json.loads(old_cfg)
            else:
               DDR_print_mesg("Basic block start and end address not found.",2) 

            return 1

        if self.cmd == ("Run_Trace_On_BB_list"):
            DDR_print_mesg("Running trace for selected basic block list:")

            # We can either dump a buffer or trace the file itm. 
            old_cfg = DDR_API_V1_CONFIG_SETTINGS.get_cfg_json_str_formatted()

            for block in BB_LIST:
                DDR_print_mesg("Block [0x{:x} - 0x{:x}]".format(block.start, block.end))
                DDR_API_V1_CONFIG_SETTINGS.set_cfg_para("trace", hex(block.start), hex(block.end), str(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE)) 

            if not DDR_API_V1_CONFIG_SETTINGS.cfg_verified():
                idaapi.warning("Trace config verification failed. Please first select basic blocks via 'Select' menu.")
                DDR_print_mesg("Missing mandatory values: {}".format(DDR_API_V1_CONFIG_SETTINGS.get_missing_cfg_values_msg("trace")),2)
                DDR_print_mesg("Trace configuration verification failed. Please first select basic blocks via 'Select' menu.",2)        
            else:
                DDR_API_V1_CONFIG_SETTINGS.cfg["id"] = 7
                # We can either dump a buffer or trace the file itm. 
                DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("dumpbuffer") 

                DDR_print_mesg("Sending following config to server:")
                DDR_API_V1_CONFIG_SETTINGS.print_cfg()
                if not self._call_api(cmd_id=7, dump_para_json = DDR_API_V1_CONFIG_SETTINGS.cfg):
                    DDR_print_mesg("Failed to run full trace for basic block list.",2)
                    idaapi.warning("Failed to run full trace for basic block list.")
                else:
                    DDR_print_mesg("Done. Full trace on basic block list executed.")
                    DDR_print_mesg("-------------------------------------------------------------------------------")

                DDR_API_V1_CONFIG_SETTINGS.cfg = json.loads(old_cfg)

            DDR_API_V1_CONFIG_SETTINGS.clear_cfg_para("trace") # clear trace config, we have it still saved in the BB list

            return 1

        if self.cmd == ("Highlight_trace"): 
            if(JSONFILE_LOADED == False):
                self._trace_file_not_loaded()
                return 1
            else:
                self._highlight_trace()
                DDR_print_mesg("Done. Instructions highlighted.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
                return 1

        if self.cmd == ("Clear_highlighted_blocks"):
                self._clear_highlight_trace(ea)
                DDR_print_mesg("Done. Highlighted instructions cleared.")
                DDR_print_mesg("-------------------------------------------------------------------------------")
                return 1

        if self.cmd == ("Get_Set_Num_Hits_Cmt"):
            cmt_rnds = ida_kernwin.ask_long(DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS, "Please enter max. number of hits to display in IDA comments (max. {:d}):".format(DDR_CONFIG_SETTINGS.MAX_INSTR_COUNT))
            try:
                if cmt_rnds > 0 and cmt_rnds <= DDR_CONFIG_SETTINGS.MAX_INSTR_COUNT:
                    DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS = cmt_rnds
                    DDR_print_mesg("Number of hits for repeatable comments {:d} set".format(DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS)) 
                return 1
            except:
                DDR_print_mesg("Setting value canceled. Number of hits for repeatble comments {:d}".format(DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS), 1) 
                return 1

        if self.cmd == ("Get_Set_Num_Hits_IdaLog"):
            try:
                cmt_rnds = ida_kernwin.ask_long(DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS, "Please enter max. number of hits to display in IDA comments (max. {:d}):".format(DDR_CONFIG_SETTINGS.MAX_INSTR_COUNT))
                if cmt_rnds > 0 and cmt_rnds <= DDR_CONFIG_SETTINGS.MAX_INSTR_COUNT:
                    DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS = cmt_rnds
                    DDR_print_mesg("Number of hits for IDA log window {:d} set".format(DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS)) 
                return 1
            except:
                DDR_print_mesg("Setting value canceled. Number of hits for IDA log window {:d}".format(DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS), 1) 
                return 1


        if self.cmd == ("Get_Set_Max_Instr"):
            try:
                cmt_rnds = ida_kernwin.ask_long(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE, "Please enter max. number of instructions to process in DynamoRio analysis (Default: 20000):")
                if cmt_rnds > 0:
                    if cmt_rnds > 40000:
                        idaapi.warning("Setting max. instructions to greater than 40000 might be slow. Only use it for 'Run Light Trace on Segment' feature " + 
                            "or make sure you do not run into API timeouts (DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT) because the analysis takes too long on the server side.")
                    DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE = cmt_rnds
                    DDR_print_mesg("Max. Number of instructions to process in DynamoRio analysis set to: {:d}".format(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE))
                return 1
            except:
                DDR_print_mesg("Setting value canceled. Max. Number of instructions to process in DynamoRio analysis: {:d}".format(DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE), 1)
                return 1

        if self.cmd == ("Get_Set_API_timeout"):
            try:
                cmt_rnds = ida_kernwin.ask_text(20, str(DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT), "Please enter max. number of seconds to wait for the DDR server API to answer (Default: 30):")
                DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT = float(cmt_rnds)
                DDR_print_mesg("Max. number of seconds to wait for a response from the DDR server set to: {:f} seconds".format(DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT))
                return 1
            except:
                DDR_print_mesg("Setting value canceled. Max. Number of to wait for a response from the DDR server: {:f}".format(DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT), 1)
                return 1

        if self.cmd == ("Display_Strings_View"):
            if(JSONFILE_LOADED == False):
                self._trace_file_not_loaded()
                return 1    
            else:
                items = self._get_chooser_row_list_strings()
                DDR_print_mesg("Len items: {:d}".format(len(items)),7)
                columns = [ ["Instruction #", 6], ["Address", 12], ["Type", 15], ["Data Hex", 25], ["Data Address", 12], ["String", 12], ["Disasm", 35] ]
                c = DDR_MyChoose("Strings Trace", items=items, modal=False, columns=columns)
                if not c.show():
                    DDR_print_mesg("Failed to start Strings Trace View", 7)
                else:
                    DDR_print_mesg("Strings Trace View created", 7)
                return 1 

        if self.cmd == ("Display_Calls_View"):
            if APIFILE_LOADED == False:
                DDR_print_mesg("API trace file not loaded. Pls use 'Trace' menu to run a trace first. To generate a trace and API trace file.", 1)
                DDR_print_mesg("Alternativly, you can use 'File/Load File/Load DDR trace ... file' menu to load custom files.", 1)
                idaapi.warning("API trace file not loaded. Pls use DDRs 'Trace' menu to run a trace first OR load custom trace files via 'File/Load File/Load DDR trace ... file'.") 
                return 1

            if JSONFILE_LOADED == False:
                self._trace_file_not_loaded()
                return 1
            else:
                items = self._get_chooser_row_list_calls()
                DDR_print_mesg("Len items: {:d}".format(len(items)),7)
                columns = [ ["Instruction #", 6], ["Address", 12], ["Type", 15], ["Data Address", 12], ["API call", 12], ["API module", 12], ["Disasm", 35] ]
                c = DDR_MyChoose("API Call Trace", items=items, modal=False, columns=columns)
                if not c.show():
                    DDR_print_mesg("Failed to start Call Trace View", 7)
                else:
                    DDR_print_mesg("Call Trace View created", 7)
                return 1 

        # Load DynamoRIO JSON File 
        if self.cmd == "LoadFile" :
            self._load_JSON_file()
            return 1

        # Load DynamoRIO JSON API File 
        if self.cmd == "LoadAPIFile" :
            api_filename=self._get_JSON_APIfile()
            if api_filename == None:
                DDR_print_mesg("File dialog canceled. API file not loaded.",1)
                return 1
            if self._load_APICalls_file(api_filename):
                DDR_print_mesg("API trace file imported: {}".format(api_filename),7)
            return 1

        # Delete comments
        if self.cmd == "DeleteNonRepeatableComments":
            try:
                start = idc.read_selection_start()
                end   = idc.read_selection_end()

                DDR_print_mesg("Selected processing range: {:x} - {:x} ea={:x}".format(start, end, ea),7)
                # User selected multiple lines
                if start != idc.BADADDR and end != idc.BADADDR:
                    DDR_print_mesg("Selected processing range: {:x} - {:x}".format(start, end),7)
                    ea=start
                    while(ea < end):  
                        DDR_print_mesg("Delete non-repeatable comment at {:x}".format(ea)) 
                        idc.set_cmt(ea, "",0)         
                        ea = idc.next_head(ea)
                # User selected single line
                else: 
                    DDR_print_mesg("Selected address: {:x}".format(ea),7) 
                    DDR_print_mesg("Delete non-repeatable comment at line {:x}".format(ea))
                    idc.set_cmt(ea, "",0)

                DDR_print_mesg("Done. repeatable Comments deleted.")
                DDR_print_mesg("-------------------------------------------------------------------------------")

                return 1
            except:
                raise


        # Parse all the other menu items (parse_ea) which can be applied to a single ea or a range (e.g. Get src op value etc)
        if(JSONFILE_LOADED == True):
            start = idc.read_selection_start()
            end   = idc.read_selection_end()
            # User selected multiple lines
            if start != idc.BADADDR and end != idc.BADADDR:
                DDR_print_mesg("Selected processing range: {:x} - {:x}".format(start, end),7)
                ea=start
                while(ea < end):
                    self._parse_ea(ea)
                    ea = idc.next_head(ea)
            # User selected single line
            else:
                DDR_print_mesg("Selected address: {:x}".format(ea),7)
                self._parse_ea(ea)

            DDR_print_mesg("Done.")
            DDR_print_mesg("-------------------------------------------------------------------------------")
        else:
            self._trace_file_not_loaded()
            
        return 1


    def op_count(self, ea):
        """Return the number of operands of given instruction"""
        for i in range(10):
            op = idc.print_operand(ea,i)
            if op:
                continue
            break
        return i    


    def _get_dump_para_addr_n_op(self, op_str, ea):
        """ Get dump parameters """
        DDR_print_mesg("op_str = {}".format(op_str),7)
        num_operands = self.op_count(ea)
        DDR_print_mesg("Number of operands for instruction at {:x}: {:d}".format(ea, num_operands),7)

        if num_operands < 2:
            op_src = idc.print_operand(ea,0)
            DDR_print_mesg("op_src = {}".format(op_src),7)
            if op_str in op_src:
                DDR_print_mesg("src op match",7)
                ret = "SP0"
            else:
                DDR_print_mesg("Highlighted operand not found pls set it manually",1)
                ret = ida_kernwin.ask_text(3, "SP0", "Highlighted operand not found, pls enter value manually.")
                if ret == "":
                    ret = None
                    ea  = None

        elif num_operands < 3:
            op_dst = idc.print_operand(ea,0)
            op_src = idc.print_operand(ea,1)
            DDR_print_mesg("op_dst = {}".format(op_dst),7)
            DDR_print_mesg("op_src = {}".format(op_src),7)
            if op_str in op_src:
                DDR_print_mesg("src op match",7)
                ret = "SP0"
            elif op_str in op_dst:
                DDR_print_mesg("dst op match",7)
                ret = "DP0"
            else:
                DDR_print_mesg("Highlighted operand not found pls set it manually",1)
                ret = ida_kernwin.ask_text(3, "SP0", "Highlighted operand not found, pls enter value manually.")
                if ret == "":
                    ret = None
                    ea  = None

        else:
            idaapi.warning("Sorry, instructions with more than 2 operands are not supported in the moment.")
            DDR_print_mesg("Sorry, instructions with more than 2 operands are not supported in the moment.",2)
            return (None,None)

        return (ea,ret)

    def _parse_ea(self, ea):
        """
        Main parser method for parsing and analysing data at address (ea)
        """
        
        op0 = idc.print_operand(ea,0)
        op1 = idc.print_operand(ea,1)
        op0_type = idc.get_operand_type(ea,0)
        op1_type = idc.get_operand_type(ea,1)

        DDR_print_mesg("Address: 0x{:x}:".format(ea))
        DDR_print_mesg("  DISASM   : {}".format(idc.GetDisasm(ea)))
        DDR_print_mesg("  CMD      : {}".format(self.cmd), 7)
        DDR_print_mesg("  OP0      : {}".format(op0),7)
        DDR_print_mesg("  OP1      : {}".format(op1),7)
        DDR_print_mesg("  OP0 type : {:x}".format(op0_type),7)
        DDR_print_mesg("  OP1 type : {:x}".format(op1_type),7)
        DDR_print_mesg("  OP0 value: {:x}".format(idc.get_operand_value(ea,0)),7)
        DDR_print_mesg("  OP1 value: {:x}".format(idc.get_operand_value(ea,1)),7)

        # Handle selected menu entries
        if self.cmd == "GetSrcOpValue":
            trace_instr_num_list = self._get_trace_instr_list(ea) 
            self._set_ida_src_op_name(ea)
            self._handle_trace_list(ea, self.src_op, "inst_mem_addr_src0", trace_instr_num_list, "SrcVal")

        if self.cmd == "GetDstOpValue":
            trace_instr_num_list = self._get_trace_instr_list(ea) 
            self._set_ida_dst_op_name(ea)
            self._handle_trace_list(ea, self.dst_op, "inst_mem_addr_dst0", trace_instr_num_list, "DstVal")
          
        if self.cmd == "GetSrcOpPtrValue":
            DDR_print_mesg("Menu GetSrcOpPtrValue selected")
            trace_instr_num_list = self._get_trace_instr_list(ea) 
            self._set_ida_src_op_name(ea)
            self._handle_trace_list_ptr_value(ea, self.src_op, "inst_mem_addr_src0_data", trace_instr_num_list, "SrcValPtr")

        if self.cmd == "GetDstOpPtrValue":
            DDR_print_mesg("Menu GetDstOpPtrValue selected")
            trace_instr_num_list = self._get_trace_instr_list(ea) 
            self._set_ida_dst_op_name(ea)
            self._handle_trace_list_ptr_value(ea, self.dst_op, "inst_mem_addr_dst0_data", trace_instr_num_list, "DstValPtr")

        if self.cmd == "GetSrcOpPtrPtrValue":
            DDR_print_mesg("Menu GetSrcOpPtrPtrValue selected")
            trace_instr_num_list = self._get_trace_instr_list(ea) 
            self._set_ida_src_op_name(ea)
            self._handle_trace_list_ptr_value(ea, self.src_op, "inst_mem_addr_src0_data_ptr_data", trace_instr_num_list, "SrcValPtrPtr")

        if self.cmd == "GetDstOpPtrPtrValue":
            DDR_print_mesg("Menu GetDstOpPtrPtrValue selected")
            trace_instr_num_list = self._get_trace_instr_list(ea) 
            self._set_ida_dst_op_name(ea)
            self._handle_trace_list_ptr_value(ea, self.dst_op, "inst_mem_addr_src0_data_ptr_data", trace_instr_num_list, "DstValPtrPtr")

        if self.cmd=="GetSrcPtrMem":
            trace_instr_num_list = self._get_trace_instr_list(ea)
            self._set_ida_src_op_name(ea)
            self._handle_trace_list_ptr(ea, self.src_op, "inst_mem_addr_src0_data", trace_instr_num_list, "SrcPtrMem")  

        if self.cmd=="GetDstPtrMem":
            trace_instr_num_list = self._get_trace_instr_list(ea)
            self._set_ida_dst_op_name(ea)
            self._handle_trace_list_ptr(ea, self.dst_op, "inst_mem_addr_dst0_data", trace_instr_num_list, "DstPtrMem")  

        if self.cmd=="GetSrcPtrPtrMem":
            trace_instr_num_list = self._get_trace_instr_list(ea)
            self._set_ida_src_op_name(ea)
            self._handle_trace_list_ptr(ea, self.src_op, "inst_mem_addr_src0_data_ptr_data", trace_instr_num_list, "SrcPtrPtrMem")

        if self.cmd=="GetDstPtrPtrMem":
            trace_instr_num_list = self._get_trace_instr_list(ea)
            self._set_ida_dst_op_name(ea)
            self._handle_trace_list_ptr(ea, self.dst_op, "inst_mem_addr_dst0_data_ptr_data", trace_instr_num_list, "DstPtrPtrMem")

        # --- Register menu selected ---
        # REG_LIST(64) = ["xax","xbx","xcx","xdx","xsp","xbp","xsi","xdi","r8","r9","r10","r11","r12","r13","r14","r15"]
        # REG_LIST(32) = ["xax","xbx","xcx","xdx","xsp","xbp","xsi","xdi"]
        for reg in REG_LIST:
            DDR_print_mesg("reg:{}".format(reg), 7) 
            if self.cmd=="Get_Mem_Ptr_" + reg:
                trace_instr_num_list = self._get_trace_instr_list(ea)
                self._set_ida_comment_regmenu_mem_ptr(ea, reg, trace_instr_num_list)

        return True

    def _trace_file_not_loaded(self):
        DDR_print_mesg("Trace file not loaded. Pls use DDRs 'Trace' menu to run a trace first.", 1)
        DDR_print_mesg("Alternativly, you can use 'File/Load File/Load DDR trace file' to load a custom trace file.", 1)
        idaapi.warning("Trace file not loaded. Pls use DDRs 'Trace' menu to run a trace first OR load a custom trace file via 'File/Load File/Load DDR trace file'.") 

    def _load_APICalls_file(self, filename = None):
        global APIFILE_LOADED
        global API_CALLS
        API_CALLS = {}      # reset API calls dict

        try:
            with open(filename) as apicall_file: 
                apicall_data = json.load(apicall_file)
            DDR_print_mesg("API calls file loaded: {}".format(filename))
            APIFILE_LOADED = True
        except IOError as e:
            DDR_print_mesg("Failed to open API calls file. Quitting operation.")
            APIFILE_LOADED = False
            return False
        except ValueError as e:
            DDR_print_mesg("Failed to parse API calls file: {}. Quitting operation.".format(filename),2)
            DDR_print_mesg("Please check file format is JSON and try again.",2)
            e_args = ''.join(map(str,e.args))
            DDR_print_mesg("{}".format(e_args))
            APIFILE_LOADED = False
            idaapi.warning("[DDR] Failed to open API calls file. Check Logging window for details.")
            return False

        # Build call dict with address as key
        for call in apicall_data["apicalls"]:
            if call["address"] in API_CALLS:
                old_name = API_CALLS[call["address"]]
                API_CALLS[call["address"]] = call["name"] + "," + old_name  
            else:
                API_CALLS[call["address"]] = call["name"] + ";" + call["module"]

        return True


    def _load_JSON_file(self, filename = None):
        """ Loads DynamoRIO generated JSON file into memory """
        global JSONDATA
        global JSONFILE_LOADED

        if filename == None:
            filename = self._get_JSON_file()
            if filename == None:
                # Dialog canceled
                DDR_print_mesg("File dialog canceled. Trace file not loaded.",1)
                return False

        try:
            with open(filename) as json_file:  
                JSONDATA = json.load(json_file)
                JSONFILE_LOADED = True
                DDR_print_mesg("JSON file was generated for executable: {}".format((JSONDATA["samplename"])))
                if DDR_CONFIG_SETTINGS.ARCH_BITS == 64 and JSONDATA["architecture"] != "x64":
                    idaapi.warning("JSON File has wrong architecture: {}".format(JSONDATA["architecture"]))
                    DDR_print_mesg("JSON File has wrong architecture: {}".format(JSONDATA["architecture"]))
                    JSONFILE_LOADED = False
                    return False
                elif DDR_CONFIG_SETTINGS.ARCH_BITS == 32 and JSONDATA["architecture"] != "x32":
                    idaapi.warning("JSON File has wrong architecture: {}".format(JSONDATA["architecture"]))
                    DDR_print_mesg("JSON File has wrong architecture: {}".format(JSONDATA["architecture"]))
                    JSONFILE_LOADED = False
                    return False
                else:
                    DDR_print_mesg("Instructions traced in JSON file: {:d}".format(len(JSONDATA["instruction"])))
                    return True
        except IOError as e:
            DDR_print_mesg("Failed to open JSON file. Quitting operation.")
            JSONFILE_LOADED = False
            return False
        except ValueError as e:
            DDR_print_mesg("Failed to parse JSON file: {}. Quitting operation.".format(filename),2)
            DDR_print_mesg("Please check file format is JSON and try again.",2)
            e_args = ''.join(map(str,e.args))
            DDR_print_mesg("{}".format(e_args))
            JSONFILE_LOADED = False
            idaapi.warning("[DDR] Failed to open JSON file. Check Logging window for details.")
            return False
        else:
            DDR_print_mesg("Failed to open JSON file: {} with unknown error. Quitting operation.".format(filename),2)
            JSONFILE_LOADED = False
            idaapi.warning("[DDR] Failed to open JSON file. Check Logging window for details.")
            raise


    def _get_JSON_file(self):
        """
        Prompt a file selection dialog, returning file selections.
        """
        my_dir = JSONFILE_DIR

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            'Open DDR generated instructions trace JSON file', # IDA does not show this capition itm.
            #idautils.GetIdbDir(),
            my_dir,
            'All Files (*.*)'
        )
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filename, _ = file_dialog.getOpenFileName()

        if filename == '':
            return None

        # log the selected filenames from the dialog
        DDR_print_mesg("DDR instructions trace JSON file loaded: {}".format(filename))

        # return the captured filenames
        return filename


    def _get_JSON_APIfile(self):
        """
        Prompt a file selection dialog, returning file selections.
        """
        my_dir = JSONFILE_DIR

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            'Open DDR generated API trace JSON file',  # IDA does not show this capition itm.  
            #idautils.GetIdbDir(),
            my_dir,
            'All Files (*.*)'
        )
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filename, _ = file_dialog.getOpenFileName()

        if filename == '':
            return None

        # log the selected filenames from the dialog
        DDR_print_mesg("DDR API trace JSON file loaded: {}".format(filename),7)

        # return the captured filenames
        return filename


    def _highlight_trace(self):
        """ Highlight basics blocks in IDA graph disasm view"""
        
        #idaapi.get_item_color(ea)   # Get actual color at ea

        # COLOR                                                                                             # Number of instr. executed
        # -----------------------------------------------------------------------------------------------------------------------------
        # green         = [0xa0ffa0, 0x70ff70, 0x00ff00, 0x00ef00, 0x00df00, 0x00cf00, 0x00bf00, 0x00af00]  # 0x0   - 0xf
        # yellow        = [0xd0ffff, 0xa0ffff, 0x70ffff, 0x00ffff, 0x00efff, 0x00dfff, 0x00cfff, 0x00bfff]  # 0x10  - 0xff
        # red           = [0xC0C0ff, 0xB0B0ff, 0xA0A0ff, 0x8080ff, 0x6060ff, 0x4040ff, 0x2020ff, 0x0000ff]  # 0x100 -  0xfff
        # light_purple  = 0xFF60FF                                                                          # 0x1000  - 0xffff
        # purple        = 0xFF00FF                                                                          # 0x10000 - infinity

        inst_addr_list = []
        for instr in JSONDATA["instruction"]:
            inst_addr_list.append(int(instr["address"], 16))

        inst_addr_counter = Counter(inst_addr_list)

        # paint lines depending on the number of occurences in the trace 
        # Default: (green 0-0xf, yellow 0x10 - 0xff, red 0x100 - 0xfff, light_purple 0x1000 - 0xffff, purple > 0xffff)
        for ea in inst_addr_counter:
            if inst_addr_counter[ea] > 0xffff:  
                idaapi.set_item_color(ea, COLOR5)
                continue

            if inst_addr_counter[ea] > 0xfff:  
                idaapi.set_item_color(ea, COLOR4)
                continue

            if inst_addr_counter[ea] > 0xff: 
                if inst_addr_counter[ea] <= 7:
                    color = COLOR3[inst_addr_counter[ea]]
                else:
                    color = COLOR3[7]
                idaapi.set_item_color(ea, color)
                continue

            if inst_addr_counter[ea] > 0xf: 
                if inst_addr_counter[ea] <= 7:
                    color = COLOR2[inst_addr_counter[ea]]
                else:
                    color = COLOR2[7]
                idaapi.set_item_color(ea, color)
                continue

            if inst_addr_counter[ea] <= 0xf:
                if inst_addr_counter[ea] <= 7:
                    color = COLOR1[inst_addr_counter[ea]]
                else:
                    color = COLOR1[7]
                idaapi.set_item_color(ea, color)
     
    def _clear_highlight_trace(self, ea):
        # Loop through all instructions
        for ea in idautils.Segments():
            seg_start = idc.get_segm_start(ea)
            seg_end = idc.get_segm_end(ea)

            addr = seg_start
            while (addr < seg_end) and (addr != idaapi.BADADDR):
                # Set color to default white background
                idaapi.set_item_color(addr, 0xffffffff)
                addr = idc.next_head(addr)

    def _find_apicall_for_addr(self, addr):
        """ Check if addr is a symbol / known api address"""
        if addr in API_CALLS:
            apiname_with_module = API_CALLS[addr]
            name = apiname_with_module.split(";")[0]
            module = apiname_with_module.split(";")[1]
            return name, module
        return "-", "-"

    def _get_chooser_row_list_strings(self) :
        """ Fill the lines list used for the Trace Window item list"""

        lines = []
        for instr in JSONDATA["instruction"]:                               
            for s in [ "inst_mem_addr_src0_data", "inst_mem_addr_src0_data_ptr_data"]:
                try:
                    line  = []
                    line.append("{:12d}".format(int(instr["instr_num"],10)))    # instruction number in trace
                    line.append(str(instr["address"]))                          # ea address of instruction
                    if s == "inst_mem_addr_src0_data":
                        datatype = "Pointer"                                    
                    else:
                        datatype = "Pointer-Pointer"                            
                    line.append(datatype)                                       # JSON field (type) of string
                    mystring = str(instr[s])
                    stringlist = mystring.split("    ")
                    line.append(stringlist[0])                                  # String in Hex
                    data_addr = self._get_addr_from_data(mystring)
                    line.append(data_addr)                                      # Data address extracted from mystring
                    line.append("".join(stringlist[1:]))                        # String
                    line.append(str(instr["disasm"]))                           # Disasm of instruction
                    lines.append(line)                                          # add generated line to lines list
                except KeyError as e:
                    break                                                       # key doesn't exists in JSON file, try next instruction

        return lines

    def _get_chooser_row_list_calls(self) :
        """ Fill the lines list used for the API calls Window item list"""
        lines = []
        for instr in JSONDATA["instruction"]:    
            try:
                disasm = instr["disasm"]
            except:
                disasm = "na"                          
            
            try:
                val = instr["inst_mem_addr_src0"]
            except:
                val = "0x0"

            try:
                ptr = instr["inst_mem_addr_src0_data_ptr"]
            except:
                ptr = "0x0"

            if disasm == "na":
                return lines

            else:
                # correlate api function addresses with inst_mem_addr_src0 or inst_mem_addr_src0_data_ptr
                apicall_val, apimodule_val = self._find_apicall_for_addr(val)
                apicall_ptr, apimodule_ptr = self._find_apicall_for_addr(ptr) 

                if apicall_val == '-' and apicall_ptr == '-':
                    continue

                
                if apicall_val != '-':
                    datatype  = "Value"
                    data_addr = val
                    apicall   = apicall_val
                    apimodule = apimodule_val
                else:
                    datatype  = "Pointer"
                    data_addr = ptr
                    apicall   = apicall_ptr
                    apimodule = apimodule_ptr

                line  = []
                line.append("{:12d}".format(int(instr["instr_num"],10)))    # instruction number in trace
                line.append(str(instr["address"]))                          # ea address of instruction
                line.append(datatype)                                       # JSON field (type) of string
                line.append(data_addr)                                      # address called
                line.append(apicall)                                        # API call name
                line.append(apimodule)                                      # API module name
                line.append(disasm)                                         # Disasm of instruction
                lines.append(line)                                          # add generated line to lines list

        return lines

    def _set_ida_src_op_name(self, ea):
        """ Find source operand of instruction and set src_op name"""
        op0 = idc.print_operand(ea,0)
        op1 = idc.print_operand(ea,1)
        op0_type = idc.get_operand_type(ea,0)
        op1_type = idc.get_operand_type(ea,1)

        if op1_type == idaapi.o_void:
            self.src_op = op0
        else:
            self.src_op = op1

        if op0_type == idaapi.o_void:
            self.src_op = "src_op not set"

    def _set_ida_dst_op_name(self, ea):
        """ Find destination operand of instruction and set dst_op name"""
        op0 = idc.print_operand(ea,0)
        op1_type = idc.get_operand_type(ea,1)

        if op1_type == idaapi.o_void:
            self.dst_op = "dst_op not set"
        else:
            self.dst_op = op0

    def _handle_trace_list_ptr_value(self, ea, op, json_instr_field, trace_instr_num_list, usrcmd):
        comment = ""
        if not trace_instr_num_list:
            comment = "Instruction at {:x} not in trace".format(ea)

        #TBD: sub optimal algorithm, fix this
        for c,i in enumerate(trace_instr_num_list):
            try:
                if c < DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS:
                    data = JSONDATA["instruction"][i][json_instr_field]
                    addr = self._get_addr_from_data(data)
                    apicall, apimodule = self._find_apicall_for_addr(addr)
                    DDR_print_mesg("    {}:{}  APIname:{}  Module:{}".format(usrcmd,addr,apicall,apimodule))
                if c < DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS:
                    data = JSONDATA["instruction"][i][json_instr_field]
                    addr = self._get_addr_from_data(data)
                    apicall, apimodule = self._find_apicall_for_addr(addr)
                    if apicall == '-':
                        comment += "{}:0x{:x}; ".format(usrcmd, int(addr,16))  # delete leading zeros
                    else:
                        comment += "{}:{}; ".format(usrcmd, apicall)  
            except:
                if c < DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS:
                    DDR_print_mesg("    {}:InstrAddr=0x{:x} instr number:{:07d} = No pointer found".format(usrcmd, ea, i))
                if c < DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS:
                    comment += "{}:PtrNotFound; ".format(usrcmd)


        # Get existing commend and add our dynamic data to it.
        org_cmt = idc.GetCommentEx(ea, False)
        if org_cmt != None:
            new_comment = org_cmt + "\n" + comment
        else:
            new_comment = comment

        idc.set_cmt(ea, str(new_comment),0)   # IDA doesn't like unicode from JSON file 


    def _handle_trace_list(self, ea, op, json_instr_field, trace_instr_num_list, usrcmd):
        """ Get content from 'json_instr_field' key from JSON file and generate corrosponding comment for value"""
        comment = ""
        if not trace_instr_num_list:
            comment = "Instruction at 0x{:x} not in trace".format(ea)

        for c,i in enumerate(trace_instr_num_list):
            try:
                addr = JSONDATA["instruction"][i][json_instr_field]
                if c < DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS:
                    apicall, apimodule = self._find_apicall_for_addr(addr)
                    DDR_print_mesg("    {}({})@0x{:x}@instr number:{:07d} = 0x{:x} (APIname:{}  Module:{})".format(usrcmd, op, ea, i, int(addr,16), apicall,apimodule))

                if c < DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS:
                    apicall, apimodule = self._find_apicall_for_addr(addr)
                    if apicall == '-':
                        comment += "{}:0x{:x}; ".format(usrcmd, int(addr,16))  # delete leading zeros
                    else:
                        comment += "{}:{}; ".format(usrcmd, apicall)  
            except:
                if c < DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS:
                    DDR_print_mesg("    {}({})@0x{:x}@instr number:{:07d} = No memory data found in JSON file".format(usrcmd, op, ea, i))
                if c < DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS:
                    comment += "{}({}):NotFound; ".format(usrcmd,op) 

        # Get existing commend and add our dynamic data to it.
        org_cmt = idc.GetCommentEx(ea, False)
        if org_cmt != None:
            new_comment = org_cmt + "\n" + comment
        else:
            new_comment = comment

        idc.set_cmt(ea, str(new_comment),0)    

    def _handle_trace_list_ptr(self, ea, op, json_instr_field, trace_instr_num_list, usrcmd):
        """ Get content from 'json_instr_field' key from JSON file and generate corrosponding comment for pointer or pointer-pointer"""
        comment = ""
        if not trace_instr_num_list:
            comment = "Instruction at 0x{:x} not in trace".format(ea)

        for c,i in enumerate(trace_instr_num_list):
            try:
                if c < DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS:
                    DDR_print_mesg("    {}({})@0x{:x}@instr number:{:07d} = {}".format(usrcmd, op, ea, i, str(JSONDATA["instruction"][i][json_instr_field])))
                if c < DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS:
                    comment += "{}({}):{}; ".format(usrcmd, op, str(JSONDATA["instruction"][i][json_instr_field])) 
            except:
                if c < DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS:
                    DDR_print_mesg("    {}({})@0x{:x}@instr number:{:07d} = No memory data found in JSON file".format(usrcmd, op, ea, i))
                if c < DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS:
                    comment += "{}({}):NotFound; ".format(usrcmd,op) 

        # Get existing commend and add our dynamic data to it.
        org_cmt = idc.GetCommentEx(ea, False)
        if org_cmt != None:
            new_comment = org_cmt + "\n" + comment
        else:
            new_comment = comment

        idc.set_cmt(ea, new_comment,0)        
 
    def _set_ida_comment_regmenu_mem_ptr(self, ea, reg, trace_instr_num_list):
        """ Prints out the content stored in the register and the memory data the register value is pointing to, then adds a comment to the disasm view"""
        comment = ""

        if not trace_instr_num_list:
            comment = "Instruction at 0x{:x} not in trace".format(ea)

        for c,i in enumerate(trace_instr_num_list):
            if c < DDR_CONFIG_SETTINGS.MAX_LOG_ROUNDS:
                try:
                    DDR_print_mesg("    {}(={})@instr number:{:07d} = {}".format(reg, JSONDATA["instruction"][i][reg], i, JSONDATA["instruction"][i][reg + "_ptr_data"]))
                except:
                    DDR_print_mesg("    {}@instr number:{:07d} = not found in data. Did you run a full trace ?".format(reg,i))
            if c < DDR_CONFIG_SETTINGS.MAX_CMT_ROUNDS:
                s_pdata  = "NO_DATA"
                regval   = 0

                try:
                    s_pdata  = str(JSONDATA["instruction"][i][reg + "_ptr_data"])
                    regval   = int(JSONDATA["instruction"][i][reg],16)
                except:
                    pass

                s_cmt = str("{}(0x{:x})={}; ".format(reg, regval, s_pdata)) #IDA doesn't like unicode type

                comment += s_cmt

        # Get existing commend and add our dynamic data to it.
        org_cmt = idc.GetCommentEx(ea, False)
        if org_cmt != None:
            new_comment = org_cmt + "\n" + comment
        else:
            new_comment = comment

        idc.set_cmt(ea, new_comment,0)

    def _get_addr_from_data(self, data):
        """ Extracts an address from the data bytes stream e.g. 04 03 02 01 00 00 00 ... => 01020304. Returns the addrs as string with a leading 0x... """
        if DDR_CONFIG_SETTINGS.ARCH_BITS == 64:
            s_addr = data[21:23] + data[18:20] + data[15:17] + data[12:14] + data[9:11] + data[6:8] + data[3:5] + data[:2] 
        else:
            s_addr = data[9:11] + data[6:8] + data[3:5] + data[:2] 

        return "0x" + s_addr

    def _get_trace_instr_list(self, ea):
        """ Get instruction number list from JSON trace file for ea address, if operand is a memory address"""

        trace_instr_num_list = []
        trace_instr_num_list = self._find_instr_addr_in_json(ea, trace_instr_num_list)

        DDR_print_mesg("Build list for ea=0x{:x} length_trace_instr_num_list={:d}".format(ea, len(trace_instr_num_list)),7)

        if not trace_instr_num_list:
            DDR_print_mesg("Instruction address 0x{:x} not found in trace file.".format(ea))

        return trace_instr_num_list

    def _find_instr_addr_in_json(self, ea, trace_instr_num_list):
        """ Return a list of all instructions from the JSON file which match the ea address"""
        i=0
        c=0
        for instr in JSONDATA["instruction"]:                               # TBD change to eval..
            jsonaddr = int(JSONDATA["instruction"][i]["address"], 16)
            if jsonaddr == ea:
                DDR_print_mesg("    {:d}. Found instr address    : {:x}".format(i, ea),7)
                trace_instr_num_list.append(i)
                c += 1
                if c > DDR_CONFIG_SETTINGS.MAX_INSTR_COUNT-1: break
            i += 1

        DDR_print_mesg("    Number of times instruction at address (0x{:x}) executed in trace file: {:d}".format(ea, len(trace_instr_num_list)))

        return trace_instr_num_list

    def _Add_BB2BBlist(self, ea):
        """ runs DynamoRio analysis against the marked basic block (only works for functions)"""
        f = idaapi.get_func(ea)

        if not f:
            DDR_print_mesg("No function found at 0x{:x}. This only works inside of functions.".format(ea))
            idaapi.warning("No function found at 0x{:x}. This only works inside of functions.".format(ea))
            return False

        fc = idaapi.FlowChart(f)
        for block in fc:
            if block.start_ea <= ea:
                if block.end_ea > ea:
                    DDR_print_mesg("0x{:x} is part of block [0x{:x} - 0x{:x}]".format(ea, block.start_ea, idc.prev_head(block.end_ea)))
                    BB_LIST.add(block.start_ea, idc.prev_head(block.end_ea))
        return True

    def _Remove_BB2BBlist(self, ea):
        """ runs DynamoRio analysis against the marked basic block (only works for functions)"""
        f = idaapi.get_func(ea)

        if not f:
            DDR_print_mesg("No function found at 0x{:x}. This only works inside of functions.".format(ea))
            idaapi.warning("No function found at 0x{:x}. This only works inside of functions.".format(ea))
            return False

        fc = idaapi.FlowChart(f)
        for block in fc:
            if block.start_ea <= ea:
                if block.end_ea > ea:
                    DDR_print_mesg("0x{:x} is part of block [0x{:x} - 0x{:x}]".format(ea, block.start_ea, idc.prev_head(block.end_ea)))
                    BB_LIST.remove(block.start_ea, block.end_ea)
        return True

    def _exec_dynRIO_against_BB(self, ea):
        """ runs DynamoRio analysis against the marked basic block (only works for functions)"""
        f = idaapi.get_func(ea)

        if not f:
            DDR_print_mesg("No function found at 0x{:x}. This only works inside of functions.".format(ea))
            idaapi.warning("No function found at 0x{:x}. This only works inside of functions.".format(ea))
            return

        fc = idaapi.FlowChart(f)
        for block in fc:
            if block.start_ea <= ea:
                if block.end_ea > ea:
                    DDR_print_mesg("0x{:x} is part of block [0x{:x} - 0x{:x}]".format(ea, block.start_ea, idc.prev_head(block.end_ea)))
                    self._exec_dynRio(start_addr=block.start_ea, end_addr=idc.prev_head(block.end_ea), instr_count=DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE)
             
    #TBD: do some input checks
    def _exec_dynRio(self, start_addr=None, end_addr=None, break_addr=None, instr_count=None, options=None):
        """ Wrapper to prepare calling the DDRsever.py API _call_api method to send cmds"""
        if start_addr == None or end_addr == None or instr_count == None:
            DDR_print_mesg("start_addr, end_addr or instr_count not set")
            return False

        DDR_print_mesg("Block 0x{:x} - 0x{:x}".format(start_addr, end_addr),7)

        dynrio_sample = SAMPLE_FILENAME

        if options == "light_trace_only":
            cmd_id = 3
        else:
            cmd_id = 1

        self._call_api(cmd_id       = cmd_id,                                   # run dynamoRIO client against sample 
                      dynrio_sample = dynrio_sample,                            # sample file to analyse
                      start_addr    = start_addr,                               # start address to log
                      end_addr      = end_addr,                                 # end address to log
                      instr_count   = DDR_CONFIG_SETTINGS.MAX_INSTR_TO_EXECUTE, # max number of instructions to execute in the trace
                      arch_bits     = DDR_CONFIG_SETTINGS.ARCH_BITS,            # 32 or 64 bit sample architecture
                      options       = options)                                  # option e.g. light_trace_only        
        
        return True

    def _test_zip_is_valid(self, zipfilename):

        if not os.path.isfile(zipfilename):
             DDR_print_mesg("Zip file not found.", 2)
             return False

        try:
            zip_file = zipfile.ZipFile(zipfilename)
            res = zip_file.testzip()

            if res is not None:
                DDR_print_mesg("Bad file in zip archive: {}".format(res), 2)
                return False
            else:
                return True
        except:
            DDR_print_mesg("Zip file: {} is corrupt. File content:\n".format(zipfilename), 2)

            with open(zipfilename, 'r') as f:
                print(f.read())

            os.remove(zipfilename)
            DDR_print_mesg("Corrupt zip file: {} deleted.".format(zipfilename), 2)
            return False

    def get_hash_from_str(self,s):
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256() 
        md5.update(s.encode())
        sha1.update(s.encode())
        sha256.update(s.encode())
        return {"md5_sum"   :md5.hexdigest().upper(),
                "sha1_sum"  :sha1.hexdigest().upper(), 
                "sha256_sum":sha256.hexdigest().upper()}

    def http_ping(self, url):
        """ Quick test if server is responding """
        ret = False

        if DDR_CONFIG_SETTINGS.VERIFY_CERT:
            req_verify =  DDR_CONFIG_SETTINGS.CA_CERT
        else:
            req_verify =  False
                
        try :
            with requests.get(url, verify=req_verify, timeout=3) as res:
                if res.status_code == 200:
                    DDR_print_mesg("HTTP ping successful")
                    ret = True

        except requests.exceptions.SSLError as e:
            DDR_print_mesg("[API SSL ERROR]: {}".format(e),2)
            DDR_print_mesg("Did you configure a valid serial number for the certificate ?",2)
            DDR_print_mesg("For troubleshooting install the certificate from the <IDA plugin dir>/ddr into your browser.",2)
            DDR_print_mesg("Access the DDR server test webpage with your browser and check the error message.",2)
            DDR_print_mesg("Reminder: Test webpage is {}".format(url),2)

        except requests.exceptions.ConnectionError as e:
            DDR_print_mesg("[CONNECTION ERROR]: {}".format(e),2)
            DDR_print_mesg("Did you start and configure the DDR server script or is there any firewall inbetween ?",2)

        except requests.exceptions.HTTPError as e:
            DDR_print_mesg("[HTTP ERROR]: {}".format(e),2)

        except requests.exceptions.ReadTimeout as e:
            DDR_print_mesg("[TIMEOUT ERROR]: {}".format(e),2)

        except:
            DDR_print_mesg("[UNKNOWN ERROR] Unkown error happend. HTTP ping failed.",2)

        return ret


    def _call_api(self, cmd_id=0, dynrio_sample=None, start_addr=None, end_addr=None, instr_count=None, arch_bits=None, options=None, dump_para_json={}):
        """ Main method to call the DDRserver.py API"""

        ret = False

        # Let's test servers reachabillity first
        if not self.http_ping("https://" + DDR_CONFIG_SETTINGS.WEBSERVER + ":" + DDR_CONFIG_SETTINGS.WEBSERVER_PORT + "/"):
            DDR_print_mesg("HTTP ping failed.")
            return False
        
        # ----- New JSON API -------
        if cmd_id >= 5 and cmd_id <= 12:
            url = "https://" + DDR_CONFIG_SETTINGS.WEBSERVER + ":" + DDR_CONFIG_SETTINGS.WEBSERVER_PORT + "/api/v1/json"
            DDR_print_mesg("Using new JSON API...")
        # Error
        else:
            DDR_print_mesg("Unknown command id: {:d}\n".format(cmd_id), 2)
            return False

        if DDR_CONFIG_SETTINGS.VERIFY_CERT:
            req_verify =  DDR_CONFIG_SETTINGS.CA_CERT
        else:
            req_verify =  False

        try:            
            # ---- Dump buffer ----
            if cmd_id == 5:
                ret = False
                dump_para_json['id'] = cmd_id

                tmp_file_list      = []
                dump_filename_list = []
            
                for upload_counter in range(DDR_CONFIG_SETTINGS.MAX_UPLOAD_ATTEMPTS, -1, -1):
                    if upload_counter < 1:
                        DDR_print_mesg("Failed to upload sample file to server. Max number of upload attempts reached",2)
                        return False

                    with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=False) as res:
                        if res.status_code == 200:
                            try:
                                dump_files = res.json()["files"]
                                break
                            except:
                                DDR_print_mesg("No dumpfiles found in server response.",2)
                                dump_files = None
                                ret = False
                                break
                        else:
                            # API return status not 200
                            if "Sample file not found" in res.json()["return_status"]:
                                DDR_print_mesg("Sample file not found on DDR server, trying to upload it...")
                                if DDR_upload_sample(idaapi.get_input_file_path()):
                                    DDR_print_mesg("File {} successfully uploaded.".format(idaapi.get_input_file_path()))
                                continue

                            # other error than sample file not found
                            json_res = res.json()
                            idaapi.warning("Failed dumping buffer on server. See server log for details.")
                            DDR_print_mesg("Failed dumping buffer on server. API return_status = {}".format(json_res["return_status"]),2)
                            return False

                if dump_files:
                    DDR_print_mesg("Successfully dumped buffer on server.")
                    t = datetime.now()
                    timestamp = t.strftime("%d%b%y_%H%M%S")
                    # Prepare filename lists
                    for num, d_file in enumerate(dump_files):
                        df_addr = str(res.json()["fileaddrs"][num])
                        df_size = str(res.json()["filesizes"][num])
                        dump_filename = "dump_{}_{:d}_{}_{}_{}.bin".format(os.path.splitext(SAMPLE_FILENAME)[0], num, df_addr, df_size, timestamp)
                        tmp_file_list.append(d_file)
                        dump_filename_list.append(dump_filename)

                    # Download the dumped file(s)
                    for num, d_file in enumerate(tmp_file_list):
                        dump_para_json['id'] = 9
                        dump_para_json['dl_file'] = [d_file]

                        DDR_print_mesg("Start downloading file {}...".format(d_file))
                        DDR_print_mesg("Sending following config to server:\n{}".format(json.dumps(dump_para_json,indent=4, sort_keys=True)))

                        with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=True) as res:
                            dump_para_json['dl_file'] = []
                            #Success. Response code 200
                            if res.status_code == 200:
                                dump_filename = dump_filename_list[num]
                                dump_filename = ida_kernwin.ask_file(1,dump_filename,"Save dumped buffer to:")
                                if dump_filename:
                                    # Download file
                                    with open(dump_filename, 'wb') as f:
                                        for chunk in res.iter_content(chunk_size=1024): 
                                            if chunk: 
                                                f.write(chunk)
                                else:
                                    DDR_print_mesg("File '{}' not saved. Dialog was canceled.".format(d_file),1)
                                    
                            # Download failed. Response code is not 200
                            else:
                                DDR_print_mesg("Failed downloading {} from server".format(d_file))
                                return False
                    ret = True
                
                # try to delete tmp. buffer files on server
                if tmp_file_list:
                    dump_para_json['id'] = 6
                    dump_para_json['filelist2del'] = tmp_file_list

                    with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=False) as res:
                        if res.status_code == 200:
                            DDR_print_mesg("Temp. buffer file(s) on server successfully deleted")
                            dump_para_json['filelist2del'] = []
                        else:
                            DDR_print_mesg("Failed to delete temp. buffer file(s) on server",2)
                            dump_para_json['filelist2del'] = []
                            ret = False

                return ret

            # ----- Run trace -----
            if cmd_id == 7:
                ret = False
                dump_para_json['id'] = cmd_id
               
                for upload_counter in range(DDR_CONFIG_SETTINGS.MAX_UPLOAD_ATTEMPTS, -1, -1):

                    if upload_counter < 1:
                        DDR_print_mesg("Failed to upload sample file to server. Max number of upload attempts reached",2)
                        return False
                    
                    hash_list = []
                    hash_list.append(json.dumps(dump_para_json['trace_start']))
                    hash_list.append(json.dumps(dump_para_json['trace_end']))
                    hash_list.append(json.dumps(dump_para_json['trace_light']))
                    hash_str = "".join(hash_list)
      
                    trace_filename     = "trace_tmp_" + self.get_hash_from_str(hash_str)["md5_sum"] + ".json"
                    trace_filename_api = os.path.splitext(trace_filename)[0] + "_apicalls.json"
                    zipfilename        = os.path.splitext(trace_filename)[0] + ".zip"
                    
                    with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=True) as res:
                        if res.status_code == 200:
                            # Download file
                            with open(zipfilename, 'wb') as f:
                                for chunk in res.iter_content(chunk_size=1024): 
                                    if chunk: 
                                        f.write(chunk)
                            DDR_print_mesg("Analysis done. Downloaded zip file from server: {}".format(zipfilename))
                            break

                        # Error on the server side. Response is not 200        
                        else:
                            # Sample not found on server
                            if "Sample file not found" in res.json()["return_status"]:
                                DDR_print_mesg("Sample file not found on DDR server, trying to upload it...")
                                
                                if DDR_upload_sample(idaapi.get_input_file_path()):
                                    DDR_print_mesg("File {} successfully uploaded.".format(idaapi.get_input_file_path()))
                            # Other error on server      
                            else:
                                DDR_print_mesg("Failed to generate trace on server, please check server side for details.",2)
                                return False
                
                # Verify zip file is valid
                if not self._test_zip_is_valid(zipfilename):
                    DDR_print_mesg("Zip file verification failed for full trace", 2)
                    return False
                    
                # Extract files from zip archive
                with zipfile.ZipFile(zipfilename, "r") as ziparchive:
                    DDR_print_mesg("Extracting files to {}".format(JSONFILE_DIR))
                    ziparchive.extractall(JSONFILE_DIR)

                # Delete zip archive
                DDR_print_mesg("Delete archive: {}".format(zipfilename))
                try:
                    os.remove(zipfilename)
                except:
                    DDR_print_mesg("Failed to delete zip file: {}".format(zipfilename), 1)
                    pass

                # load and parse downloaded JSON trace file and the API file 
                if self._load_JSON_file(filename=trace_filename):
                    DDR_print_mesg("JSON file succesfully parsed: {}".format(trace_filename))
                    if self._load_APICalls_file(filename=trace_filename_api):
                        # Operation successful. We got valid files from the server.
                        ret = True
                    else:
                        ret = False
                else:
                    ret = False
                  
                # Delete tmp files on server
                dump_para_json['id'] = 8
                
                with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=False) as res:
                    DDR_print_mesg("Told server to delete local temp. files. Respondscode={:d} API status:{}".format(res.status_code, res.json()["return_status"]))
                    
                return ret

            # ----- Run sample only -----
            if cmd_id == 10:
                dump_para_json['id'] = cmd_id

                for upload_counter in range(DDR_CONFIG_SETTINGS.MAX_UPLOAD_ATTEMPTS, -1, -1):
                    with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=False) as res:
                        if res.status_code == 200:
                            DDR_print_mesg("Successfully executed sample on server",2)
                            ret = True
                            break
                        else:
                            if "Sample file not found" in res.json()["return_status"]:
                                DDR_print_mesg("Sample file not found on DDR server, trying to upload it...")
                                if DDR_upload_sample(idaapi.get_input_file_path()):
                                    DDR_print_mesg("File {} successfully uploaded.".format(idaapi.get_input_file_path()))
                            # all other errors
                            DDR_print_mesg("Failed to execute sample on server",2)
                            ret = False

                return ret

            # ----- Create patched binary with endless loop at ea (without DynRio) -----
            if cmd_id == 11:
                dump_para_json['id'] = cmd_id

                for upload_counter in range(DDR_CONFIG_SETTINGS.MAX_UPLOAD_ATTEMPTS, -1, -1):
                    with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=False) as res:
                        if res.status_code == 200:
                            DDR_print_mesg("Response: {}".format(res.json()["return_status"]))
                            ret = True
                            break
                        else:
                            if "Sample file not found" in res.json()["return_status"]:
                                DDR_print_mesg("Sample file not found on DDR server, trying to upload it...")
                                if DDR_upload_sample(idaapi.get_input_file_path()):
                                    DDR_print_mesg("File {} successfully uploaded.".format(idaapi.get_input_file_path()))
                            # all other errors
                            DDR_print_mesg("Failed to execute sample on server",2)
                            ret = False

                return ret

            # run sample in x64dbg (create x64dbg script)
            if cmd_id == 12:
                dump_para_json['id'] = cmd_id

                for upload_counter in range(DDR_CONFIG_SETTINGS.MAX_UPLOAD_ATTEMPTS, -1, -1):
                    with requests.post(url, verify=req_verify, json=dump_para_json, timeout=DDR_CONFIG_SETTINGS.MAX_API_TIMEOUT, stream=False) as res:
                        if res.status_code == 200:
                            DDR_print_mesg("Response: {}".format(res.json()["return_status"]))
                            ret = True
                            break
                        else:
                            if "Sample file not found" in res.json()["return_status"]:
                                DDR_print_mesg("Sample file not found on DDR server, trying to upload it...")
                                if DDR_upload_sample(idaapi.get_input_file_path()):
                                    DDR_print_mesg("File {} successfully uploaded.".format(idaapi.get_input_file_path()))
                            # all other errors
                            DDR_print_mesg("Failed to execute sample on server",2)
                            ret = False

                return ret


        except requests.exceptions.SSLError as e:
            DDR_print_mesg("[API SSL ERROR]: {}".format(e),2)
            DDR_print_mesg("Did you configure a valid serial number for the certificate ?",2)
            DDR_print_mesg("For troubleshooting install the certificate from the <IDA plugin dir>/ddr into your browser.",2)
            DDR_print_mesg("Access the DDR server test webpage with your browser and check the error message.",2)
            url = "https://" + DDR_CONFIG_SETTINGS.WEBSERVER + ":" + DDR_CONFIG_SETTINGS.WEBSERVER_PORT + "/"
            DDR_print_mesg("Reminder: Test webpage is {}".format(url),2)
            ret = False

        except requests.exceptions.ConnectionError as e:
            DDR_print_mesg("[API CONNECTION ERROR]: {}".format(e),2)
            DDR_print_mesg("Did you start and configure the DDR server script or is there any firewall inbetween ?",2)
            ret = False

        except requests.exceptions.HTTPError as e:
            DDR_print_mesg("[API HTTP ERROR]: {}".format(e),2)
            DDR_print_mesg("\nCMD execution failed. Check server side for details",2)
            ret = False

        except requests.exceptions.ReadTimeout as e:
            DDR_print_mesg("[API TIMEOUT ERROR]: {}".format(e),2)
            ret = False

        except ValueError as e:
            DDR_print_mesg("[API JSON ERROR] Failed to decode the returned JSON data from server: {}".format(e), 2)
            ret = False

        except:
            DDR_print_mesg("[API UNKNOWN ERROR] Unkown error happend. REST API request failed.",2)
            raise

        return ret

class ddrPlugin(idaapi.plugin_t):
    """
    The IDA plugin stub for DDR.
    """

    #
    # Plugin flags:
    # - PLUGIN_MOD: DDR may modify the database
    # - PLUGIN_PROC: Load/unload DDR when an IDB opens / closes
    # - PLUGIN_HIDE: Hide DDR from the IDA plugin menu
    #
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD 
    comment = "Dynamic Data Resolver Plugin"
    help = ""
    wanted_name = "DDR"
    wanted_hotkey = ""

    def activate(self,ctx):
        if sys.version_info > (3, 7):
            return 0
        return 1

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """     
        global REG_LIST
        global JSONFILE_DIR
        global DDR_API_V1_CONFIG_SETTINGS
        global SAMPLE_FILENAME
        global SAMPLE_SHA256
        global SAMPLE_DIR
            
        if not sys.version_info >= (3, 0):
            print("[DDR][WARNING] This script only supports Python 3. Install Python 3 64bit and use idapyswitch.exe to enable Python 3 for IDA.")
            print("[DDR][WARNING] DDR only support Python 3.7 and below in the moment due to http://www.hexblog.com/?cat=3.")
        
        if idaapi.IDA_SDK_VERSION < 750:
            if sys.version_info >= (3, 8):
                print("[DDR][ERROR] ------------------------------------------------------------------------------------------------")
                print("[DDR][ERROR] In IDA version below 7.5, the DDR plugin only supports Python 3.7 64 bit due to")
                print("[DDR][ERROR] http://www.hexblog.com/?cat=3. It is fine to use 3.8 on the DDR server side.")
                print("[DDR][ERROR] Unloading DDR plugin.")
                print("[DDR][ERROR] ------------------------------------------------------------------------------------------------")
                idaapi.warning("[DDR] Failed to load DDR plugin. Wrong Python version detected. Please see log for more details.")
                return idaapi.PLUGIN_SKIP   

        if DDR_CONFIG_SETTINGS.is_initalized == "PHASE1":
            print("[DDR][INFO] Configuration found.")
        else:
            print("[DDR][ERROR] Failed to initialze DDR configuration. Unloading Plugin.")
            return idaapi.PLUGIN_SKIP

        DDR_print_mesg("Activating plugin...")

        info = idaapi.get_inf_structure()
        orgfile = ida_nalt.get_input_file_path()

        try:
            SAMPLE_FILENAME         = idaapi.get_root_filename()
            #SAMPLE_SHA256           = ida_nalt.retrieve_input_file_sha256().decode()  # buggy itm, cuts the last byte of the hash
            SAMPLE_SHA256           = get_hash(orgfile)['sha256_sum']

            if orgfile:
                SAMPLE_DIR              = os.path.dirname(os.path.abspath(orgfile)) 
                DDR_CONFIG_SETTINGS.DUMP_CFG_FILE_WITHPATH  = SAMPLE_DIR + DDR_CONFIG_SETTINGS.DUMP_CFG_FILE

                if info.is_64bit():
                    DDR_CONFIG_SETTINGS.ARCH_BITS = 64
                    DDR_print_mesg("We are in a 64bit world...",0)
                    REG_LIST = ["xax","xbx","xcx","xdx","xsp","xbp","xsi","xdi","r8","r9","r10","r11","r12","r13","r14","r15"]
                elif info.is_32bit():
                    DDR_CONFIG_SETTINGS.ARCH_BITS = 32
                    DDR_print_mesg("We are in a 32bit world...",0)
                    REG_LIST = ["xax","xbx","xcx","xdx","xsp","xbp","xsi","xdi"]
                else:
                    #ERROR
                    DDR_CONFIG_SETTINGS.ARCH_BITS = 16
                    DDR_print_mesg("This plugin only supports 64/32bit enviroments and PE files. Unloading plugin.",2)
                    return idaapi.PLUGIN_SKIP

                DDR_API_V1_CONFIG_SETTINGS  = ddr_api_v1_cfg(BB_LIST)

            else:
                DDR_print_mesg("No input file loaded yet. Pls load a sample file into IDA")
                return idaapi.PLUGIN_SKIP
        except:
            DDR_print_mesg("Initalizing plugin failed.",2)
            raise
            return idaapi.PLUGIN_SKIP

        try:
            JSONFILE_DIR  = os.path.dirname(os.path.abspath(idaapi.get_input_file_path()))
        except:
            DDR_print_mesg("No input file loaded. Pls load a sample file into IDA")

        if not orgfile:
            DDR_print_mesg("No PE file loaded. Unloading plugin.",1)
            return idaapi.PLUGIN_SKIP

        try:
            pe = pefile.PE(orgfile)
        except:
            DDR_print_mesg("This plugin only supports PE files. Unloading plugin.",1)
            return idaapi.PLUGIN_SKIP

        if pe.is_dll():
            DDR_print_mesg("This plugin does not support DLLs in the moment.",1)
            return idaapi.PLUGIN_SKIP

        if not pe.is_exe():
            DDR_print_mesg("This plugin only supports PE files. Unloading plugin.",1)
            return idaapi.PLUGIN_SKIP
        
        # Register Menu Actions
        for m in menu_items:
            if DDR_CONFIG_SETTINGS.ARCH_BITS == 32:
                if menu_items[m]["x64only"]:
                    continue

            self._add_action(m, menu_items[m]["menu_str"], menu_items[m]["hotkey"], "DDR Tool", DDR_ida_action_handler(menu_items[m]["ah_id"]))

        # attach action to 'File/Load file/' menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",      # Relative path of where to add the action
            "DDR_Action_Load_file", # The action ID (see above)
            idaapi.SETMENU_APP      # We want to append the action after ^
        )
        if not result:
            idaapi.warning("[DDR] Failed to attach action (DDR_Action_Load_file) to main menu")
        else:
            DDR_print_mesg("Attached [DDR_Action_Load_file] to main menu", 7)

        # attach action(s) to the toolbar
        if idaapi.attach_action_to_toolbar("AnalysisToolBar", "DDR_Action_Load_file"):
            DDR_print_mesg("Action [DDR_Action_Load_file] attached to toolbar.", 7)
        else:
            idaapi.warning("[DDR] Failed to attach action [DDR_Action_Load_file] to toolbar.")


        # attach action to 'File/Load file/' menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",          # Relative path of where to add the action
            "DDR_Action_Load_api_file", # The action ID (see above)
            idaapi.SETMENU_APP          # We want to append the action after ^
        )
        if not result:
            idaapi.warning("[DDR] Failed to attach action (DDR_Action_Load_api_file) to main menu")
        else:
            DDR_print_mesg("Attached [DDR_Action_Load_api_file] to main menu", 7)

        # attach action(s) to the toolbar
        if idaapi.attach_action_to_toolbar("AnalysisToolBar", "DDR_Action_Load_api_file"):
            DDR_print_mesg("Action [DDR_Action_Load_api_file] attached to toolbar.", 7)
        else:
            idaapi.warning("[DDR] Failed to attach action [DDR_Action_Load_api_file] to toolbar.")

        # attach action(s) to context menu
        class Hooks(idaapi.UI_Hooks):
            #def finish_populating_tform_popup(self, form, popup):
            def finish_populating_widget_popup(self, form, popup):
                # register all menu items from global menu_item dict
                for m in menu_items:

                    if menu_items[m]["hide_in_context"]:
                        continue

                    if DDR_CONFIG_SETTINGS.ARCH_BITS != 64 and menu_items[m]["x64only"]:
                        continue

                    self._add_ida_popup(m, form, popup, "DDR/" + menu_items[m]["submenu"])

            def _add_ida_popup(self, act_name, form, popup, menuname):
                """
                Helper function to add a menu to the context menu in IDA if we are in the Disasm view
                """
                
                if ida_kernwin.get_widget_type(form) == idaapi.BWN_DISASM:
                    DDR_print_mesg("we are in DISASM view.",7)
                    if (idaapi.attach_action_to_popup(form, popup, act_name, menuname)):
                        DDR_print_mesg("added [{}] to context menu.".format(act_name),7)
                        pass
                    else:
                        idaapi.warning("[DDR] Failed to add [{}] to context menu.".format(act_name))

                else:
                   DDR_print_mesg("we are NOT in DISASM view.",7)
                   return False

                return True

        self.hooks = Hooks()
        if (self.hooks.hook()):
            DDR_print_mesg("All actions attached to context menu.",7)
        else:
            idaapi.warning("[DDR] Hooking context menu failed.")

        try:
            DDR_print_mesg("Done. DDR plugin started and initalized.")
            DDR_CONFIG_SETTINGS.is_initalized = "FULL"
            #logger.info("DDR plugin started")
            #DDR_print_mesg("Using Logfile: " + ddr_logfilename)
  
        except Exception as e:
            idaapi.warning("[DDR] init failed.")
            #logger.exception("Exception details:")
            return idaapi.PLUGIN_SKIP

        if not os.path.isfile(DDR_CONFIG_SETTINGS.CA_CERT):
            DDR_print_mesg("CA certificate file not found. Pls check the DDR_CONFIG_SETTINGS.CA_CERT variable in the ddr_plugin.py script. Fix it and restart IDA.",3)
            idaapi.warning("[DDR] CA file not found. Pls check the DDR_CONFIG_SETTINGS.CA_CERT variable in the ddr_plugin.py script. Fix it and restart IDA.")
            return idaapi.PLUGIN_SKIP

        # tell IDA to keep the plugin loaded (everything is okay)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.warning("[DDR] This plugin cannot be run as a script in IDA.")

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_FORM

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        try:
            # unregister all menues. ToDo: check if action is registered
            if DDR_CONFIG_SETTINGS.is_initalized == "FULL":
                for m in menu_items:            

                    if DDR_CONFIG_SETTINGS.ARCH_BITS == 16:    # actions are only registered for 32/64 bit enviroments at init 
                        break

                    if DDR_CONFIG_SETTINGS.ARCH_BITS != 64 and menu_items[m]["x64only"]:
                        continue

                    self._unregister_ida_action(m)

            DDR_print_mesg("plugin terminated.",7)
        except Exception as e:
            idaapi.warning("[DDR] Failed to cleanly unload DDR from IDA.")
            #logger.exception("Failed to cleanly unload DDR from IDA.")

    def _unregister_ida_action(self, act_name):
        """
        Helper function to unregister an IDA action
        """

        if idaapi.unregister_action(act_name):
            DDR_print_mesg("[{}] action unregistered from IDA.".format(act_name),7)
        else:
            idaapi.warning("Failed to unregister ({action_name}) action in IDA.".format(action_name=act_name)) 

    def _add_action(self, act_name, act_text, act_shortcut, act_tooltip, act_handler):
        """
        Helper function to add an action description to IDA
        """
        action_desc = idaapi.action_desc_t(
            act_name,                  # The action name
            act_text,                  # The action text
            act_handler,               # The action handler
            act_shortcut,              # Optional: action shortcut
            act_tooltip                # Optional: tooltip
                                       # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result: 
            idaapi.warning("[DDR] Failed to register action({action_name}) with IDA".format(action_name=act_name))

class DDR_MyChoose(idaapi.Choose):
    """ Chooser2 class to display Strings and API calls views"""
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False, columns=False):
        
        self.lines_n = []

        idaapi.Choose.__init__(
            self,
            title,
            columns,
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = items
        self.icon = -1
        #self.selcount = 0
        self.modal = modal
        #self.popup_names = ["Inzert", "Del leet", "Ehdeet", "Ree frech"]

    def OnClose(self):
        # Window closed
        DDR_print_mesg("Trace View window closed" , 7)
        pass

    def OnEditLine(self, n):
        # Click on "Edit.. menu"
        DDR_print_mesg("Not implemented.")

    def OnInsertLine(self):
        # Click on "Insert.. menu"
        DDR_print_mesg("Not implemented.")

    def OnDeleteLine(self, n):
        # Click on "Delete menu"
        del self.items[n]
        DDR_print_mesg("Line {:d} deleted.".format(n) , 7)
        return n

    def OnRefresh(self, n):
        # Click on "Refresh menu"
        DDR_print_mesg("Trace View window refreshed {:d}".format(n), 7)
        return n

    def OnSelectLine(self, n):
        # double click on line
        self.lines_n.append(n)
        DDR_print_mesg("Line: {:d}  Address: {}  Name:{}".format(n, str(self.items[n][0]), str(self.items[n][1])), 7)
        ea = int(self.items[n][1],16) 
        ida_kernwin.jumpto(ea)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        return t

    def OnGetLineAttr(self, n):
        # Highlight line 1 in blue:
        if n in self.lines_n:
            self.highlight_line = False
            return [0xFF0000, 0]
        
        return

    def show(self):
        return self.Show(self.modal) >= 0


# --- For future use Tree View Class  ---
#
#  tree_window = CBaseTreeViewer()
#  tree_window.Show("TreeView Tab Name")
#
class DDR_CBaseTreeViewer(idaapi.PluginForm):
    def populate_tree(self):
        # Clear previous items
        self.tree.clear()

    def OnCreate(self, form):
        # Get parent widget
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

        # Create tree control
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(("TreeWindowSubName",))
        self.tree.setColumnWidth(0, 100)

        # Create layout
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)

        TreeBranch1 = QtWidgets.QTreeWidgetItem(self.tree)
        TreeBranch1.setText(0, "TreeBranch1")
        TreeBranch1.ea = idc.BADADDR
        leaf1 = QtWidgets.QTreeWidgetItem(TreeBranch1)
        leaf1.setText(0, "{} {} {}".format("Leaf1.0","Leaf1.1","Leaf1.2"))
        leaf1.ea = idc.BADADDR
        leaf2 = QtWidgets.QTreeWidgetItem(TreeBranch1)
        leaf2.setText(0, "{} {} {}".format("Leaf2.0","Leaf2.1","Leaf2.2"))
        leaf2.ea = idc.BADADDR
        TreeBranch2 = QtWidgets.QTreeWidgetItem(self.tree)
        TreeBranch2.setText(0, "TreeBranch2")
        leaf3 = QtWidgets.QTreeWidgetItem(TreeBranch2)
        leaf3.setText(0, "{} {} {}".format("Leaf3.0","Leaf3.1","Leaf3.2"))
        leaf3.ea = idc.BADADDR

        # Populate PluginForm
        self.parent.setLayout(layout)

    def Show(self, title):
        return idaapi.PluginForm.Show(self, title, options = idaapi.PluginForm.FORM_PERSIST)

