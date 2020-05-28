import flask
import json
import sys
import os
import shutil
import zipfile
import ctypes
from cheroot.wsgi import Server as WSGIServer

MY_PORT = "80"
PLUGIN_INSTALL_DIR  = "DDR_IDA_plugin_install"
PLUGIN_CFG_TEMPLATE = "templates\\ddr_config_template.json"
IDA_DIR             = "C:\\Program Files\\IDA Pro 7.5"
IDA_PLUGIN_ZIP      = PLUGIN_INSTALL_DIR + ".zip"

app = flask.Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# DDR server configuration file
DDR_SERVER_CFG = sys.argv[1]      # e.g. C:\tools\DDR\ddr_server.cfg

with open(DDR_SERVER_CFG, 'r') as handle:
    ddrserver_cfg = json.load(handle)

DDR_SERVER_VERSION       = ddrserver_cfg["DDR_SERVER_VERSION"]          # e.g. "1.0"
FLASKLOGGING             = ddrserver_cfg["APILOGGING"]                  # e.g. (NORMAL,MEDIUM,DEBUG)
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

# prevent cached responses. Sets no-cache parameters header for every flask response.
@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

@app.route('/', methods=['GET'])
def ddr_plugin_installation():

    IDA_PLUGIN_ZIP

    webcontent = '''     
<html>
<header><title>DDR IDA Plugin Installer Website</title></header>
<body>
</br>
Hello DDR User,                                                                                                    </br>
                                                                                                                   </br>
<b>Hint: Read the whole text and don't forget to install the dependencies (see below) !</b>                        </br>
                                                                                                                   </br>
Just download <a href="http://<MY_IP>:<MY_PORT>/get_plugin"><IDA_PLUGIN_ZIP></a>,                                  </br>
Unzip it and copy the content of the unpacked folder to your IDA plugins directory.</br>                           </br>
In other words, copy the 'ddr_plugin.py' and the 'ddr' folder to e.g.                                              </br>
<i>C:\\Program Files\\IDA Pro 7.4\\plugins\\ddr_plugin.py</i>                                                      </br>
<i>C:\\Program Files\\IDA Pro 7.4\\plugins\\ddr</i>                                                                </br>
                                                                                                                   </br>
<b>Make sure you have the Python requests and pefile modules installed for the Python version                      </br>
your IDA installation is using (see below). </b>                                                                   </br>
                                                                                                                   </br>
-------------------------------------------------------------------------------------------------------------      </br>
!!! Reminder: DDR only supports Python 3 !!!                                                                       </br>
                                                                                                                   </br> 
<b>Due to the <a href="https://www.hexblog.com/?cat=8">IDA Python 3.8 issue</a> you should use Python 3.7 for      </br>
IDA below version 7.5. IDA 7.5 and above have fixed this issue. In any case, using Python 3.8 for the DDR          </br> 
server side is fine and recommended.)</b>                                                                          </br>
-------------------------------------------------------------------------------------------------------------      </br>
                                                                                                                   </br>
# Verify which Python version your IDA installation is using e.g.                                                  </br>
<i>"C:\\Program Files\\IDA Pro 7.5\\idapyswitch.exe"                                                               </br>
...                                                                                                                </br>
Found: "C:\\Program Files\\Python38\\" (version: 3.8.2 ('3.8.2150.1013'))                                          </br>
...                                                                                                                </br>
CTRL-C</i>                                                                                                         </br>
                                                                                                                   </br>
# Install the requests and pefile module for that version. 														   </br>
(If neccessary, open a cmd window via 'Run as administrator'):													   </br>
                                                                                                                   </br>
<i>"C:\\Program Files\\Python38\\python.exe" -m pip install --upgrade pip                                          </br>
                                                                                                                   </br>
"C:\\Program Files\\Python38\\Scripts\\pip.exe" install -U requests                                                </br>
                                                                                                                   </br>
"C:\\Program Files\\Python38\\Scripts\\pip.exe" install -U pefile</i>                                              </br>
                                                                                                                   </br>
                                                                                                                   </br>
<b>Once you are done installing the plugin and its dependencies, switch back to the server machine finish          </br>
the installation and start the DDR server.                                                                         </br>
                                                                                                                   </br>
After the installer script has started the DDR Server, you can test if the server is reachable from the IDA        </br>
machine by clicking the following link: </b>                                                                       </br>
                                                                                                                   </br>
<a href="https://<SERVER_IP>:<SERVER_PORT>/">Link to DDR Server test page</a>                                      </br>
                                                                                                                   </br>
Details on how to use DDR can be found <a href="https://blog.talosintelligence.com/">here</a>.                     </br>
Search for DDR or Dynamic Data Resolver.                                                                           </br>
																												   </br>
<b>For a quick test, launch IDA, load a sample and check the IDA log window, if DDR was successfully initialized.  </br>
</b>                                                                                                               </br>                                                                                                                                                                                                                            
</body>
</html>
''' # TBD: add URL to blog
    webcontent = webcontent.replace('<IDA_PLUGIN_ZIP>', IDA_PLUGIN_ZIP)
    webcontent = webcontent.replace('<MY_IP>'         , SERVER_IP)
    webcontent = webcontent.replace('<MY_PORT>'       , MY_PORT)
    webcontent = webcontent.replace('<SERVER_IP>'     , SERVER_IP)
    webcontent = webcontent.replace('<SERVER_PORT>'   , SERVER_PORT)

    return webcontent


@app.route('/get_plugin', methods=['GET'])
def ddr_plugin_download():
    #my_path  = os.path.dirname(os.path.realpath(__file__))
    #filename = IDA_PLUGIN_ZIP
    #return flask.send_from_directory(directory=my_path, filename=filename, as_attachment=True)
    return flask.send_file("..\\" + IDA_PLUGIN_ZIP, as_attachment=True)


def zip_files(filelist, zipfilename):
    """ 
    Create ZIP file archive
    """
    with zipfile.ZipFile(zipfilename, "w") as newzip:
        for filename in filelist:
            newzip.write(filename, os.path.basename(filename))

    return True

if __name__ == "__main__":

    print("[DDR_INSTALLER][INFO] IDA plugin installation started.\n")

    print("[DDR_INSTALLER][INFO] Please enter your IDA directory (on your analyst machine)")
    IDA_DIR = input("[DDR_INSTALLER][INFO] (Default: {}) : ".format(IDA_DIR)) or IDA_DIR
    IDA_PLUGIN_DIR = IDA_DIR + "\\plugins"
    IDA_PLUGIN_DIR = IDA_PLUGIN_DIR.replace("\\", "\\\\")

    # copy plugin, cert and apikey files
    filename_list = [ "ddr_server.crt" ]
    os.makedirs(os.path.dirname(PLUGIN_INSTALL_DIR + "\\ddr\\"), exist_ok=True)
    for fn in filename_list:
        shutil.copyfile(CONFDIR + "\\" + fn, PLUGIN_INSTALL_DIR + "\\ddr\\" + fn)
        print("[DDR_INSTALLER][INFO] Copied file: {}".format(fn))

    shutil.copyfile("plugin\\ddr_plugin.py", PLUGIN_INSTALL_DIR + "\\ddr_plugin.py")

    # Get API key
    with open(CONFDIR + "\\" + APIKEY_FILE, 'r') as apifile:
            apikey=apifile.read().replace('\n', '')

    # Create DDR plugin config file
    with open(PLUGIN_CFG_TEMPLATE, 'r') as f:
            ddrplugin_cfg_file = f.read()

    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<WEBSERVER>"           , SERVER_IP)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<WEBSERVER_PORT>"      , SERVER_PORT)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<DDR_WEBAPI_KEY>"      , apikey)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<CA_CERT>"             , IDA_PLUGIN_DIR + "\\\\ddr\\\\" + CERT_FILE)
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<VERIFY_CERT>"         , "true")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<DUMP_CFG_FILE>"       , "tmp_dump.cfg")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_API_TIMEOUT>"     , "30.0")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<DBG_LEVEL>"           , "2")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_INSTR_TO_EXECUTE>", "20000")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_LOG_ROUNDS>"      , "5")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_CMT_ROUNDS>"      , "3")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_INSTR_COUNT>"     , "50")
    ddrplugin_cfg_file = ddrplugin_cfg_file.replace("<MAX_UPLOAD_ATTEMPTS>" , "3")

    ddrplugin_cfg_filename = PLUGIN_INSTALL_DIR + "\\ddr\\ddr_config.json" 

    with open(ddrplugin_cfg_filename, 'w') as f:
        f.write(ddrplugin_cfg_file)

    try:
        res = shutil.make_archive(PLUGIN_INSTALL_DIR, 'zip', PLUGIN_INSTALL_DIR)
    except:
        raise

    server = WSGIServer(bind_addr=(SERVER_IP, int(MY_PORT)), wsgi_app=app, numthreads=100) 

    print("[DDR_INSTALLER][INFO] ------------------------------------------------------------------------")
    print("[DDR_INSTALLER][INFO] Please go to your IDA machine and point your browser to:\n")
    print("[DDR_INSTALLER][INFO] http://{}:{}\n".format(SERVER_IP,MY_PORT))
    print("[DDR_INSTALLER][INFO] Once you are done installing the IDA plugin, hit Ctrl-C here to proceed.")
    print("[DDR_INSTALLER][INFO] ------------------------------------------------------------------------")

    msg  = "Click ok to start the webserver, then go to your IDA machine and point your browser to:\n\n"  
    msg += "http://{}:{}\n\n".format(SERVER_IP,MY_PORT)  
    msg += "Make sure you are following the instructions shown on the webpage\n"  
    msg += "Once you are done installing the IDA plugin, hit Ctrl-C in\n"  
    msg += "the installer script cmd window to proceed with the installation.\n"
    msg += "After some final checks, the script will start the DDR server and\n"
    msg += "you can start using the IDA plugin.\n"

    ctypes.windll.user32.MessageBoxW(0, msg, "DDR Installer", 0) 

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
    except:
        print("[DDR_INSTALLER][ERROR] Failed to start installation server. Please check if you")
        print("[DDR_INSTALLER][ERROR] have configured a valid NGINX IP address above.\n")
        raise

    exit(0)