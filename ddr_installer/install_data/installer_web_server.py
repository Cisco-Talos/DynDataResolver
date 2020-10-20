import flask
import json
import sys
import os
import shutil
import zipfile
import ctypes
from cheroot.wsgi import Server as WSGIServer

IDA_PLUGIN_ZIP = "ddr_plugin.zip"
MY_IP   = sys.argv[1]
MY_PORT = "80"

app = flask.Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

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

    webcontent = '''     
<html>
<header><title>DDR IDA Plugin Installer Website</title></header>
<body>
</br>
Hello DDR User,                                                                                                    </br>
                                                                                                                   </br>
Just download <a href="http://<MY_IP>:<MY_PORT>/get_plugin"><IDA_PLUGIN_ZIP></a>,                                  </br>
unzip it and execute the ida_plugin_installer.py script.                                                           </br>
                                                                                                                   </br>                                                                                                                                                                                                                            
</body>
</html>
''' 
    webcontent = webcontent.replace('<IDA_PLUGIN_ZIP>', IDA_PLUGIN_ZIP)  
    webcontent = webcontent.replace('<MY_IP>'         , MY_IP)
    webcontent = webcontent.replace('<MY_PORT>'       , MY_PORT)

    return webcontent

@app.route('/get_plugin', methods=['GET'])
def ddr_plugin_download():
    return flask.send_file(IDA_PLUGIN_ZIP, as_attachment=True)

def run_webserver():

    server = WSGIServer(bind_addr=(MY_IP, int(MY_PORT)), wsgi_app=app, numthreads=100) 

    print("[DDR_INSTALLER][INFO] ------------------------------------------------------------------------")
    print("[DDR_INSTALLER][INFO] Starting IDA plugin installation.")
    print("[DDR_INSTALLER][INFO] Please go to your IDA machine and point your browser to:\n")
    print("[DDR_INSTALLER][INFO] http://{}:{}\n".format(MY_IP,MY_PORT))
    print("[DDR_INSTALLER][INFO] Once you are done installing the IDA plugin, hit Ctrl-C here to stop the")
    print("[DDR_INSTALLER][INFO] webserver and proceed with the installation.")
    print("[DDR_INSTALLER][INFO] ------------------------------------------------------------------------")

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
    except:
        print("[DDR_INSTALLER][ERROR] Failed to start installation server. Please check if you")
        print("[DDR_INSTALLER][ERROR] have configured a valid NGINX IP address above.\n")
        raise

if __name__ == "__main__":

    run_webserver()
