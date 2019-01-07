# Dynamic Data Resolver (DDR) IDA Pro Plug-in

Version 0.1 alpha

Tested on IDA 7.2

Copyright (C) 2019 Cisco Talos
Autor: Holger Unterbrink (hunterbr@cisco.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

**Python Requirements**
<pre>
- Requests    (http://docs.python-requests.org)   # on IDA machine (Analyst PC)
- Flask       (http://flask.pocoo.org/)           # only on ddr_server.py machine (Malware host)
- PyOpenSSL   (https://pyopenssl.org/en/stable/)  # only on ddr_server.py machine (Malware host)

e.g.  
pip install -U requests  
pip install -U Flask  
pip install -U pyOpenSSL  
</pre>

**Other Requirements**
<pre>
- DynamoRIO (https://www.dynamorio.org/) # only on ddr_sever.py machine (Malware host)
</pre>

Hint: Make sure you install these requirements for the same Python version IDA is using. 

**Common setup and usage**
<pre>
Analyst PC (IDA, ddr_plugin.py) - The PC you are running IDA on.
         | 
         | SSL connection
         |
         | IP addr = [WEBSERVER/WEBSERVER_PORT (in ddr_plugin.py header)]
Malware PC (DynamoRio, ddr.dll, ddr_server.py, sample.exe) - The PC you are executing the malware on.
           MALWARE DIR = 
           [ SERVER_LOCAL_SAMPLE_DIR (in ddr_plugin.py) = Folder you copied the sample.exe file to on the Malware host] 
</pre>

The IDA *ddr_plugin.py* is the frontend for the *ddr_server.py* backend which executes the 
DynamoRio DDR client (*ddr.dll*) on the command line via the DynamoRio *drrun.exe* tool. 
The result is then send back to the *ddr_plugin.py*. The *ddr_plugin.py* frontend and the 
*ddr_server.py* backend are communicating over an encrypted SSL tunnel. The server authentication 
is done via a certificate, the client authentication is done via the API key.

You can do the same process described above also manually by running the drrun.exe tool on the command line e.g.

<pre>
<DYNAMORIO_INSTALL_DIR>\bin32\drrun.exe -c "<PATH_TO_DLL>\ddr.dll" -s 0x401190 -e 0x4011fb -c 20000 -f "<YOUR_LOGGING_DIR>\DDR_log_sample_x32_0x401190-0x4011fb_20000.json" -- "<PATH_TO_SAMPLE>\sample_x32.exe"
</pre>

Then load the *DDR_log_sample_x32_0x401190-0x4011fb_20000.json* logfile into IDA via *File/LoadFile/LoadDynRioFile*, 
but it is probably much easier to use the automatic process via the IDA plugin menu e.g. DDR/Trace/Run... as
described above.

Anyway the manual process might be handy if you want to run the malware sample on a 100% disconnected PC or if
you want to execute it against a address range which is not supported in the menu.

All features provided by the plugin are accessible via the right click context menu 'DDR' in the IDA assembler/graph view. 
You always have to run/load a trace (file) first (e.g. DDR/Trace/Run...), before you pick one of the menu entries. 
Keep in mind that all features are working against the trace file you have loaded. This means e.g. if you are selecting the 
string view menu entry, you are only seeing the strings which are in that trace file or in other words in the address 
range or instruction count you used for generating this trace file. All trace run via the DDR menu are cached in the same 
directory like the sample is, if you want to regenerate them you have to delete the cache first via the DDR/Trace menu or
delete the files manually.

**Installation/Usage**

As usual, just drag and drop the *ddr_plugin.py* into IDA Pro's plugin folder, for IDA Pro 7.x and higher
e.g. C:\Program Files\IDA 7.x\plugins (on your analyst PC).

Copy *ddr_server.py*, *ddr.dll* and the malware sample e.g. *sample.exe* to a remote PC directory. In other words, to the PC 
where you want to run the malware sample against the DynamoRIO DDR client on e.g. Remote PC: C:\Users\<name>\Documents\DDR_files\. Install DynamoRIO on this remote PC, too and change the CFG_DYNRIO_DRRUN_X32 and the other variables in the *ddr_server.py* file to the right paths corrosponding to your setup.

**It is highly recommended to run the *ddr_server.py* on a different PC.
WARNING: Keep in mind the DynamoRio client is executing the sample !!!**

Make sure you have *changed the variables* e.g. MY_IPADDR etc, in the *ddr_server.py* script header, 
*before you start the *ddr_server.py* the first time*. The *ddr_server.py* will generate 
a self-signed certificate/key pair and an API key, when you start it the first time. 
It writes those files into the config directory (set in the ddr_server.py header CONFDIR variable).
You should copy over the certificate file to the Analyst PC and set it's path in the *ddr_plugin.py* script header variable.
Also modify the other variables based on your setup. Don't forget to copy the API key value into the DDR_WEBAPI_KEY variable. 

**ToDo** 
- Automatically copy sample file from IDA to DDRserver.py side (P1)
- Kill DynamoRIO client after time x to fight sleepers (P2)
- Improve input checks for user provided data (P3)
