# Dynamic Data Resolver (DDR) IDA Pro Plug-in

Version 0.1 alpha

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

**Common setup**
<pre>
Analyst PC (IDA, ddr_plugin.py) 
         | 
         | IP network
         |
         | IP addr = [WEBSERVER/WEBSERVER_PORT (ddr_plugin.py header)]
Malware PC (DynamoRio, ddr.dll, ddr_server.py, sample.exe)
           MALWARE DIR = 
           [ SERVER_LOCAL_SAMPLE_DIR (in ddr_plugin.py) = Folder you copied the sample file to on the Malware host] 
</pre>

**Installation**

Drag and drop *ddr_plugin.py* into IDA Pro's plugin folder for IDA Pro 7.x and higher
e.g. C:\Program Files\IDA 7.x\plugins (on your analyst PC)

Copy *ddr_server.py* and *ddr.dll* to a remote PC where you want to run the malware sample
against the DynamoRIO DDR client e.g. C:\Users\<name>\Documents\DDR_files

The IDA *ddr_plugin.py* is the frontend for the ddr_server.py which executes the 
DynamoRio DDR client (*ddr.dll*) via DynamoRio *ddrun.exe* to instrument and analyze the 
malware sample

**It is highly recommended to run the *ddr_server.py* on a different PC.
WARNING: Keep in mind the DynamoRio client is executing the sample !!!**

Make sure you have changed the variables e.g. MY_IPADDR in the *ddr_server.py* 
script header regarding your local setup. The *ddr_server.py* will generate 
a self-signed certificate/key pair and an API key, when you start it the first time. 
It writes those into the config directory (set in the ddr_server.py header CONFDIR variable).

**ToDo** 
- Automatically copy sample file from IDA to DDRserver.py side
- Kill DynamoRIO client after time x to fight sleepers 
- Improve input checks for user provided data
