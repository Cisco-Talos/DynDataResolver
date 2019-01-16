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

**Blog**

You can find an overview video and detailed installation instructions at:

https://blog.talosintelligence.com/2019/01/ddr.html

**Python Requirements**
<pre>
- Requests    (http://docs.python-requests.org)   # on the IDA machine (Analyst PC)
- Flask       (http://flask.pocoo.org/)           # only on the ddr_server.py machine (Malware host)
- PyOpenSSL   (https://pyopenssl.org/en/stable/)  # only on the ddr_server.py machine (Malware host)

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

**Disclaimer**  
Talos is releasing this alpha version knowing that it may contain a few bugs and can be improved upon in the future. Nevertheless, we think it is a useful tool that we want to share with the community at an early stage. Please see the source code for where to send issues, bug reports and feature requests. Feel free to contact the author if you run into issues.

**Roadmap**   
- Automatically copy sample file from IDA to DDRserver.py side  
- Manually enter logging address space range via 'Trace' context menu  
- Create separated config file  
- Return more info to plugin if sample execution returns and error  
- Kill DynamoRIO client after n seconds to fight sleepers  
- Get last n values for instructions which are executed multiple times  
- Improve input checks for user-provided data  
- Improve API implementation  
- Code cleanup needs to be better structured for easier implementation of new features.   

