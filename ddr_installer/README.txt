
Usual setup:
------------

  Analyst PC (IDA, ddr_plugin.py) 
             | 
             | IP network (Allow port DDR_CONFIG_SETTINGS.WEBSERVER_PORT (Default: 5000)
             |             in your firewall. There should be a pop when you run ddr_server.py)
             |             the first time during installation.
             V
  Malware PC (DynamoRio, ddr32.dll, ddr64.dll, ddr_server.py)
Notes:
------
Installing both the server and the plugin on the same PC, should work to, but is not 
recommended. Keep in mind that the malware sample is executed by the DynamoRio framework.


Installation:
-------------
Copy this directory to the Malware PC (ddr_server PC) and run DDR_INSTALLER.py.
The script will download all dependencies and create all necessary configuration files
for your environment. It will guide you through the whole installation process of the 
DDR server and IDA plugin.
It will not touch your local python environment, instead it creates a dedicated virtual 
Pyhton environment for all dependencies. It will also create individual cryptographic 
material for the SSL encrypted traffic between the DDR server and IDA plugin.

Pls report bugs and issues to hunterbr@cisco.com

===========================================================================================
You can find more infos at https://blog.talosintelligence.com/ search for DDR or Dynamic
Data Resolver to find the latest blog about DDR. It is highly recommended to read this blog
as far as DDR is a complex tool and without knowing some basics, it might be difficult to
use the tool in a proper way.
============================================================================================

Dependancies:
-------------

Python 3.x 

If you are using IDA < 7.5 you should use Python 3.7 on the IDA machine. This is due to a")
bug in IDA 7.4 which is fixed in 7.5. If you are using 7.5 we recommend to use Python 3.8.")
In any case it is recommended to use Python 3.8 for the DDR server machine. If it is the")
same machine, go for 3.7. Again, the latter setup is NOT recommended, better use two separate")
machines !")

See https://blog.talosintelligence.com/ for details.






