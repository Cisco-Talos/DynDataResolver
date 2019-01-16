#-------------------------------------------------------------------------------
#
#   IDA Pro Plug-in: Dynamic Data Resolver (DDR)
#   Version 0.1 alpha
#   Copyright (C) 2019 Cisco Talos
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
#   Flask       (http://flask.pocoo.org/)
#   PyOpenSSL   (https://pyopenssl.org/en/stable/)
#
#   e.g.
#   pip install -U Flask
#   pip install -U pyOpenSSL
#

import os
import time
import socket
import OpenSSL
import os
import string
import random
import tempfile
import flask
import time
import subprocess
import zipfile

app = flask.Flask(__name__)
#app.config["DEBUG"] = True

CERT_FILE   = r"ddr_server.crt"
KEY_FILE    = r"ddr_server.key"
APIKEY_FILE = r"ddr_apikey.txt"
MY_IPADDR   = r"192.168.100.122"
MY_PORT     = r"5000"
MY_FQDN     = r"malwarehost.local"
CONFDIR		= r"C:\Users\Dex Dexter\Documents\DDR_tool"

# verify directory ends with backslash
if not CONFDIR.endswith("\\"):
	CONFDIR += "\\"

CFG_DYNRIO_DRRUN_X32     = r"C:\tools\DynamoRIO-Windows-7.0.0-RC1\bin32\drrun.exe"
CFG_DYNRIO_CLIENTDLL_X32 = r"C:\Users\Dex Dexter\Documents\Visual Studio 2017\Projects\ddr\Release\\ddr.dll"
CFG_DYNRIO_DRRUN_X64     = r"C:\tools\DynamoRIO-Windows-7.0.0-RC1\bin64\drrun.exe" 
CFG_DYNRIO_CLIENTDLL_X64 = r"C:\Users\Dex Dexter\Documents\Visual Studio 2017\Projects\ddr\x64\Release\ddr.dll"

tmpdir = tempfile.gettempdir()

cert_file = CONFDIR + CERT_FILE
cert_key  = CONFDIR + KEY_FILE

@app.route('/api/v1/cmd', methods=['POST'])
def api_id():
	""" 
	API request handler
	"""

	# TBD improve imput checks
	if 'apikey' in flask.request.form:
		if flask.request.form['apikey'] == DDR_WEBAPI_KEY:
			pass
		else:
			return flask.jsonify({ "return_status" : "Error: Wrong API key" }), 201
	else:
		return flask.jsonify({ "return_status" : "Error: No API key given" }), 201


	if 'id' in flask.request.form:
		try:
			id = int(flask.request.form['id'])
		except:
			return flask.jsonify({ "return_status" : "Error: Failed to convert command id number" }), 201
	else:
		return flask.jsonify({ "return_status" : "Error: No id field provided. Please specify an id." }), 201


	if 'dynrio_sample' in flask.request.form:
		try:
			dynrio_sample = flask.request.form['dynrio_sample']
			if not os.path.isfile(dynrio_sample):
				print("[ERROR] Sample file not found. Did you copy it and/or configure the SERVER_LOCAL_SAMPLE_DIR in ddr_plugin.py properly ?")
				return flask.jsonify({ "return_status" : "Error: Sample file not found. Did you copy it and/or configure the SERVER_LOCAL_SAMPLE_DIR properly ?" }), 201
		except:
			return flask.jsonify({ "return_status" : "Error: Failed to convert command dynrio_sample number" }), 201
	else:
		return flask.jsonify({ "return_status" : "Error: No dynrio_sample field provided. Please specify an dynrio_sample." }), 201


	if 'start_addr' in flask.request.form:
		try:
			start_addr = int(flask.request.form['start_addr'])
		except:
			return flask.jsonify({ "return_status" : "Error: Failed to convert command start_addr number" }), 201
	else:
		return flask.jsonify({ "return_status" : "Error: No start_addr field provstart_addred. Please specify an start_addr." }), 201


	if 'end_addr' in flask.request.form:
		try:
			end_addr = int(flask.request.form['end_addr'])
		except:
			return flask.jsonify({ "return_status" : "Error: Failed to convert command end_addr number" }), 201
	else:
		return flask.jsonify({ "return_status" : "Error: No end_addr field provided. Please specify an end_addr." }), 201


	if 'instr_count' in flask.request.form:
		try:
			instr_count = int(flask.request.form['instr_count'])
		except:
			return flask.jsonify({ "return_status" : "Error: Failed to convert command instr_count number" }), 201
	else:
		return flask.jsonify({ "return_status" : "Error: No instr_count field provided. Please specify an instr_count." }), 201


	if 'arch_bits' in flask.request.form:
		try:
			arch_bits = int(flask.request.form['arch_bits'])
		except:
			return flask.jsonify({ "return_status" : "Error: Failed to convert command arch_bits" }), 201
	else:
		return flask.jsonify({ "return_status" : "Error: No arch_bits field provided. Please specify an arch_bits." }), 201


	if 'break_addr' in flask.request.form:
		try:
			break_addr = int(flask.request.form['break_addr'])
		except:
			break_addr = None
	else:
		break_addr = None

	if 'opt' in flask.request.form:
		try:
			opts = flask.request.form['opt']
			if opts == "light_trace_only":
				cmd_opts = "-t" 
		except:
			cmd_opts = None
	else:
		cmd_opts = None


	jsonfile_name = tmpdir + "\\" + "DDR_log_" + '.'.join(os.path.basename(dynrio_sample).split('.')[:-1]) 
	jsonfile_name += "_0x%x" % start_addr + "-" + "0x%x" % end_addr + "_%d" % instr_count + ".json" 

	# full analysis of sample file
	if id == 1: 
		print("API Id = 1 called - run full analysis")
		jsonfile_name_api = ".".join(jsonfile_name.split('.')[:-1]) + "_apicalls.json"
		filelist = [ jsonfile_name, jsonfile_name_api]
		zipfilename = ".".join(jsonfile_name.split('.')[:-1]) + ".zip"

		print("Client will try to download file: %s" % jsonfile_name)

		dyn_full = build_dynRio_full_run_cmd(start_addr=start_addr, 
											 end_addr=end_addr, 
											 instr_count=instr_count, 
											 jsonfile_name=jsonfile_name, 
											 dynrio_sample=dynrio_sample, 
											 arch_bits=arch_bits,
											 break_addr=break_addr)
		
		runstatus = runcmd(dyn_full)
		if runstatus['status'] == 'success':
			print("JSON instructions log file generated: %s" % jsonfile_name)    # TBD check if file exists
			print("JSON api calls log file generated: %s" % jsonfile_name_api)	 # TBD check if file exists

			print("Start zipping files to %s" % zipfilename)
			if zip_files(filelist, zipfilename):
				print("Start sending zip file back to client...")
				return flask.send_file(zipfilename, as_attachment=True)
			else:
				print("[ERROR] Failed to zip files")
				return flask.jsonify({ "return_status" : "Error: Failed to zip files on server side. Pls restart server and IDA" }), 201
				exit(1)
		else:
			return flask.jsonify({ "return_status" : "Error: Failed to run sample on server side. Pls restart server and IDA" }), 201
			exit(1)

	# Delete temp. logfiles of full analysis
	if id == 2: 
		print("API Id = 2 called - Delete tmp. analysis files")
		# build filename to delete
		jsonfile_name_api = ".".join(jsonfile_name.split('.')[:-1]) + "_apicalls.json"
		zipfilename = ".".join(jsonfile_name.split('.')[:-1]) + ".zip"
		print("Removing temp. files: \n%s,\n%s,\n%s" % (jsonfile_name, jsonfile_name_api, zipfilename))
		try:
			os.remove(jsonfile_name)
			os.remove(jsonfile_name_api)
			os.remove(zipfilename)
		except:
			print("[ERROR] Failed to delete tmp. file(s)")
			return flask.jsonify({ "return_status" : "Error: failed to delete tmp. files on server" }), 201

		print("Temp. log file deleted.")
		return flask.jsonify({ "return_status" : "success" })

	# Generate trace only logfiles
	if id == 3: 
		print("API Id = 3 called - run instruction address trace only")
		jsonfile_name_trace_only = ".".join(jsonfile_name.split('.')[:-1]) + "_trace-only.json"
		jsonfile_name_api_trace_only = ".".join(jsonfile_name_trace_only.split('.')[:-1]) + "_apicalls.json"
		jsonfile_name_api = ".".join(jsonfile_name.split('.')[:-1]) + "_apicalls.json"
		zipfilename = ".".join(jsonfile_name_trace_only.split('.')[:-1]) + ".zip"
		
		dyn_full = build_dynRio_full_run_cmd(start_addr=start_addr, 
											 end_addr=end_addr, 
											 instr_count=instr_count, 
											 jsonfile_name=jsonfile_name_trace_only, 
											 dynrio_sample=dynrio_sample, 
											 arch_bits=arch_bits,
											 break_addr=break_addr,
											 cmd_opts = cmd_opts )
		
		runstatus = runcmd(dyn_full)
		if runstatus['status'] == 'success':
			delete_target_file(jsonfile_name_api)
			os.rename(jsonfile_name_api_trace_only, jsonfile_name_api)
			filelist = [ jsonfile_name_trace_only, jsonfile_name_api]

			if zip_files(filelist, zipfilename):
				print("Start sending zip file back to client...")
				return flask.send_file(zipfilename, as_attachment=True)
			else:
				print("[ERROR] Failed to zip files")
				return flask.jsonify({ "return_status" : "Error: Failed to zip files on server side. Pls restart server and IDA" }), 201
				exit(1)
		else:
			print("[ERROR] Failed to execute command. Runstatus = %s" % runstatus['status'] )
			return flask.jsonify({ "return_status" : "Error: Failed to run sample on server side. Pls restart server and IDA" }), 201
			exit(1)

	# Delete trace-only tmp. file
	if id == 4: 
		print("API Id = 4 called - Delete tmp. trace only file")
		jsonfile_name_trace_only = ".".join(jsonfile_name.split('.')[:-1]) + "_trace-only.json"
		jsonfile_name_api = ".".join(jsonfile_name.split('.')[:-1]) + "_apicalls.json"
		zipfilename = ".".join(jsonfile_name_trace_only.split('.')[:-1]) + ".zip"
		try:
			os.remove(jsonfile_name_trace_only)
			os.remove(jsonfile_name_api)
			os.remove(zipfilename)
		except:
			print("[ERROR] Failed to delete temp. trace-only file(s):")
			return flask.jsonify({ "return_status" : "Error: failed to delete trace-only tmp. files on server" }), 201

		print("Temp. trace-only log files deleted")
		return flask.jsonify({ "return_status" : "success" })

	print("[ERROR] Invalid API call received: ID=%d" % id)
	return flask.jsonify({ "return_status" : "Error: Invalid API call received" }), 201

def delete_target_file(targetfile):

	if not os.path.isfile(targetfile):
		return

	os.remove(targetfile)

def zip_files(filelist, zipfilename):
	""" 
	Create ZIP file archive
	"""
	with zipfile.ZipFile(zipfilename, "w") as newzip:
		for filename in filelist:
			newzip.write(filename, os.path.basename(filename))

	return True


def create_self_signed_cert():
	"""
	Create self signed certificate and key if they do not exists
	"""

	if not os.path.exists(cert_file) or not os.path.exists(cert_key):
		# create a key pair
		k = OpenSSL.crypto.PKey()
		k.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)

		# create a self-signed cert
		cert = OpenSSL.crypto.X509()
		cert.get_subject().C  = "DE"                            		# country of residence
		cert.get_subject().ST = "Dortmund"                              # state of residence
		cert.get_subject().L  = "SomeLocality"                  		# locality
		cert.get_subject().O  = "Talos"                                 # organization 
		cert.get_subject().OU = "Security"                              # organizational unit 
		cert.get_subject().CN = MY_IPADDR                               # common name IP or FQDN
		san_list = ["IP:" + MY_IPADDR, "DNS:" + MY_IPADDR]  			# subjectAltName list
		cert.add_extensions([ OpenSSL.crypto.X509Extension("subjectAltName", False, ', '.join(san_list))])
		cert.set_serial_number(1001)
		cert.gmtime_adj_notBefore(0)
		cert.gmtime_adj_notAfter(10*365*24*60*60)
		cert.set_issuer(cert.get_subject())
		cert.set_pubkey(k)
		cert.sign(k, 'sha1')
		open(cert_file, "wt").write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
		open(cert_key,  "wt").write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k))

		print("\n--------------------------------------------------------------------------------")
		print("HINT: Self signed certificate and secret key generated. Make sure you protect the key.")
		print("      Copy the certificate file '%s' to the analyst machine." % cert_file)
		print("      (The machine where IDA with the DDR plugin is running on)")
		print("      This is usually only neccessary when you run this script the first time.")
		print("--------------------------------------------------------------------------------\n")
	else:
		print("\n--------------------------------------------------------------------------------")
		print("HINT: Existing certificate and key file found, certificate/key pair NOT generated !")
		print("      If you want to auto-generate a new key/cert pair, just delete the files: '%s'" % CERT_FILE)
		print("      and '%s' from this directory %s." % (KEY_FILE,CONFDIR))
		print("      This is usually only neccessary when you run this script the first time.")
		print("--------------------------------------------------------------------------------\n")

def create_apikey():
	""" 
	Read or generate API key
	"""
	key    = None
	apikey = CONFDIR + APIKEY_FILE

	try:	
		with open(apikey, 'r') as myfile:
			key=myfile.read().replace('\n', '')
		print("--------------------------------------------------------------------------------")
		print("HINT: Read API Key from file %s." % apikey)
		print("      If you want to auto-generate a new API key, just delete the file: %s" % apikey)
		print("      from the directory %s" % CONFDIR)
		print("      This is usually only neccessary when you run this script the first time.")
		print("--------------------------------------------------------------------------------\n")

	except:
		if not key:
			key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(24))
			with open(apikey, "w") as text_file:
				text_file.write("%s" % key)
			print("--------------------------------------------------------------------------------")
			print("Generated new API Key and wrote it to file %s" % apikey)
			print("--------------------------------------------------------------------------------\n")

	return key

def runcmd(my_cmd):
	""" 
	Execute shell command
	"""
	print("CMD to execute: %s" % " ".join(my_cmd))

	stdout = False
	stderr = False

	cmd_ret = { 'status' : False, 'stdout' : None, 'stderr' : None}
	cmd_ret['status'] = 'success'

	try:
		process = subprocess.Popen(" ".join(my_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = process.communicate()

		if process.returncode != 0:
			print("[WARNING] Command execution failed. Error code: %d" % process.returncode)
			#cmd_ret['status'] = 'failed - return code not 0'


		if stderr:
			print("[WARNING] Command execution failed. Stderr:\n----\n%s\n----" % stderr)
			#cmd_ret['status'] = 'failed - stderr set'

		if stdout:
			print("Command execution stdout:\n----\n%s\n----" % stdout)
			cmd_ret['stdout'] =  stdout
		
	except :
		print("Exception: Command execution failed with unknown error")
		cmd_ret['status'] = 'failed - unknown error/exception'
	
	return cmd_ret

def build_dynRio_full_run_cmd(start_addr=None, end_addr=None, break_addr=None, instr_count=None, jsonfile_name=None, dynrio_sample=None, arch_bits=None, cmd_opts=None):
	""" 
	Build shell cmd line for DynamoRIO drrun.exe -c DDR.dll ...
	"""
	if start_addr == None or end_addr == None or instr_count == None or jsonfile_name==None or arch_bits==None:
		print("jsonfile_name, start_addr, end_addr, arch_bits or instr_count not set")
		return False

	if arch_bits == 32:
		dynrio_client_x32        = CFG_DYNRIO_CLIENTDLL_X32
		dynrio_cmd_x32           = [CFG_DYNRIO_DRRUN_X32]
		dynrio_cmd_x32.append("-c")
		dynrio_cmd_x32.append("\"" + dynrio_client_x32 + "\"")
		dynrio_cmd_x32.append("-s")
		dynrio_cmd_x32.append("0x%x" % start_addr)
		dynrio_cmd_x32.append("-e")
		dynrio_cmd_x32.append("0x%x" % end_addr)
		dynrio_cmd_x32.append("-c %d" % instr_count)
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
		dynrio_cmd_x64.append("0x%x" % start_addr)
		dynrio_cmd_x64.append("-e")
		dynrio_cmd_x64.append("0x%x" % end_addr)
		dynrio_cmd_x64.append("-c %d" % instr_count)
		dynrio_cmd_x64.append("-f")
		dynrio_cmd_x64.append("\"" + jsonfile_name + "\"")
		if cmd_opts:
			dynrio_cmd_x64.append(cmd_opts)
		dynrio_cmd_x64.append("--")
		dynrio_cmd_x64.append("\"" + dynrio_sample + "\"")
		return dynrio_cmd_x64

def check_config_files_exist(files, dirs):
	ret = True
	
	for dir in dirs:
		if not os.path.isdir(dir):
			print("[ERROR] Directory: %s not found." % dir)
			ret = False

	for fname in files:
		if not os.path.isfile(fname):
			print("[ERROR] File: %s not found." % fname)
			ret = False

	return ret

if __name__ == "__main__":

	# check for config errors
	if not check_config_files_exist([CFG_DYNRIO_DRRUN_X32,CFG_DYNRIO_CLIENTDLL_X32,CFG_DYNRIO_DRRUN_X64,CFG_DYNRIO_CLIENTDLL_X64], [CONFDIR]):
		exit(1)

	# Create self signed certificate for TLS communication 
	create_self_signed_cert()

	# Create API key
	global DDR_WEBAPI_KEY 
	webkey = create_apikey()
	DDR_WEBAPI_KEY = webkey

	print("--------------------------------------------------------------------------------")
	print("TODO: Make sure you have edited the DDR_WEBAPI_KEY in the DDR_plugin.py script. ")
	print("      Using DDR_WEBAPI_KEY = %s" % DDR_WEBAPI_KEY)
	print("      This is usually only neccessary when you run this script the first time.")
	print("--------------------------------------------------------------------------------\n")

	# Run API web server
	app.run(ssl_context=(cert_file, cert_key), host=MY_IPADDR, port=MY_PORT)

