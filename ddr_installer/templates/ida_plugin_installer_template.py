import os
import sys
import subprocess
import shutil
from distutils import dir_util, file_util

# List of Python module dependencies
DEPS = ["requests", "pefile"]

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


def runcmd(my_cmd):
    """ 
    Execute shell command
    """

    print("[DDR_INSTALLER][INFO] Executing cmd: \n{}\n".format(my_cmd))

    stdout = False
    stderr = False

    try:
        process = subprocess.run(my_cmd)

        if process.returncode != 0:
            print("\n[DDR_INSTALLER][WARNING] Command execution failed. Error code: {:d}".format(process.returncode))
            ret = False
        else:
            ret = True
                    
    except :
        print("[DDR_INSTALLER][ERROR] Exception: Command execution failed with unknown error.")
        ret = False
    
    return ret

def install_deps(ida_python_path):
    """
    Main installer routine to install all neccessary 
    dependencies for DDR IDA plugin
    """

    ida_python_interpreter = ida_python_path + "\\python.exe"
    ida_python_pip         = ida_python_path + "\\Scripts\\pip.exe"

    # update pip in virtual enviroment
    pip_latest_version = False
    while pip_latest_version == False:
        print("[DDR_INSTALLER][INFO] Checking for pip in virtual enviroment...")
        my_cmd = ida_python_interpreter + " -m pip install --no-warn-script-location --upgrade pip" 
        if runcmd(my_cmd):
            print("[DDR_INSTALLER][INFO] pip tools upgraded/installed.\n")
            pip_latest_version=True
        else:
            print("\n[DDR_INSTALLER][ERROR] pip is not the latest version.")
            print("[DDR_INSTALLER][ERROR] Please update your pip tools manually first")
            print("[DDR_INSTALLER][ERROR] Installing/Updating the pip tools likely needs admin rights in your setup.")
            print("[DDR_INSTALLER][ERROR] Run a command prompt (cmd.exe) as administrator and enter:")
            print("[DDR_INSTALLER][ERROR] \"{}\\python.exe\" -m pip install --upgrade pip\n".format(ida_python_path))
            proceed("[DDR_INSTALLER][ERROR] Hit any key once you have updated pip.")
            
    # Install pip tools
    print("[DDR_INSTALLER][INFO] Installing pip-tools.")
    my_cmd = ida_python_pip + " install --no-warn-script-location --upgrade pip-tools" 
    if runcmd(my_cmd):
        print("[DDR_INSTALLER][INFO] pip-tools upgraded/installed.\n")
    else:
        print("\n[DDR_INSTALLER][ERROR] Failed to upgrad/install pip-tools.")
        return False

    # Install dependencies
    for m in DEPS:
        print("[DDR_INSTALLER][INFO] --- Installing {} ---".format(m))
        my_cmd = ida_python_pip + " install --no-warn-script-location --upgrade " + m 
        if runcmd(my_cmd):
            print("[DDR_INSTALLER][INFO] --- {} installed. ---\n".format(m))
        else:
            print("[DDR_INSTALLER][ERROR] Failed to install {}.\n".format(m))
            return False

# --- Main ---
if __name__ == "__main__":

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    mydir = os.path.realpath(__file__)
    print("\n[DDR_INSTALLER][INFO] Running from directory {}\n".format(mydir))

    ida_install_dir = r"<IDA_INSTALL_DIR>"
    ida_plugin_dir  = r"<IDA_PLUGIN_DIR>"
    ida_python_path = r"<IDA_PYTHON_PATH>"

    print("[DDR_INSTALLER][INFO] Using the following directories:")
    print("[DDR_INSTALLER][INFO] IDA install dir: {}".format(ida_install_dir))
    print("[DDR_INSTALLER][INFO] IDA plugin dir : {}".format(ida_plugin_dir))
    print("[DDR_INSTALLER][INFO] IDA Python dir : {}\n".format(ida_python_path))

    if os.path.isdir(ida_install_dir) == False: 
        print("[DDR_INSTALLER][ERROR] {} is not a directory.".format(ida_install_dir))
        exit(1)

    if os.path.isdir(ida_plugin_dir)  == False:
        # Doesn't exist or is no directory
        if os.path.exists(ida_plugin_dir): 
            print("[DDR_INSTALLER][ERROR] {} is not a directory.".format(ida_plugin_dir))
            exit(1)
        else:
            if proceed("[DDR_INSTALLER][WARNING] {} does not exist. Should I create it [Y/n] ?".format(ida_plugin_dir)):
                try:
                    os.makedirs(ida_plugin_dir)    
                    print("Directory {} successfully created.".format(ida_plugin_dir))
                except:
                    print("[DDR_INSTALLER][ERROR] Failed to create directory; {}" , ida_plugin_dir)
                    exit(1)

    if os.path.isdir(ida_python_path) == False:
        print("[DDR_INSTALLER][ERROR] {} is not a directory.".format(ida_python_path))
        exit(1)

    if os.path.isfile(ida_plugin_dir + "\\ddr_plugin.py"):
        print("[DDR_INSTALLER][INFO] IDA plugin exists at {}".format(ida_plugin_dir + "\\ddr_plugin.py"))
        if os.path.exists(ida_plugin_dir + "\\ddr"):
            print("[DDR_INSTALLER][INFO] IDA plugin directory exists at {}".format(ida_plugin_dir + "\\ddr"))
            print("[DDR_INSTALLER][INFO] If this is an update it is recommended to delete the old installation first.")
            if proceed("[DDR_INSTALLER][INFO] Should we delete it [Y/n] ?"):
                os.remove(ida_plugin_dir + "\\ddr_plugin.py")
                shutil.rmtree(ida_plugin_dir + "\\ddr")
                print("[DDR_INSTALLER][INFO] Old installation removed")

    # Install dependencies
    if proceed("[DDR_INSTALLER][INFO] Should we proceed with installing the Python module dependencies ? [Y/n]"):
        install_deps(ida_python_path)
            
    # Copy DDR files to plugin directory
    if proceed("[DDR_INSTALLER][INFO] Should we proceed with copying the DDR plugin files to the IDA plugin directory? [Y/n]"):
        print("[DDR_INSTALLER][INFO] Copying plugin files to {}...".format(ida_plugin_dir))
        flist = dir_util.copy_tree("ddr", ida_plugin_dir + "\\ddr")  
        for f in flist:
            print("[DDR_INSTALLER][INFO] File: {} copied.".format(f))

        f = file_util.copy_file("ddr_plugin.py", ida_plugin_dir + "\\ddr_plugin.py")
        print("[DDR_INSTALLER][INFO] File: {} copied.".format(f[0]))

        print("\nDone. Go back to the malware machine side and start the DDR server. By default: C:\\tools\\DDR\\ddr_server.py")
        print("(If you still have the DDR server installer open, it will do that for you if you hit Ctrl-C.)\n")
        print("Then start IDA and ... Happy reversing !\n")

    proceed("[DDR_INSTALLER][INFO] Hit any key to end installer.\n")


