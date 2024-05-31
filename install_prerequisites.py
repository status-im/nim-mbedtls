import subprocess
import sys
import os

def run_command(command):
    try:
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
        sys.exit(1)

def install_pip():
    print("Installing pip...")
    get_pip_script = "get-pip.py"
    try:
        run_command(f"curl https://bootstrap.pypa.io/get-pip.py -o {get_pip_script}")
        run_command(f"{sys.executable} {get_pip_script}")
    except Exception as e:
        print(f"Failed to install pip: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(get_pip_script):
            os.remove(get_pip_script)

def check_and_install(package, version):
    try:
        pkg = __import__(package)
        installed_version = pkg.__version__
        if installed_version != version:
            print(f"Updating {package} to version {version}.")
            run_command(f"{sys.executable} -m pip install {package}=={version}")
        else:
            print(f"{package} {version} is already installed.")
    except ImportError:
        print(f"Installing {package} {version}.")
        run_command(f"{sys.executable} -m pip install {package}=={version}")

def main():
    # Check if pip is installed
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
    except subprocess.CalledProcessError:
        install_pip()

    # Check and install Jinja2 and jsonschema
    check_and_install("jinja2", "2.10.1")
    check_and_install("jsonschema", "3.2.0")

if __name__ == "__main__":
    main()
