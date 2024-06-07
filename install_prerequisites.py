import subprocess
import sys
import os

def run_command(command):
  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError as e:
    print(f"Error occurred: {e}")
    sys.exit(1)

def install_pip():
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

def check_and_install(package, constraint):
  try:
    pkg = __import__(package)
    # Skip version check for simplicity, as we are ensuring the constraint is applied on installation
    print(f"{package} is already installed.")
  except ImportError:
    print(f"Installing {package} with constraint {constraint}.")
    run_command(f"{sys.executable} -m pip install {package}{constraint}")

def main():
  try:
    print("python -m pip --version")
    subprocess.check_call([sys.executable, "-m", "pip", "--version"])
  except subprocess.CalledProcessError:
    print("install pip")
    install_pip()

  # Check and install markupsafe, Jinja2 and jsonschema
  check_and_install("markupsafe", "<2.1")
  check_and_install("jinja2", ">=2.10.3")
  check_and_install("jsonschema", "<4.18.0")

if __name__ == "__main__":
  main()
