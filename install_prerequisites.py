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
  get_pip_script = "get-pip.py"
  try:
    run_command(f"curl -s https://bootstrap.pypa.io/get-pip.py -o {get_pip_script}")
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
      run_command(f"{sys.executable} -m pip --quiet install {package}=={version}")
  except ImportError:
    run_command(f"{sys.executable} -m pip --quiet install {package}=={version}")

def main():
  try:
    subprocess.check_call([sys.executable, "-m", "pip", "--version"])
  except subprocess.CalledProcessError:
    install_pip()

  # Check and install Jinja2 and jsonschema
  check_and_install("jinja2", "2.10.1")
  check_and_install("jsonschema", "3.2.0")

if __name__ == "__main__":
  main()
