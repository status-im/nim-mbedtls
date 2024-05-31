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

def main():
  try:
    subprocess.check_call([sys.executable, "-m", "pip", "--version"])
  except subprocess.CalledProcessError:
    install_pip()

  # Check and install Jinja2 and jsonschema
  requirements_file = os.path.join(os.path.dirname(__file__),
          'mbedtls/csources/scripts/driver.requirements.txt')
  run_command(f"{sys.executable} -m pip --quiet install -r {requirements_file}")


if __name__ == "__main__":
  main()
