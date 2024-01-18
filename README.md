# trustpoint-client

## Installation
1. Clone git repo: https://github.com/TrustPoint-Project/trustpoint-client
2. Change into the trustpoint-client directory
   ```
   cd trustpoint-client
   ```
3. Install virtual environment and required dependencies
    ```
   sudo apt install python3-venv
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
4. Execute program
   Note that trustpoint_client executed below is the directory (as package), not the trustpoint_client.py file
   ```
   python3 -m trustpoint_client
   python3 -m trustpoint_client provision --otp abc --salt fgh --url xyz
   ```
