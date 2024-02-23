<p align="center">
  <img alt="Trustpoint Client" src="/.github-assets/trustpoint_client_banner.png"><br/>
  <strong>The secure user-driven onboarding utility for Trustpoint.</strong><br/><br/>
  <a href="https://github.com/orgs/TrustPoint-Project/trustpoint"><img src="https://img.shields.io/badge/Looking_for_the_main_repo%3F-014BAD?style=flat"></a>
  <a href="https://github.com/orgs/TrustPoint-Project/discussions"><img src="https://img.shields.io/badge/GitHub-Discussions-014BAD?style=flat"></a>
  <img src="https://img.shields.io/badge/License-None-red?style=flat">
  <img src="https://img.shields.io/badge/Status-Early_technology_preview-red?style=flat">
</p>

> [!CAUTION]
> Trustpoint Client is currently in an **early technology preview** (alpha) state. Do not use it in production.

## What is Trustpoint Client?

Trustpoint Client allows you to onboard devices to Trustpoint, which encompasses retrieving the trust store, and requesting and downloading a digital identity (LDevID) and its associated certificate chain.
All you need is a command line interface on your device, and a recent version of python.

> [!WARNING]
> Please only onboard devices to your network you are sure you can trust.

## Installation

### Method 1: Directly from Trustpoint (TBD)

Just download the package from Trustpoint during onboarding and transfer it to the device, e.g. via SCP or a USB drive.

### Method 2: From GitHub

1. Clone git repo: https://github.com/TrustPoint-Project/trustpoint-client
2. Change into the trustpoint-client directory
   ```bash
   cd trustpoint-client
   ```
3. Install virtual environment and required dependencies
    ```bash
   sudo apt install python3-venv
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
4. Execute program
   Trustpoint will generate and display the exact command for you during the onboarding process.

   Note that trustpoint_client executed below is the directory (as package), not the trustpoint_client.py file
   ```bash
   python3 -m trustpoint_client
   python3 -m trustpoint_client provision --otp abc --salt fgh --url xyz
   ```

## Where is the license?

There is no explicit license yet. All rights reserved.

Currently Trustpoint is in an early technology preview state.  
We are still deciding on the most appropriate open source license, as that is hard or impossible to change down the line. Potential candidates include the EUPL-1.2, a GPL flavor or a more permissive license like MPL or MIT.

You may download, view, and use Trustpoint free of charge for testing and evaluation purposes, however you MUST NOT redistribute Trustpoint or a Derivative Work based on it. Use outside of testing and evaluation is heavily discouraged.  
You may contribute to the project, however in doing so you accept your contributions to be relicensed under any license of the author's choosing.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.  