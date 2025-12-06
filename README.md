# Don's System Monitor

Don's System Monitor is a unified system monitoring tool that can run in **host** mode (collecting system data and optionally serving it remotely) or **viewer** mode (connecting to a remote host and displaying its data).  
It is designed to work both for developers and for non-technical users who prefer running a single executable.

---

## What this project does (plain language)

- Shows CPU, RAM, disk usage, and temperature (when available)
- Detects high resource usage and possible memory leaks
- Can run:
  - Locally with a window
  - Headless in the background
  - Remotely, with another computer viewing the stats
- Uses one app for both **monitoring** and **viewing**

No internet services, no cloud, no telemetry.

---

## First-time users (non-developers)
Start by downloading the **EXE** from the Releases tab:
https://github.com/Ronnie-Reagan/Dons_System_Monitor/releases

1. Place the `.exe` in a folder where you want it to permanently live  
   (for example: Desktop or a utilities/tools folder)

2. Run the EXE once  
   - On first launch, it will automatically generate a file called `sysmon.config.json`

3. Open `sysmon.config.json` with a text editor such as Notepad and:
   - Set a secure value for `remote_password`
   - (Optional) Set `viewer_default` to true if this machine will only be used to view a remote system

4. Run the EXE again  
   - By default, it will start in host mode with a window
   - Close the window to exit the application

---

Running as a viewer only

If this computer should only connect to another system (viewer mode), edit `sysmon.config.json` and set:

- viewer_default = true  
- viewer_server_ip = IP address of the host machine  
- viewer_password = password configured on the host  

After that, simply double-click the EXE to run it whenever needed, including at startup.

---

Adding the application to Startup (Windows)

Follow these steps if you want the application to launch automatically when you log in:

1. Right-click the EXE  
2. Select Show more options  
3. Select Create shortcut  
4. Select the shortcut and press Ctrl+X  
5. Press Win+R, enter shell:startup, and press Enter  
   - Or manually navigate to:  
     `C:\Users\YOUR-USER-NAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
6. Press Ctrl+V or right-click and select Paste to place the shortcut in the Startup folder

After completing these steps, the application will start automatically when you log in.  
> If you move the original EXE after creating the shortcut, startup will stop working, as shortcuts are not dynamic.  
> If preferred, you may place the actual EXE directly in the Startup folder instead.
---

## First-time users (developers / _power users_)

If you are running from Python source:

Requirements:
- Python **3.11+** (tested up through **3.14**)
- **psutil** installed

Run examples:

Host mode with GUI:
```bash
python main.py --mode host
```
Host mode, headless:
```bash
python main.py --mode host --headless
```
Viewer mode:
```bash
python main.py --mode viewer
```
Viewer with overrides:
```bash
python main.py --mode viewer --server-ip 192.168.1.50 --server-port 34255 --password example --refresh-ms 1000
```
All CLI options override values in `sysmon.config.json`.

---

## Configuration file

`sysmon.config.json` is created automatically on first run.

It controls:
- Host/server behavior (bind address, port, password, thresholds)
- Viewer behavior (target IP, refresh rate, default mode)
- Headless vs GUI defaults

Passwords are never logged.

---

## Build notes

- The project supports PyInstaller single-file builds
- Intended to be built with `pyinstaller --onefile --windowed --name "Dons System Monitor" main.py`
  - Due to how PyInstaller creates a `.spec` file; you cannot use an apostrophe in the name
  - If a apostrophe is desired to denote ownership:
    - Build it normally without the apostrophe(s)
    - Open the `.spec` file to change the name under `exe[name]`
    - The single qoutes `'` must be replaced with double qoutes `"`
    - I.e. `name='Dons System Monitor',` -> `name="Don's System Monitor",`
- GUI is built with Tkinter for portability

---

## License

See LICENSE file.

---

This project prioritizes:
- Local control
- Transparency
- Low overhead
- Practical diagnostics over dashboards
