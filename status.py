import os
import json
import atexit
import subprocess
import re
import logging
from collections import defaultdict
from waitress import serve
from pathlib import Path
from flask import Flask, jsonify, render_template, request, Response
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Event, Lock
from pprint import pprint
from datetime import datetime

logging.basicConfig(level=logging.INFO)

PROGRAM_PATH = Path(__file__).resolve().parent
PROJECTS_FILE = Path(f"{PROGRAM_PATH}/projects.txt")

RE_PEER = re.compile(r"\[(.*?)\]")
RE_RESET_CN = re.compile(r"\s(\S+?)/")
RE_VERIFY_CN = re.compile(r"CN=(\S+)")

data_events = defaultdict(Event)
watchers = {}
WATCHER_LOCK = Lock()

PROJECT_CACHE = {}
CACHE_LOCK = Lock()

PROJECT_MAP = []
PROJECTS_LOCK = Lock()

#----------------------------------------------------------------

def load_projects():

   tmp = []
   with PROJECTS_FILE.open() as f:
      for line in f:
         line = line.strip()
         if not line or line.startswith("#"):
            continue
         start_ip, project = line.split(";", 1)
         tmp.append((start_ip, project))

   tmp.sort(key=lambda x: len(x[0]), reverse=True)

   with PROJECTS_LOCK:
      PROJECT_MAP.clear()
      PROJECT_MAP.extend(tmp)

#----------------------------------------------------------------

def get_project(ip):

   with PROJECTS_LOCK:
      for start_ip, project in PROJECT_MAP:
         if ip.startswith(start_ip):
            return project
   raise ValueError("Project variable is not set!")

#----------------------------------------------------------------

def get_project_cache(project):

   with CACHE_LOCK:
      return PROJECT_CACHE.setdefault(project, {
         "cn_order": [],
         "cn_list": {},
         "active_cn_list": {},
         "connection_history": {},
         "connection_state": {},
         "cn_to_ip": {},
         "ip_to_cn": {},
         "permissions": {},
         "is_degraded": {},
         "cn_end_date": {},
         "last_log_pos": 0,
         "last_seen_dirty": True,
         "ip_dirty": True,
         "cn_file_dirty": True,
         "permissions_dirty": True,
         "cn_end_date_dirty": True,
      })

#----------------------------------------------------------------

def load_permissions(project):

   cache = get_project_cache(project)
   PERM = Path(f"/etc/openvpn/{project}/auth/auth-files/permissions.txt")
   perm_map = {}

   if not PERM.is_file():
      cache["permissions"] = {}
      cache["permissions_dirty"] = False
      return

   with PERM.open() as f:
      for line in f:
         if not line or line.startswith("#"):
            continue
         p = line.strip().split(";", 6)
         if len(p) < 7:
            continue

         cn = p[0]
         perm_map[cn] = (
            p[2] == "1",
            p[3] == "1",
            p[4] == "1",
            p[5] == "1",
            p[6] == "1",
         )

   cache["permissions"] = perm_map
   cache["permissions_dirty"] = False

#----------------------------------------------------------------

def read_PERMISSIONS(ip):

   project = get_project(ip)
   cache = get_project_cache(project)

   if cache["permissions_dirty"]:
      load_permissions(project)

   if cache["ip_dirty"]:
      load_CLIENT_CONF(project)

   if cache["cn_file_dirty"]:
      load_CN_LIST(project)

#----------------------------------------------------------------

def block_key(requested_keys, ip):

   project = get_project(ip)
   CN_LIST = Path(f"/etc/openvpn/{project}/auth/auth-files/allowed-cn.txt")
   cache = get_project_cache(project)
   cn = cache["ip_to_cn"].get(ip)

   if not CN_LIST.is_file():
      raise FileNotFoundError(f"File {CN_LIST} not found")

   lines = []
   read_PERMISSIONS(ip)

   if not cache["permissions"][cn][1]:
      print("You do not have permission to use BLOCK button!")
      return

   with CN_LIST.open() as f:
      for line in f:
         line = line.strip()
         if not line:
            lines.append("\n")
            continue
         parts = line.split(";", 2)
         if len(parts) == 3:
            flag, key, _ = parts
            if key in requested_keys:
               if flag == "B":
                  flag = "U"
               else:
                  flag = "B"

            lines.append(f"{flag};{key};{_}\n")

   with CN_LIST.open("w") as f:
      f.writelines(lines)

#----------------------------------------------------------------

def restart(ip):

   project = get_project(ip)
   cache = get_project_cache(project)

   read_PERMISSIONS(ip)

   if not cache["permissions"][cache["ip_to_cn"].get(ip)][0]:
      print("You do not have permision to use RESET button!")
      return

   subprocess.run(["systemctl", "restart", f"openvpn@{PROJECT}"], check=True)

#----------------------------------------------------------------

def load_CN_END_DATE(project):

   cache = get_project_cache(project)
   certs_path = Path(f"/etc/openvpn/{project}/easy-rsa/pki/issued")

   cn_end_date = {}

   if not certs_path.is_dir():
      with CACHE_LOCK:
         cache["cn_end_date"] = {}
         cache["cn_end_date_dirty"] = False
      return

   for path in certs_path.iterdir():
      if not path.is_file():
         continue
      cn_date = subprocess.run(["openssl","x509","-enddate","-noout","-in",f"{path}"],check=True, text=True, capture_output=True)
      cn_date_split = cn_date.stdout.split("=", 1)[1].strip()
      cn_date_object = datetime.strptime(cn_date_split, "%b %d %H:%M:%S %Y %Z")
      cn_date_str = cn_date_object.strftime("%Y-%m-%d %H:%M")
      cn_end_date[path.stem] = cn_date_str

   with CACHE_LOCK:
      cache["cn_end_date"] = cn_end_date
      cache["cn_end_date_dirty"] = False

#----------------------------------------------------------------

def read_CN_END_DATE(project):

   cache = get_project_cache(project)
   if cache["cn_end_date_dirty"]:
      load_CN_END_DATE(project)

#----------------------------------------------------------------

def load_CLIENT_CONF(project):

   cache = get_project_cache(project)
   clients_conf = Path(f"/etc/openvpn/{project}/clients-conf")

   cn_to_ip = {}
   ip_to_cn = {}

   if not clients_conf.is_dir():
      cache["cn_to_ip"] = {}
      cache["ip_to_cn"] = {}
      cache["ip_dirty"] = False
      return

   for path in clients_conf.iterdir():
      if not path.is_file():
         continue

      with path.open() as f:
         for line in f:
            if line.startswith("ifconfig-push"):
               ip = line.split()[1]

               cn_to_ip[path.name] = ip
               ip_to_cn[ip] = path.name
               break

   cache["cn_to_ip"] = cn_to_ip
   cache["ip_to_cn"] = ip_to_cn
   cache["ip_dirty"] = False

#----------------------------------------------------------------

def load_CN_LIST(project):

   cache = get_project_cache(project)
   CN_LIST = Path(f"/etc/openvpn/{project}/auth/auth-files/allowed-cn.txt")
   cn_list = {}
   cn_order = []

   with CN_LIST.open() as f:
      for line in f:
         line = line.strip()
         if line.startswith("#"):
            continue
         if not line:
            cn_order.append(None)
            continue
         flag, key, value = line.strip().split(";", 2)
         cn_list[key] = (value, flag)
         cn_order.append(key)

   cache["cn_list"] = cn_list
   cache["cn_order"] = cn_order
   cache["cn_file_dirty"] = False

#----------------------------------------------------------------

def read_CN_LIST(ip):

   project = get_project(ip)
   cache = get_project_cache(project)

   if cache["ip_dirty"]:
      load_CLIENT_CONF(project)

   if cache["cn_file_dirty"]:
      load_CN_LIST(project)

   existing_clients = {}

   for key, (value, flag) in cache["cn_list"].items():
      vpn_ip = cache["cn_to_ip"].get(key)
      existing_clients[key] = (value, vpn_ip, flag)

   return existing_clients

#----------------------------------------------------------------

def read_LAST_SEEN(ip):

   project = get_project(ip)
   LOG = Path(f"/var/log/openvpn/full-logs/full-{project}.log")
   cache = get_project_cache(project)

   if not cache.get("last_seen_dirty", True):
      return cache["connection_history"], cache["connection_state"]

   cache.setdefault("last_log_pos", 0)
   cache.setdefault("connection_history", {})
   cache.setdefault("connection_state", {})

   if LOG.stat().st_size < cache["last_log_pos"]:
      cache["last_log_pos"] = 0

   with LOG.open() as f:
      f.seek(cache["last_log_pos"])

      for line in f:
         line = line.strip()

         if "Peer Connection Initiated" in line:
            m = RE_PEER.search(line)
            if m:
               cn = m.group(1)

               set_default_to_connection_history(cache, cn)

               cache["connection_state"][cn] = {
                  "verify_recorded": False,
                  "is_degraded": False
               }

         elif "SIGUSR1" in line:
            m = RE_RESET_CN.search(line)
            if m:
               cn = m.group(1)

               cache["connection_history"][cn] = {
                  "last_seen": line[:19],
                  "is_blocked": False
               }

               cache["connection_state"][cn] = {
                  "verify_recorded": False,
                  "is_degraded": False
               }

         elif "VERIFY SCRIPT ERROR" in line:
            m = RE_VERIFY_CN.search(line)
            if m:
               cn = m.group(1)

               set_default_to_connection_history(cache, cn)
               set_default_to_connection_state(cache, cn)

               if not cache["connection_state"][cn]["verify_recorded"]:
                  cache["connection_history"][cn]["is_blocked"] = True
                  cache["connection_history"][cn]["last_seen"] = line[:19]
                  cache["connection_state"][cn]["verify_recorded"] = True

         elif "VERIFY OK" in line:
            m = RE_RESET_CN.search(line)
            if m:
               cn = m.group(1)

               set_default_to_connection_history(cache, cn)

               cache["connection_state"][cn] = {
                  "verify_recorded": False,
                  "is_degraded": False
               }

         elif "MULTI: packet dropped due to output saturation" in line:
            m = RE_RESET_CN.search(line)
            if m:
               cn = m.group(1)

               set_default_to_connection_state(cache, cn)

               if not cache["connection_state"][cn]["is_degraded"]:
                  cache["connection_state"][cn]["is_degraded"] = True

      cache["last_log_pos"] = f.tell()

   cache["last_seen_dirty"] = False

#----------------------------------------------------------------

def set_default_to_connection_history(cache, cn):
   cache["connection_history"].setdefault(cn, {
      "last_seen": "Never",
      "is_blocked": False,
   })

def set_default_to_connection_state(cache, cn):
   cache["connection_state"].setdefault(cn, {
      "verify_recorded": False,
      "is_degraded": False
   })

#----------------------------------------------------------------

def read_OPENVPN_STATUS(ip):

   project = get_project(ip)
   cache = get_project_cache(project)
   STATUS = Path(f"/var/log/openvpn/current-logs/current-status-{project}.log")

   if not STATUS.is_file():
      raise FileNotFoundError(f"File {STATUS} not found")

   in_clients = False
   active_cn_list = {}

   with STATUS.open() as f:
      for line in f:
         line = line.strip()

         if line.startswith("Common Name"):
            in_clients = True
            continue
         if line.startswith("Virtual Address"):
            in_clients = False
            continue

         if in_clients and line:
            parts = line.split(",")
            if len(parts) >= 5:
               active_cn_list[parts[0]] = {
                  "real_ip": parts[1].split(":")[0],
                  "mb_received": round(int(parts[2]) / 1_000_000, 2),
                  "mb_sent": round(int(parts[3]) / 1_000_000, 2),
                  "connected_since": parts[4]
               }

   cache["active_cn_list"] = active_cn_list

#----------------------------------------------------------------

def permission_filter(value, perms, project_parts, project_ip, last_seen, cn):
   if value.startswith("Newag_OpenVPN") and not perms[2]:
      return False
   if not value[-1].isdigit() and value.startswith(project_parts) and project_ip in value and not perms[3]:
      return False
   if (value[-1].isdigit() and value.startswith(project_parts) and not perms[4]) or (not value.startswith(project_parts) and not value.startswith("Newag_OpenVPN") and not perms[4]):
      return False
   if value[-1].isdigit() and value.startswith(project_parts) and not last_seen:
      return False
   return True

#----------------------------------------------------------------

def show_status(ip):

   project = get_project(ip)
   project_ip = ip.split(".", 4)[1]
   project_parts = project.split("-", 1)[0]
   cache = get_project_cache(project)

   read_CN_LIST(ip)
   read_CN_END_DATE(project)
   read_OPENVPN_STATUS(ip)
   read_LAST_SEEN(ip)
   read_PERMISSIONS(ip)

   rows = []

   for cn in cache["cn_order"]:
      if cn is not None:
         value, flag = cache["cn_list"][cn]
         permission_filter_result = permission_filter(value, cache["permissions"].get(cache["ip_to_cn"].get(ip)), project_parts, project_ip, cache["connection_history"].get(cn, {}).get("last_seen"), cn)
         if not permission_filter_result:
            continue
      else:
          rows.append({"empty": True})
          continue
      if cn in cache["active_cn_list"]:

         rows.append({
            "name": value,
            "key": cn,
            "vpn_ip": cache["cn_to_ip"].get(cn),
            "real_ip": cache["active_cn_list"].get(cn).get("real_ip"),
            "mb_received": cache["active_cn_list"].get(cn).get("mb_received"),
            "mb_sent": cache["active_cn_list"].get(cn).get("mb_sent"),
            "connected_since": cache["active_cn_list"].get(cn).get("connected_since"),
            "last_seen": "",
            "is_blocked": flag == "B",
            "is_degraded": cache["connection_state"].get(cn).get("is_degraded"),
            "cn_end_date": cache["cn_end_date"].get(cn),
         })
      else:
         rows.append({
            "name": value,
            "key": cn,
            "vpn_ip": cache["cn_to_ip"].get(cn),
            "real_ip": "",
            "mb_received": "",
            "mb_sent": "",
            "connected_since": "",
            "last_seen": cache["connection_history"].get(cn, {}).get("last_seen", "Never"),
            "is_blocked": flag == "B",
            "cn_end_date": cache["cn_end_date"].get(cn),
         })

   return rows, cache["permissions"].get(cache["ip_to_cn"].get(ip))

#----------------------------------------------------------------

class ProjectsFileHandler(FileSystemEventHandler):
   def on_modified(self, event):
      if event.src_path == str(PROJECTS_FILE):
         load_projects()

def start_projects_watcher():
   observer = Observer()
   observer.schedule(
      ProjectsFileHandler(),
      PROJECTS_FILE.parent,
      recursive=False
   )
   observer.start()
   return observer

class FileChangeHandler(FileSystemEventHandler):
   def __init__(self, project):
      self.project = project

   def on_modified(self, event):
      if event.is_directory:
         return

      path = event.src_path
      cache = get_project_cache(self.project)

      if "clients-conf" in path:
         cache["cn_to_ip"] = True
         data_events[self.project].set()
         return

      if "allowed-cn" in path:
         cache["cn_file_dirty"] = True
         data_events[self.project].set()
         return

      if "current-status-" in path:
         data_events[self.project].set()
         return

      if "full-logs" in path:
         cache["last_seen_dirty"] = True
         data_events[self.project].set()
         return

      if "permissions" in path:
         cache["permissions_dirty"] = True
         data_events[self.project].set()
         return

      if "issued" in path:
         cache["cn_end_date_dirty"] = True
         data_events[self.project].set()
         return

   def on_created(self, event):
      self.on_modified(event)

   def on_deleted(self, event):
      self.on_modified(event)

def start_watcher_for_project(project):
   with WATCHER_LOCK:
      if project in watchers:
         return

      handler = FileChangeHandler(project)
      observer = Observer()

      CLIENTS_CONF = Path(f"/etc/openvpn/{project}/clients-conf")
      if not CLIENTS_CONF.is_dir():
         raise NotADirectoryError(f"{CLIENTS_CONF} is not a directory")

      CN_LIST = Path(f"/etc/openvpn/{project}/auth/auth-files/allowed-cn.txt")
      if not CN_LIST.is_file():
         raise FileNotFoundError(f"File {CN_LIST} not found")

      OPENVPN_STATUS = Path(f"/var/log/openvpn/current-logs/current-status-{project}.log")
      if not OPENVPN_STATUS.is_file():
         raise FileNotFoundError(f"File {OPENVPN_STATUS} not found")

      FULL_LOGS = Path(f"/var/log/openvpn/full-logs/full-{project}.log")
      if not FULL_LOGS.is_file():
         raise FileNotFoundError(f"File {FULL_LOGS} not found")

      PERM = Path(f"/etc/openvpn/{project}/auth/auth-files/permissions.txt")
      if not PERM.is_file():
         raise FileNotFoundError(f"File {PERM} not found")

      CERTS = Path(f"/etc/openvpn/{project}/easy-rsa/pki/issued")
      if not CERTS.is_dir():
         raise NotADirectoryError(f"{CERTS} is not a directory")

      observer.schedule(handler, CN_LIST.parent, recursive=False)
      observer.schedule(handler, OPENVPN_STATUS.parent, recursive=False)
      observer.schedule(handler, CLIENTS_CONF, recursive=False)
      observer.schedule(handler, FULL_LOGS, recursive=False)
      observer.schedule(handler, PERM, recursive=False)
      observer.schedule(handler, CERTS, recursive=False)

      observer.start()
      watchers[project] = observer

#----------------------------------------------------------------

app = Flask(__name__)

@app.before_request
def log_request():
   logging.info(
      f"IP={request.remote_addr} "
      f"Request IP={request.url} "
   )

@app.before_request
def ensure_watcher():
   project = get_project(request.remote_addr)
   start_watcher_for_project(project)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/block", methods=["POST"])
def block():
    block_key(request.get_json()["keys"], request.remote_addr)
    data_events[get_project(request.remote_addr)].set()
    return "", 204

@app.route("/restart", methods=["POST"])
def restart_openvpn():
   restart(request.remote_addr)
   return "", 204

@app.route("/events", methods=["GET"])
def events():

    ip = request.remote_addr
    project = get_project(ip)
    event = data_events[project]

    def stream():
        while True:
            event.wait()
            event.clear()
            rows, cn_permissions = show_status(ip)
            yield f"data: {json.dumps({'rows': rows, 'cn_permissions': cn_permissions})}\n\n"

    return Response(stream(), mimetype="text/event-stream")

@app.route("/data", methods=["GET"])
def data():
   rows, perms = show_status(request.remote_addr)
   return jsonify({
      "rows": rows,
      "cn_permissions": perms
   })

@atexit.register
def stop_watchers():
   if 'projects_observer' in globals():
      projects_observer.stop()
      projects_observer.join()
   for observer in watchers.values():
      observer.stop()
      observer.join()

if __name__ == "__main__":
   load_projects()
   projects_observer = start_projects_watcher()
   serve(app, host="0.0.0.0", port=58081, threads=24)
