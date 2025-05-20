#!/usr/bin/env python3

import os
import sys
import uuid
import json
import datetime as _dt
import ctypes
from pathlib import Path
from configparser import ConfigParser
import shutil
import re
import tkinter as tk
import argparse
import traceback
import subprocess
import base64
import hashlib

# Optional drag-and-drop support and BaseTk selection
try:
	from tkinterdnd2 import DND_FILES, TkinterDnD
	BaseTk = TkinterDnD.Tk
except ImportError:
	DND_FILES = None
	BaseTk = tk.Tk

from tkinter import ttk, filedialog, messagebox

# ─── MAIN CONFIG & PRIVILEGE ───────────────────────────────────────────────────
def get_base_dir() -> Path:
	"""Get the base directory for the application, whether running as script or exe."""
	if getattr(sys, 'frozen', False):
		# Running as PyInstaller exe
		return Path(sys.executable).parent
	else:
		# Running as script
		return Path(__file__).parent

CONFIG_INI = get_base_dir() / "config.ini"
ENV = {
	"APP_UUID": "APOLLO_APP_UUID",
	"CLIENT_UUID": "APOLLO_CLIENT_UUID",
	"APP_NAME": "APOLLO_APP_NAME",
	"CLIENT_NAME": "APOLLO_CLIENT_NAME",
	"PROFILE_DIR": "APOLLO_PROFILE_DIR",
}

def is_elevated() -> bool:
	if sys.platform.startswith("win"):
		try:
			return ctypes.windll.shell32.IsUserAnAdmin() != 0
		except Exception:
			return False
	return True

# ─── CONFIG HELPERS ────────────────────────────────────────────────────────────
def load_config(ini_path: Path, defaults: dict) -> ConfigParser:
	cfg = ConfigParser(interpolation=None)
	if ini_path.exists():
		cfg.read(ini_path, encoding="utf-8")
	for section, entries in defaults.items():
		if section not in cfg:
			cfg[section] = {}
		for k, v in entries.items():
			cfg[section].setdefault(k, v)
	return cfg


def save_config(cfg: ConfigParser, ini_path: Path):
	ini_path.parent.mkdir(parents=True, exist_ok=True)
	with ini_path.open("w", encoding="utf-8") as fp: cfg.write(fp)

# Constants for backup and metadata
BACKUP_PREFIX = "__backup_"
CLIENT_META_INI = "client.ini"

# Meta helpers
def load_meta(ini_path: Path) -> ConfigParser:
	"""Load metadata section from ini file."""
	return load_config(ini_path, {"meta": {}})


# Helper function to spawn the error dialog in a detached process
def _spawn_error_dialog_and_exit_zero(error_message: str):
	"""Spawns a detached process (the script itself with special args) to show an error dialog, then exits current process with 0."""
	encoded_error_message = base64.b64encode(error_message.encode('utf-8')).decode('utf-8')
	
	# sys.executable will be the path to the script or the PyInstaller executable
	cmd_args = [sys.executable]
	if not getattr(sys, 'frozen', False):
		cmd_args.append(str(Path(sys.argv[0]).resolve()))
	cmd_args.append("--show-error-dialog")
	cmd_args.append(encoded_error_message)

	print(cmd_args)

	creation_flags = 0
	startupinfo = None
	if sys.platform == "win32":
		creation_flags = 0x00000008  # DETACHED_PROCESS
		startupinfo = subprocess.STARTUPINFO()
		startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		startupinfo.wShowWindow = subprocess.SW_HIDE  # Hides the console window if one would appear

	try:
		subprocess.Popen(cmd_args,
						 creationflags=creation_flags,
						 startupinfo=startupinfo,
						 close_fds=True) # close_fds is default True on POSIX, good practice
	except Exception as popen_err:
		# If Popen itself fails, print to current process's stderr as a last resort.
		sys.stderr.write(f"FATAL: Failed to spawn error dialog process: {popen_err}\n")
		sys.stderr.write(f"Original error was:\n{error_message}\n")
		# Exiting with 1 here as the error handling mechanism itself failed.
		sys.exit(1)

	sys.exit(0) # Original process exits with 0 after successfully launching dialog


# ─── INJECT PREP COMMANDS ONCE ─────────────────────────────────────────────────
def inject_prep_commands(apollo_cfg_path: Path):
	try:
		text = apollo_cfg_path.read_text(encoding="utf-8")
	except Exception:
		return
	custom_cfg = ConfigParser(interpolation=None)
	custom_cfg.read_string("[root]\n" + text)
	root = custom_cfg["root"]
	gp_raw = root.get("global_prep_cmd")
	if not gp_raw:
		gp_list = []
		root["global_prep_cmd"] = "[]"
	else:
		gp_list = json.loads(gp_raw)
	script = f'"{Path(sys.argv[0]).resolve()}"'

	if not getattr(sys, 'frozen', False):
		script = f'"{Path(sys.executable).resolve()}" {script}'

	new_entry = {
		"do": f'{script} restore',
		"undo": f'{script} save',
	}
	if sys.platform.startswith("win"):
		new_entry["elevated"] = True
	# insert new prep commands at front
	gp_list.insert(0, new_entry)
	with open(apollo_cfg_path, "w", encoding="utf-8") as f:
		for k, v in root.items():
			if k == "global_prep_cmd":
				f.write(f"global_prep_cmd = {json.dumps(gp_list)}\n")
			else:
				f.write(f"{k} = {v}\n")

def try_inject_prep_commands(apollo_cfg_path: Path):
	if messagebox.askyesno(
		"Inject Prep Commands",
		"Are you sure you want to inject do/undo prep commands into the Apollo config now? Please make sure you have already removed the existing prep commands for the profile manager.",
	):
		try:
			inject_prep_commands(apollo_cfg_path)
			messagebox.showinfo(
				"Apollo Config",
				"Prep commands injected successfully. Please restart Apollo to take effect.",
			)
		except PermissionError:
			if sys.platform.startswith("win"):
				if messagebox.askyesno(
					"Permission Denied",
					"Administrator privileges required to modify Apollo config. Would you like to run with elevated privileges?"
				):
					# Launch with elevated privileges for injection only
					if getattr(sys, 'frozen', False):
						# Running as executable
						exe_path = ''
					else:
						# Running as script
						exe_path = f'"{sys.argv[0]}"'
					
					res = ctypes.windll.shell32.ShellExecuteW(
						None, "runas", sys.executable, f'{exe_path} --inject-config "{apollo_cfg_path}"', None, 1
					)

					if res <= 32:
						messagebox.showinfo(
							"Apollo Config",
							"Failed to run as admin. Please run the script with elevated privileges manually.",
						)
						return False
			else:
				messagebox.showerror(
					"Permission Denied",
					"Elevated privileges required to modify Apollo config. Please rerun elevated.",
				)
				return False
		return True


# ─── APOLLO CONFIG PATH ────────────────────────────────────────────────────────
def get_apollo_config_path() -> Path:
	root = BaseTk()
	root.withdraw()
	root.attributes("-topmost", True)
	try:
		cfg = load_config(CONFIG_INI, {})
	except PermissionError:
		messagebox.showerror(
			"Permission Denied",
			"Administrator privileges required to read config.ini. Please rerun elevated.",
		)
		root.destroy()
		sys.exit(1)

	if cfg.has_section("apollo") and cfg["apollo"].get("apollo_config_path"):
		return Path(cfg["apollo"]["apollo_config_path"]).expanduser()

	messagebox.showinfo(
		"Apollo Config",
		"Apollo config file path not set. Please select the Apollo config file(sunshine.conf).",
	)
	path = filedialog.askopenfilename(
		title="Select Apollo Config File",
		filetypes=[("Config files", "*.conf"), ("All Files", "*.*")],
	)
	if not path:
		root.destroy()
		sys.exit("Apollo config path required.")
	apollo_path = Path(path)

	if not try_inject_prep_commands(apollo_path):
		root.destroy()
		sys.exit(1)

	cfg["apollo"] = {"apollo_config_path": str(apollo_path)}
	save_config(cfg, CONFIG_INI)

	root.destroy()
	return apollo_path


# ─── PATH HELPERS ──────────────────────────────────────────────────────────────
def make_rel(path: Path) -> Path:
	p = Path(path)
	if p.is_absolute():
		try:
			tail = p.relative_to(p.anchor)
		except:
			tail = Path(str(p).lstrip("\\/"))
		return Path(p.drive.rstrip(":")) / tail
	return p


def get_app_paths(app: Path) -> list[tuple[str, str]]:
	cfg = load_config(app / "profile.ini", {"paths": {}})
	paths_data = []
	# Each path entry is now expected to be stored like:
	# hash_value = /actual/path
	for hash_val, path_str in cfg["paths"].items():
		paths_data.append((path_str, hash_val))
	return paths_data


def set_app_paths(app: Path, paths: list[str]): # paths is a list of path strings
	cfg = load_config(app / "profile.ini", {"paths": {}})
	cfg["paths"].clear()
	for p_str in paths:
		hash_val = hashlib.sha1(p_str.encode('utf-8')).hexdigest()
		cfg["paths"][hash_val] = p_str
	save_config(cfg, app / "profile.ini")


# ─── FILESYSTEM HELPERS ─────────────────────────────────────────────────────────
def copy_item(src: Path, dst: Path):
	if not src.exists():
		return
	if src.is_dir():
		shutil.rmtree(dst, ignore_errors=True)
		shutil.copytree(src, dst, dirs_exist_ok=True)
	else:
		dst.parent.mkdir(parents=True, exist_ok=True)
		shutil.copy2(src, dst)


def remove_item(path: Path):
	if path.is_dir() and not path.is_symlink():
		shutil.rmtree(path, ignore_errors=True)
	else:
		path.unlink(missing_ok=True)


# ─── CORE WORKFLOW ─────────────────────────────────────────────────────────────
def do_action(app: Path, client: Path, paths_with_hashes: list[tuple[str, str]], action: str):
	app_profile = app / "profile.ini"
	if not app_profile.exists():
		print(f"App profile not found: {app_profile}, not doing anything.")
		sys.exit(0)

	client_uuid = os.getenv(ENV["CLIENT_UUID"])
	client_name = os.getenv(ENV["CLIENT_NAME"]) # Retained for potential use in messages, meta, etc.
	
	backup_storage_base = app / f"{BACKUP_PREFIX}{client_uuid}"
	client_profile_storage_base = client # client is rd / a_id / c_id

	client_profile_storage_base.mkdir(parents=True, exist_ok=True)

	if action == "restore":
		# Step 1: Backup current 'real' items.
		# This backup is created if it doesn't exist from a previous operation.
		if not backup_storage_base.exists():
			backup_storage_base.mkdir(parents=True, exist_ok=True)
			for p_str, path_hash_str in paths_with_hashes:
				real_path = Path(p_str).expanduser()
				if not real_path.exists():
					print(f"[warn] Path not found during backup: {real_path}")
					continue

				if real_path.is_dir():
					# Backup directory contents into a container dir named by hash
					item_backup_container = backup_storage_base / path_hash_str
					# Ensure old container is removed if it exists (e.g. from an aborted previous op)
					remove_item(item_backup_container)
					copy_item(real_path, item_backup_container)
				else: # real_path is a file
					# Backup file as hash.original_ext
					original_suffix = Path(p_str).suffix # Suffix from original path string
					item_backup_file = backup_storage_base / (path_hash_str + original_suffix)
					remove_item(item_backup_file) # Ensure old file is removed
					copy_item(real_path, item_backup_file)
		# else: backup_storage_base already exists, so we don't touch it / re-backup.

		# Step 2: Restore 'saved' (client profile) items to 'real'
		for p_str, path_hash_str in paths_with_hashes:
			real_path = Path(p_str).expanduser()
			original_suffix = Path(p_str).suffix

			# Define potential storage paths in client profile
			potential_dir_in_profile = client_profile_storage_base / path_hash_str
			potential_file_in_profile = client_profile_storage_base / (path_hash_str + original_suffix)

			restored_something = False
			if potential_dir_in_profile.is_dir():
				remove_item(real_path) # Remove current real item
				# Ensure real_path (as a dir) exists before copying contents into it
				real_path.mkdir(parents=True, exist_ok=True)
				copy_item(potential_dir_in_profile, real_path) # Copies contents
				restored_something = True
			elif potential_file_in_profile.is_file():
				remove_item(real_path) # Remove current real item
				real_path.parent.mkdir(parents=True, exist_ok=True)
				copy_item(potential_file_in_profile, real_path)
				restored_something = True
			
			# if not restored_something and real_path.exists():
			#    print(f"[info] No saved profile item found for {p_str}, existing real_path left untouched.")
			# elif not restored_something:
			#    print(f"[info] No saved profile item found for {p_str}, real_path does not exist.")


		now = _dt.datetime.now().isoformat(timespec="seconds")
		mg = load_config(app / "profile.ini", {"meta": {}})
		mg["meta"].update({"last_run_time": now, "last_run_client": client.name}) # client.name is client_uuid
		save_config(mg, app / "profile.ini")
		cm = load_config(client_profile_storage_base / "client.ini", {"meta": {}}) # Storing client.ini in client profile root
		cm["meta"]["client_name"] = client_name # User-friendly name
		cm["meta"]["last_run_time"] = now
		save_config(cm, client_profile_storage_base / "client.ini")

	elif action == "save":
		for p_str, path_hash_str in paths_with_hashes:
			real_path = Path(p_str).expanduser()
			original_suffix = Path(p_str).suffix

			# Define potential storage paths in client profile
			item_profile_dir_container = client_profile_storage_base / path_hash_str
			item_profile_file = client_profile_storage_base / (path_hash_str + original_suffix)

			if real_path.exists():
				if real_path.is_dir():
					# Clean up potential old file if type changed (file -> dir)
					if item_profile_file.is_file(): remove_item(item_profile_file)
					# Remove old dir contents before saving new
					if item_profile_dir_container.is_dir(): remove_item(item_profile_dir_container)
					copy_item(real_path, item_profile_dir_container) # Saves contents into this hash-named dir
				else: # real_path is a file
					# Clean up potential old dir if type changed (dir -> file)
					if item_profile_dir_container.is_dir(): remove_item(item_profile_dir_container)
					# copy_item will overwrite if item_profile_file exists
					copy_item(real_path, item_profile_file) # Saves as hash.ext
			else:
				print(f"[warn] Real path missing during save: {real_path}. Corresponding profile item will not be updated.")
				# If real_path is missing, we don't update the profile.
				# To delete from profile if real_path is missing:
				# if item_profile_file.exists(): remove_item(item_profile_file)
				# if item_profile_dir_container.exists(): remove_item(item_profile_dir_container)


			# Restore original item from backup (backup_storage_base) to real_path
			# This backup was created by a "restore" action.
			potential_dir_in_backup = backup_storage_base / path_hash_str
			potential_file_in_backup = backup_storage_base / (path_hash_str + original_suffix)

			restored_from_backup = False
			if potential_dir_in_backup.is_dir():
				remove_item(real_path) # Remove current real item (which was just saved to profile)
				real_path.mkdir(parents=True, exist_ok=True)
				copy_item(potential_dir_in_backup, real_path) # Copies contents
				restored_from_backup = True
			elif potential_file_in_backup.is_file():
				remove_item(real_path) # Remove current real item
				real_path.parent.mkdir(parents=True, exist_ok=True)
				copy_item(potential_file_in_backup, real_path)
				restored_from_backup = True
			
			# If real_path existed and was saved, but nothing was in backup to restore,
			# real_path effectively remains as it was (after being saved to profile).
			# If real_path did not exist, and nothing in backup, it remains non-existent.

		# After processing all paths, remove the entire backup_storage_base for this client
		if backup_storage_base.exists():
			remove_item(backup_storage_base)

		now = _dt.datetime.now().isoformat(timespec="seconds")
		mg = load_config(app_profile, {"meta": {}})
		mg["meta"].update({"last_save_time": now, "last_save_client": client.name}) # client.name is client_uuid
		save_config(mg, app_profile)
		cm = load_config(client_profile_storage_base / "client.ini", {"meta": {}}) # Storing client.ini in client profile root
		cm["meta"]["client_name"] = client_name # User-friendly name
		cm["meta"]["last_save_time"] = now
		save_config(cm, client_profile_storage_base / "client.ini")
		
	print(f"{action.title()} finished.")


# ─── GUI CLASSES ───────────────────────────────────────────────────────────────
class ProfileManagerGUI(BaseTk):
	def __init__(self, apollo_path: Path, root_dir: Path, preselect=None):
		root = BaseTk()
		root.withdraw()
		if (
			sys.platform.startswith("win")
			and is_elevated()
			and not messagebox.askyesno(
				"Elevated Process",
				"This process is running with elevated privileges. Drag and drop files to the file manage window may not work. Do you want to continue?",
			)
		):
			root.destroy()
			sys.exit(1)

		super().__init__()
		self.apollo_path, self.root_dir, self.preselect = apollo_path, root_dir, preselect
		self.apps = []

		self.title("Apollo Profile Manager")
		self.geometry("800x400")
		self.build_ui()
		self.wait_window(self)

	def build_ui(self):
		left = ttk.Frame(self)
		left.pack(side="left", fill="both", expand=True)
		self.games_lb = self._list_with_scrollbar(left, self.on_select_game)
		right = ttk.Frame(self)
		right.pack(side="left", fill="y", padx=5, pady=5)
		self.lbl_name = ttk.Label(right, text="Name: —")
		self.lbl_uuid = ttk.Label(right, text="UUID: {—}")
		self.lbl_last_run = ttk.Label(right, text="Last run: —")
		self.lbl_last_save = ttk.Label(right, text="Last save: —")
		for w in (self.lbl_name, self.lbl_uuid, self.lbl_last_run, self.lbl_last_save):
			w.pack(anchor="w")
		btnf = ttk.Frame(right)
		btnf.pack(fill="both", expand=True)
		self.btn_edit = ttk.Button(
			btnf,
			text="Edit Tracked Files",
			command=self.edit_paths,
			state="disabled"
		)
		self.btn_manage = ttk.Button(
			btnf,
			text="Manage Client Saves",
			command=self.manage_client_saves,
			state="disabled",
		)
		self.btn_open = ttk.Button(
			btnf,
			text="Open Profile Dir",
			command=self.open_app_dir,
			state="disabled"
		)
		self.btn_delete = ttk.Button(
			btnf,
			text="Delete App Profile",
			command=self.delete_app,
			state="disabled"
		)
		for b in (self.btn_edit, self.btn_manage, self.btn_open, self.btn_delete):
			b.pack(side="top", fill="x", pady=2)

		self.btn_config = ttk.Button(
			btnf,
			text="Change Apollo Config File",
			command=self.choose_config
		)
		self.btn_inject = ttk.Button(
			btnf,
			text="Inject Global Prep Commands",
			command=self.inject_prep_commands
		)
		self.btn_config.pack(side="bottom", fill="x", pady=2)
		self.btn_inject.pack(side="bottom", fill="x", pady=2)
		
		self.games_lb.bind("<Double-1>", lambda e: self.manage_client_saves())
		self.refresh_games()
		if self.preselect:
			for i, (uid, _) in enumerate(self.apps):
				if uid == self.preselect:
					self.games_lb.selection_set(i)
					self.on_select_game()
					break

	def _list_with_scrollbar(self, parent, cb):
		frame = ttk.Frame(parent)
		frame.pack(fill="both", expand=True)
		frame.rowconfigure(0, weight=1)
		frame.columnconfigure(0, weight=1)
		lb, sb = tk.Listbox(frame), ttk.Scrollbar(
			frame, command=lambda *A: lb.yview(*A)
		)
		lb.configure(yscrollcommand=sb.set)
		lb.grid(row=0, column=0, sticky="nsew")
		sb.grid(row=0, column=1, sticky="ns")
		lb.bind("<<ListboxSelect>>", lambda e: cb())
		return lb

	def refresh_games(self):
		# Load apps from apps.json based on current apollo_path
		apps_json_path = self.apollo_path.parent / self._get_apps_json_filename()
		loaded_apps = []
		if apps_json_path.exists():
			try:
				apps_data = json.load(apps_json_path.open("r", encoding="utf-8")).get("apps", [])
				loaded_apps = [(a["uuid"], a["name"]) for a in apps_data if a.get("uuid")]
			except Exception as e:
				messagebox.showerror("Error loading apps.json", f"Failed to load or parse {apps_json_path}:\n{e}", parent=self)
				# Decide if we should clear self.apps or keep old, or exit
				# For now, let's proceed with an empty list if apps.json is faulty
				loaded_apps = []
		else:
			messagebox.showwarning("apps.json not found", f"Expected apps file not found at: {apps_json_path}", parent=self)
			# If apps.json is not found, we might not want to clear existing apps if this is just a refresh
			# However, for a clean load or after config change, an empty list is appropriate.
			loaded_apps = []

		self.apps = loaded_apps # Set self.apps primarily from apps.json

		# Append other UUID dirs found in profiles_dir if not already in loaded_apps
		profiles_dir = self.root_dir
		if profiles_dir.exists():
			existing_uuids = {uid for uid, _ in self.apps} # Get UUIDs from apps.json loaded apps
			extras = []
			for d in profiles_dir.iterdir():
				if not d.is_dir():
					continue
				try:
					uuid.UUID(d.name) # Check if directory name is a valid UUID
				except ValueError:
					continue
				if d.name not in existing_uuids: # Only add if not already listed from apps.json
					ini = d / "profile.ini"
					cfg = load_config(ini, {"meta": {}})
					name = cfg["meta"].get("app_name", d.name) # Use dir name as fallback
					extras.append((d.name, f"{name} (deleted)"))
			self.apps.extend(extras) # Add extras not present in apps.json

		self.games_lb.delete(0, "end")
		for _, name in self.apps:
			self.games_lb.insert("end", name)
		
		# After refreshing, if there's no selection or the old selection is out of bounds,
		# clear the selection and update details panel.
		current_selection = self.games_lb.curselection()
		if not current_selection or current_selection[0] >= len(self.apps):
			self.games_lb.selection_clear(0, "end")
		self.on_select_game() # This will update button states and labels based on current selection / no selection

	def _get_apps_json_filename(self) -> str:
		# Helper to read the apps.json filename from apollo_config_path
		if not self.apollo_path or not self.apollo_path.exists():
			messagebox.showerror("Apollo Config Missing", "Apollo configuration path is not set or file does not exist.", parent=self)
			return "apps.json" # Default fallback
		try:
			text = self.apollo_path.read_text(encoding="utf-8")
			custom_cfg = ConfigParser(interpolation=None)
			custom_cfg.read_string("[root]\n" + text)
			return custom_cfg["root"].get("file_apps", "apps.json")
		except Exception as e:
			messagebox.showerror("Error reading Apollo Config", f"Could not read app list file name from {self.apollo_path}:\n{e}", parent=self)
			return "apps.json" # Default fallback

	def on_select_game(self):
		sel = self.games_lb.curselection()
		if not sel:
			for btn in (self.btn_manage, self.btn_open, self.btn_delete, self.btn_edit):
				btn["state"] = "disabled"
			self.lbl_name.config(text="Name: —")
			self.lbl_uuid.config(text="UUID: —")
			self.lbl_last_run.config(text="Last run: — (—)")
			self.lbl_last_save.config(text="Last save: — (—)")
			return

		uid, name = self.apps[sel[0]]
		self.lbl_name.config(text=f"Name: {name}")
		self.lbl_uuid.config(text=f"UUID: {uid}")
		ini = self.root_dir / uid / "profile.ini"
		if ini.exists():
			cfg = load_config(ini, {"meta": {}})
			lr = cfg["meta"].get("last_run_time", "—")
			ls = cfg["meta"].get("last_save_time", "—")
			lrc = cfg["meta"].get("last_run_client")
			lsc = cfg["meta"].get("last_save_client")
			if lrc:
				client_path = self.root_dir / uid / lrc / "client.ini"
				if client_path.exists():
					cm = load_config(client_path, {"meta": {}})
					lrc = cm["meta"].get("client_name", lrc)
			if lsc:
				client_path = self.root_dir / uid / lsc / "client.ini"
				if client_path.exists():
					cm = load_config(client_path, {"meta": {}})
					lsc = cm["meta"].get("client_name", lsc)
			for btn in (self.btn_manage, self.btn_open, self.btn_delete):
				btn["state"] = "normal"
		else:
			lr, ls = "—", "—"
			lrc, lsc = "—", "—"
			for btn in (self.btn_manage, self.btn_open, self.btn_delete):
				btn["state"] = "disabled"

		if not lrc:
			lrc = "—"
		if not lsc:
			lsc = "—"

		self.btn_edit["state"] = "normal"

		self.lbl_last_run.config(text=f"Last run: {lr} ({lrc})")
		self.lbl_last_save.config(text=f"Last save: {ls} ({lsc})")

	def ensure_profile_ini(self, app_dir: Path, app_name: str):
		ini = app_dir / "profile.ini"
		if ini.exists():
			return True
		if messagebox.askyesno("Profile not found", f"Do you want to create a new profile for {app_name}?"):
			app_dir.mkdir(parents=True, exist_ok=True)
			cfg = load_config(ini, {"meta": {}})
			cfg["meta"]["app_name"] = app_name
			save_config(cfg, ini)
			return True
		return False

	def open_app_dir(self):
		sel = self.games_lb.curselection()
		uid, name = self.apps[sel[0]]
		app_dir = self.root_dir / uid
		if not self.ensure_profile_ini(app_dir, name):
			return
		if sys.platform.startswith("win"):
			os.startfile(app_dir)
		elif sys.platform == "darwin":
			os.spawnlp(os.P_NOWAIT, "open", "open", str(app_dir))
		else:
			os.spawnlp(os.P_NOWAIT, "xdg-open", "xdg-open", str(app_dir))

	def delete_app(self):
		sel = self.games_lb.curselection()
		uid, name = self.apps[sel[0]]
		app_dir = self.root_dir / uid
		if app_dir.exists() and messagebox.askyesno("Delete app?", f"Delete app {name or uid}?"):
			remove_item(app_dir)
			self.refresh_games()
			self.on_select_game()
		else:
			messagebox.showinfo("Nothing to delete", "App profile does not exist.")

	def manage_client_saves(self):
		sel = self.games_lb.curselection()
		if not sel:
			return
		uid, name = self.apps[sel[0]]
		app_dir = self.root_dir / uid
		if not self.ensure_profile_ini(app_dir, name):
			return
		ClientManagerGUI(self, app_dir, name)

	def edit_paths(self):
		sel = self.games_lb.curselection()
		if not sel:
			return
		uid, name = self.apps[sel[0]]
		app_dir = self.root_dir / uid
		if not self.ensure_profile_ini(app_dir, name):
			return
		dlg = PathEditorGUI(self, app_dir, name)

	def inject_prep_commands(self):
		try_inject_prep_commands(self.apollo_path)

		# Refresh game list and selection
		self.refresh_games()
		self.on_select_game() # Resets selection and button states if list is empty

	def choose_config(self):
		new_path = filedialog.askopenfilename(
			parent=self,
			title="Select Apollo Config File (sunshine.conf)",
			filetypes=[("Config files", "*.conf"), ("All Files", "*.*")],
			initialfile="sunshine.conf"
		)
		if not new_path:
			return

		new_apollo_path = Path(new_path)
		if not new_apollo_path.is_file():
			messagebox.showerror("Invalid File", f"The selected path '{new_apollo_path}' is not a file.", parent=self)
			return

		if new_apollo_path == self.apollo_path:
			messagebox.showinfo("No Change", "The selected configuration file is already in use.", parent=self)
			return

		# Update internal path
		self.apollo_path_backup = self.apollo_path
		self.apollo_path = new_apollo_path

		# Save to config.ini
		cfg = load_config(CONFIG_INI, {})
		cfg["apollo"] = {"apollo_config_path": str(new_apollo_path)}
		try:
			save_config(cfg, CONFIG_INI)
			messagebox.showinfo("Config Updated", f"Apollo config path updated to: {new_apollo_path}", parent=self)
			# Offer to inject prep commands into the new config
			try_inject_prep_commands(self.apollo_path)
		except Exception as e:
			messagebox.showerror("Save Error", f"Failed to save config.ini: {e}", parent=self)
			self.apollo_path = self.apollo_path_backup

		# Refresh game list and selection
		self.refresh_games()
		self.on_select_game() # Resets selection and button states if list is empty


# ─── CLIENT & PATH EDITORS ────────────────────────────────────────────────────
class ClientManagerGUI(tk.Toplevel):
	def __init__(self, parent, app_path, app_name):
		super().__init__(parent)
		self.parent = parent
		self.app_path = Path(app_path)
		self.title(f"Saves for {app_name} ({{{self.app_path.name}}})")
		self.transient(parent)
		self.grab_set()
		self.geometry("600x300")
		self.build_ui()
		self.wait_window(self)

	def build_ui(self):
		left = ttk.Frame(self)
		left.pack(side="left", fill="both", expand=True, padx=5)
		self.cli_lb = self._list_with_scrollbar(left, self.on_select_client)

		right = ttk.Frame(self)
		right.pack(side="left", fill="y", padx=5, pady=5)
		self.lbl_cname = ttk.Label(right, text="Name: N/A")
		self.lbl_cuuid = ttk.Label(right, text="UUID: {—}")
		self.lbl_crun = ttk.Label(right, text="Last run: —")
		self.lbl_csave = ttk.Label(right, text="Last save: —")
		for w in (self.lbl_cname, self.lbl_cuuid, self.lbl_crun, self.lbl_csave):
			w.pack(anchor="w", pady=2)
		btnf = ttk.Frame(right)
		btnf.pack(fill="x", pady=10)
		self.btn_open_cli = ttk.Button(
			btnf, text="Open dir", command=self.open_dir, state="disabled"
		)
		self.btn_delete_cli = ttk.Button(
			btnf, text="Delete client", command=self.delete_client, state="disabled"
		)
		for b in (self.btn_open_cli, self.btn_delete_cli):
			b.pack(fill="x", pady=2)

		self.refresh_clients()

	def _list_with_scrollbar(self, parent, callback):
		frame = ttk.Frame(parent)
		frame.pack(fill="both", expand=True)
		frame.rowconfigure(0, weight=1)
		frame.columnconfigure(0, weight=1)
		lb = tk.Listbox(frame)
		sb = ttk.Scrollbar(frame, command=lb.yview)
		lb.configure(yscrollcommand=sb.set)
		lb.grid(row=0, column=0, sticky="nsew")
		sb.grid(row=0, column=1, sticky="ns")
		lb.bind("<<ListboxSelect>>", lambda e: callback())
		return lb

	def refresh_clients(self):
		self.clients = [
			d
			for d in self.app_path.iterdir()
			if d.is_dir()
			and re.fullmatch(r"[0-9A-Fa-f-]{36}", d.name)
			and not d.name.startswith(BACKUP_PREFIX)
		]
		self.clients.sort(
			key=lambda d: (
				load_meta(d / CLIENT_META_INI)["meta"]
				.get("client_name", d.name)
				.lower()
			)
		)
		self.cli_lb.delete(0, "end")
		for d in self.clients:
			name = load_meta(d / CLIENT_META_INI)["meta"].get("client_name") or d.name
			self.cli_lb.insert("end", name)
		self.on_select_client()

	def on_select_client(self):
		sel = self.cli_lb.curselection()
		state = "normal" if sel else "disabled"
		self.btn_open_cli["state"] = self.btn_delete_cli["state"] = state
		if not sel:
			for lbl in (self.lbl_cuuid, self.lbl_cname, self.lbl_crun, self.lbl_csave):
				lbl.config(text=lbl.cget("text").split(":")[0] + ": —")
			return
		d = self.clients[sel[0]]
		meta = load_meta(d / CLIENT_META_INI)["meta"]
		self.lbl_cuuid.config(text=f"UUID: {{{d.name}}}")
		self.lbl_cname.config(text=f"Name: {meta.get("client_name","N/A")}")
		self.lbl_crun.config(text=f"Last run: {meta.get("last_run_time","—")}")
		self.lbl_csave.config(text=f"Last save: {meta.get("last_save_time","—")}")

	def open_dir(self):
		sel = self.cli_lb.curselection()
		d = self.clients[sel[0]]
		if sys.platform.startswith("win"):
			os.startfile(d)
		elif sys.platform == "darwin":
			os.spawnlp(os.P_NOWAIT, "open", "open", str(d))
		else:
			os.spawnlp(os.P_NOWAIT, "xdg-open", "xdg-open", str(d))

	def delete_client(self):
		sel = self.cli_lb.curselection()
		d = self.clients[sel[0]]
		if messagebox.askyesno("Delete client?", f"Delete client {d.name}?"):
			remove_item(d)
			self.refresh_clients()


class PathEditorGUI(tk.Toplevel):
	def __init__(self, parent, app_path, app_name):
		super().__init__(parent)
		self.parent, parent = parent, parent
		self.app_path = app_path
		self.title(f"Edit Tracked Paths for {app_name}")
		self.transient(parent)
		self.grab_set()
		self.geometry("500x300")
		self.build_ui()
		self.wait_window(self)

	def _check_path_conflicts(self, p_str_to_check: str, current_tracked_paths_str: list[str], context_prefix: str) -> bool:
		p_to_check = Path(p_str_to_check)
		if not p_to_check.exists():
			messagebox.showwarning("Invalid Path", f"{context_prefix} \n'{p_str_to_check}'\ndoes not exist.", parent=self)
			return False

		p_to_check_resolved = p_to_check.resolve()

		# Check 1: Is p_to_check_resolved already a child of an existing tracked directory?
		for existing_p_str in current_tracked_paths_str:
			existing_path_resolved = Path(existing_p_str).resolve()
			if existing_path_resolved.is_dir():
				try:
					if p_to_check_resolved.relative_to(existing_path_resolved):
						messagebox.showwarning("Path Conflict", f"{context_prefix} \n'{p_str_to_check}'\nis already covered by the tracked directory \n'{existing_p_str}'.", parent=self)
						return False
				except ValueError: # Not a subpath
					pass

		# Check 2: If p_to_check_resolved is a directory, does it contain any existing tracked path?
		if p_to_check_resolved.is_dir():
			for existing_p_str in current_tracked_paths_str:
				existing_path_resolved = Path(existing_p_str).resolve()
				try:
					if existing_path_resolved.relative_to(p_to_check_resolved):
						messagebox.showwarning("Path Conflict", f"{context_prefix} directory \n'{p_str_to_check}'\ncontains an already tracked path \n'{existing_p_str}'.\nPlease remove the inner path first or add a more specific directory.", parent=self)
						return False
				except ValueError: # Not a subpath
					pass
		return True # No conflicts found

	def build_ui(self):
		lf = ttk.LabelFrame(self, text="Tracked paths")
		lf.pack(fill="both", expand=True, padx=5, pady=5)
		self.lb = tk.Listbox(lf)
		sb = ttk.Scrollbar(lf, command=self.lb.yview)
		self.lb.configure(yscrollcommand=sb.set)
		self.lb.pack(side="left", fill="both", expand=True)
		sb.pack(side="left", fill="y")
		if DND_FILES:
			self.lb.drop_target_register(DND_FILES)
			self.lb.dnd_bind("<<Drop>>", self.handle_drop)
		bf = ttk.Frame(self)
		bf.pack(fill="x", padx=5, pady=5)
		ttk.Button(bf, text="Add dir", command=lambda: self.add_path(True)).pack(
			side="left", padx=4
		)
		ttk.Button(bf, text="Add file", command=lambda: self.add_path(False)).pack(
			side="left", padx=4
		)
		ttk.Button(bf, text="Remove", command=self.remove_path).pack(
			side="left", padx=4
		)
		ttk.Button(bf, text="Close", command=self.destroy).pack(
			side="right", padx=4
		)
		self.refresh()

	def handle_drop(self, event):
		dropped_files_str = self.tk.splitlist(event.data)
		ps_with_hashes = get_app_paths(self.app_path)
		current_tracked_paths_str = [p_str for p_str, _ in ps_with_hashes]
		
		paths_to_actually_add = []
		had_at_least_one_issue = False # Tracks if any DND item had any issue (conflict, non-existence, duplicate)

		for p_str_dropped in dropped_files_str:
			# Check 0: Is it a duplicate of an already tracked path string?
			if p_str_dropped in current_tracked_paths_str:
				# Optionally inform about duplicates, or just silently skip
				# messagebox.showinfo("Already Tracked", f"The dropped path \n'{p_str_dropped}'\nis already tracked.", parent=self)
				had_at_least_one_issue = True
				continue
			
			# Perform conflict checks using the hoisted method
			if not self._check_path_conflicts(p_str_dropped, current_tracked_paths_str, "Dropped path"):
				had_at_least_one_issue = True
				continue
			
			# If all checks pass, add to our list for this DND operation, avoiding duplicates from the same DND batch
			if p_str_dropped not in paths_to_actually_add:
				paths_to_actually_add.append(p_str_dropped)

		if paths_to_actually_add:
			all_current_plus_new_valid_dnd = current_tracked_paths_str + paths_to_actually_add
			set_app_paths(self.app_path, all_current_plus_new_valid_dnd)
			self.refresh()
			
			if had_at_least_one_issue:
				messagebox.showinfo("Drag & Drop Result", "Some dropped items were added. Others were skipped due to conflicts, non-existence, or being duplicates.", parent=self)
		elif had_at_least_one_issue: # Implies paths_to_actually_add is empty
			messagebox.showwarning("Drag & Drop Failed", "No items were added from the drop operation due to conflicts, non-existence, or being duplicates.", parent=self)
			
	def refresh(self):
		self.lb.delete(0, "end")
		# get_app_paths now returns list of (path_str, hash_str)
		# We display only the path_str in the listbox
		for p_str, _ in get_app_paths(self.app_path):
			self.lb.insert("end", p_str)

	def add_path(self, is_dir: bool):
		p = (
			filedialog.askdirectory(parent=self)
			if is_dir
			else filedialog.askopenfilename(parent=self)
		)
		if not p:
			return
		p_obj = Path(p)
		if not p_obj.exists():
			messagebox.showerror("Invalid path", f"{p} does not exist", parent=self)
			return
		if is_dir and not p_obj.is_dir():
			messagebox.showerror(
				"Invalid directory", f"{p} is not a directory", parent=self
			)
			return
		if not is_dir and not p_obj.is_file():
			messagebox.showerror("Invalid file", f"{p} is not a file", parent=self)
			return

		p_to_add_path_str = p # Keep original string for adding if valid
		ps_with_hashes = get_app_paths(self.app_path)
		current_tracked_paths_str = [p_str for p_str, _ in ps_with_hashes]

		# Check 0: Is it a duplicate of an already tracked path string?
		if p_to_add_path_str in current_tracked_paths_str:
			messagebox.showwarning("Duplicate Path", f"The path \n'{p_to_add_path_str}'\nis already tracked.", parent=self)
			return

		# Perform conflict checks using the hoisted method
		if not self._check_path_conflicts(p_to_add_path_str, current_tracked_paths_str, "Path"):
			return # Conflict message already shown by _check_path_conflicts

		# If all checks pass, add the path (original string p)
		updated_paths = current_tracked_paths_str + [p_to_add_path_str]
		set_app_paths(self.app_path, updated_paths)
		self.refresh()

	def remove_path(self):
		sel = self.lb.curselection()
		if not sel:
			return
		# get_app_paths now returns list of (path_str, hash_str)
		# We need to reconstruct the list of path strings for set_app_paths
		ps_with_hashes = get_app_paths(self.app_path)
		current_paths = [p_str for p_str, _ in ps_with_hashes]
		
		del current_paths[sel[0]]
		set_app_paths(self.app_path, current_paths)
		self.refresh()


# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
def main():
	try:
		parser = argparse.ArgumentParser(description="Apollo Profile Manager")
		# Hidden argument for the error dialog mechanism
		parser.add_argument("--show-error-dialog", type=str, help=argparse.SUPPRESS)
		parser.add_argument("--show-error-dialog-test", type=str, help=argparse.SUPPRESS)
		# Existing arguments
		parser.add_argument("--inject-config", help=argparse.SUPPRESS)
		parser.add_argument("command", nargs="?", choices=["restore", "save"], help="Command to execute")

		args = parser.parse_args()

		if args.show_error_dialog_test:
			error_message = f"This is a test error message:\n\n{args.show_error_dialog_test}"
			_spawn_error_dialog_and_exit_zero(error_message)

		# Handle error dialog display if this instance is invoked for it
		if args.show_error_dialog:
			try:
				error_message_decoded = base64.b64decode(args.show_error_dialog.encode('utf-8')).decode('utf-8')
				root = BaseTk() # Use existing BaseTk for consistency
				root.withdraw()
				root.attributes("-topmost", True)
				messagebox.showerror("Apollo Profile Manager - Error", error_message_decoded, parent=None)
				root.destroy()
			except Exception as display_err:
				# If the error display mechanism itself fails, write to stderr.
				# This might go to a log file for a PyInstaller app or be lost, but it's a last resort.
				sys.stderr.write(f"Error within --show-error-dialog handler: {display_err}\nEncoded message was: {args.show_error_dialog}\n")
				sys.exit(1) # Error dialog mechanism failed
			sys.exit(0) # Error dialog shown, exit this instance cleanly

		# Proceed with normal application logic if not in --show-error-dialog mode
		# Handle Apollo config injection if specified
		if args.inject_config:
			apollo_path = Path(args.inject_config)
			if not apollo_path.exists():
				# This sys.exit will be caught by SystemExit handler below
				sys.exit(f"Apollo config file not found: {apollo_path}")

			try:
				inject_prep_commands(apollo_path)
				# Temporary root for messagebox, as main GUI might not be running
				# This part is tricky if main() is supposed to be headless for this path.
				# The original code creates a root here.
				root = BaseTk()
				root.withdraw()
				root.attributes("-topmost", True)
				messagebox.showinfo("Apollo config", "Prep commands injected successfully. Please restart Apollo to take effect.")
				root.destroy()
				sys.exit(0) # Clean exit
			except Exception as e: # Catch specific errors from inject_prep_commands
				# This will be caught by the general Exception handler below
				# To make it more specific for this phase, we could re-raise or handle directly.
				# For now, let it be caught by the general handler.
				# However, the original code had its own messagebox here.
				# Let's adapt: show its specific message then let our handler take over for exiting.
				# This message will be shown by the main process, then the general handler kicks in.
				root = BaseTk()
				root.withdraw()
				root.attributes("-topmost", True)
				messagebox.showerror("Failed to inject prep commands", f"Failed to inject prep commands: {e}")
				root.destroy()
				# Now raise e so it's caught by the outer handler which calls _spawn_error_dialog_and_exit_zero
				# Or, more directly, call sys.exit with an error message.
				sys.exit(f"Failed to inject prep commands: {e}")


		cmd = args.command
		if cmd not in ("restore", "save"):
			apollo_cfg = get_apollo_config_path() # Can raise SystemExit
			ProfileManagerGUI(
				apollo_cfg,
				get_base_dir() / "profiles",
				preselect=os.getenv(ENV["APP_UUID"]),
			)
			return # Normal exit for GUI

		rd = get_base_dir() / "profiles"
		a_id, c_id = os.getenv(ENV["APP_UUID"]), os.getenv(ENV["CLIENT_UUID"])
		if not (a_id and c_id):
			sys.exit("APOLLO_APP_UUID & APOLLO_CLIENT_UUID required.") # Caught by SystemExit
		try:
			uuid.UUID(a_id)
			uuid.UUID(c_id)
		except ValueError: # Specific exception type
			sys.exit("Invalid UUID format.") # Caught by SystemExit
		
		app, client = rd / a_id, rd / a_id / c_id
		do_action(app, client, get_app_paths(app), action=cmd)

	except Exception as e:
		traceback_str = traceback.format_exc()
		print(traceback_str)

		error_message = f"An unexpected error occurred:\n\n{type(e).__name__}: {e}\n\n{traceback_str}"

		_spawn_error_dialog_and_exit_zero(error_message)


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit(1)
