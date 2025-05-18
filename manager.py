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


# ─── INJECT PREP COMMANDS ONCE ─────────────────────────────────────────────────
def inject_prep_commands(apollo_cfg_path: Path):
	try:
		text = apollo_cfg_path.read_text(encoding="utf-8")
	except Exception:
		return
	custom_cfg = ConfigParser(interpolation=None)
	custom_cfg.read_string("[root]\n" + text)
	root = custom_cfg["root"]
	gp_raw = root.get("global_prep_cmd", "[]")
	gp_list = json.loads(gp_raw)
	script = Path(sys.argv[0]).resolve()

	if not getattr(sys, 'frozen', False):
		script = f"{Path(sys.executable).resolve()} {script}"

	new_entry = {
		"do": f'"{script}" restore',
		"undo": f'"{script}" save',
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
		"Inject do/undo prep commands into the Apollo config now? Please make sure you have already removed the existing prep commands for the profile manager.",
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


def get_app_paths(app: Path) -> list[str]:
	cfg = load_config(app / "profile.ini", {"paths": {}})
	return [cfg["paths"][k] for k in sorted(cfg["paths"], key=int)]


def set_app_paths(app: Path, paths: list[str]):
	cfg = load_config(app / "profile.ini", {"paths": {}})
	cfg["paths"].clear()
	for i, p in enumerate(paths):
		cfg["paths"][str(i)] = p
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
def do_action(app: Path, client: Path, paths: list[str], action: str):
	app_profile = app / "profile.ini"
	if not app_profile.exists():
		print(f"App profile not found: {app_profile}, not doing anything.")
		sys.exit(0)

	bkup = app / f"{BACKUP_PREFIX}{client.name}"
	if action == "restore":
		client.mkdir(parents=True, exist_ok=True)
		
		# Step 1: Backup current 'real' files to 'bkup' directory,
		#         but only if 'bkup' directory doesn't already exist.
		if not bkup.exists():
			# If bkup dir doesn't exist, create it by backing up current real files
			for p in paths:
				real_path, rel_path = Path(p).expanduser(), make_rel(Path(p))
				backup_dest = bkup / rel_path
				if real_path.exists():
					copy_item(real_path, backup_dest)
		# else: bkup already exists, so we don't touch it / re-backup.

		# Step 2: Restore 'saved' (client profile) files to 'real'
		for p in paths:
			real_path, rel_path = Path(p).expanduser(), make_rel(Path(p))
			saved_source = client / rel_path
			if saved_source.exists():
				remove_item(real_path) # Remove current real item
				copy_item(saved_source, real_path) # Copy from client profile to real
		
		now = _dt.datetime.now().isoformat(timespec="seconds")
		mg = load_config(app / "profile.ini", {"meta": {}})
		mg["meta"].update({"last_run_time": now, "last_run_client": client.name})
		save_config(mg, app / "profile.ini")
		cm = load_config(client / "client.ini", {"meta": {}})
		cm["meta"]["last_run_time"] = now
		save_config(cm, client / "client.ini")
	elif action == "save":

		client.mkdir(parents=True, exist_ok=True)
		for p in paths:
			real, rel = Path(p).expanduser(), make_rel(Path(p))
			old, saved = bkup / rel, client / rel
			if real.exists():
				copy_item(real, saved)
			else:
				print(f"[warn] missing during save: {real}")
			if old.exists():
				remove_item(real)
				copy_item(old, real)
		remove_item(bkup)
		now = _dt.datetime.now().isoformat(timespec="seconds")
		mg = load_config(app_profile, {"meta": {}})
		mg["meta"].update({"last_save_time": now, "last_save_client": client.name})
		save_config(mg, app_profile)
		cm = load_config(client / "client.ini", {"meta": {}})
		cm["meta"]["last_save_time"] = now
		save_config(cm, client / "client.ini")
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
					extras.append((d.name, name))
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
			self.lbl_uuid.config(text="UUID: {—}")
			self.lbl_last_run.config(text="Last run: —")
			self.lbl_last_save.config(text="Last save: —")
			return

		uid, name = self.apps[sel[0]]
		self.lbl_name.config(text=f"Name: {name}")
		self.lbl_uuid.config(text=f"UUID: {{{uid}}}")
		ini = self.root_dir / uid / "profile.ini"
		if ini.exists():
			cfg = load_config(ini, {"meta": {}})
			lr = cfg["meta"].get("last_run_time", "—")
			ls = cfg["meta"].get("last_save_time", "—")
			for btn in (self.btn_manage, self.btn_open, self.btn_delete):
				btn["state"] = "normal"
		else:
			lr, ls = "—", "—"
			for btn in (self.btn_manage, self.btn_open, self.btn_delete):
				btn["state"] = "disabled"

		self.btn_edit["state"] = "normal"

		self.lbl_last_run.config(text=f"Last run: {lr}")
		self.lbl_last_save.config(text=f"Last save: {ls}")

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
		if messagebox.askyesno("Inject Prep Commands", "Are you sure you want to inject prep commands? Please make sure you have already removed the existing prep commands for the profile manager."):
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
		files = self.tk.splitlist(event.data)
		ps = get_app_paths(self.app_path)
		for f in files:
			p = Path(f)
			if p.exists() and str(p) not in ps:
				ps.append(str(p))
		set_app_paths(self.app_path, ps)
		self.refresh()

	def refresh(self):
		self.lb.delete(0, "end")
		for p in get_app_paths(self.app_path):
			self.lb.insert("end", p)

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
		ps = get_app_paths(self.app_path)
		if p not in ps:
			ps.append(p)
			set_app_paths(self.app_path, ps)
			self.refresh()
		else:
			messagebox.showwarning("Duplicate Path", f"The path {p} is already tracked.", parent=self)

	def remove_path(self):
		sel = self.lb.curselection()
		if not sel:
			return
		ps = get_app_paths(self.app_path)
		del ps[sel[0]]
		set_app_paths(self.app_path, ps)
		self.refresh()


# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
def main():
	parser = argparse.ArgumentParser(description="Apollo Profile Manager")
	parser.add_argument("--inject-config", help=argparse.SUPPRESS)  # Hide from help text
	parser.add_argument("command", nargs="?", choices=["restore", "save"], help="Command to execute")

	args = parser.parse_args()

	# Handle Apollo config injection if specified
	if args.inject_config:
		apollo_path = Path(args.inject_config)
		if not apollo_path.exists():
			sys.exit(f"Apollo config file not found: {apollo_path}")

		try:
			inject_prep_commands(apollo_path)
			root = BaseTk()
			root.withdraw()
			root.attributes("-topmost", True)
			messagebox.showinfo("Apollo config", "Prep commands injected successfully. Please restart Apollo to take effect.")
			root.destroy()
			sys.exit(0)
		except Exception as e:
			root = BaseTk()
			root.withdraw()
			root.attributes("-topmost", True)
			messagebox.showerror("Failed to inject prep commands", f"Failed to inject prep commands: {e}")
			root.destroy()
			sys.exit(1)

	cmd = args.command
	if cmd not in ("restore", "save"):
		apollo_cfg = get_apollo_config_path()
		ProfileManagerGUI(
			apollo_cfg,
			get_base_dir() / "profiles",
			preselect=os.getenv(ENV["APP_UUID"]),
		)
		return

	rd = get_base_dir() / "profiles"
	a_id, c_id = os.getenv(ENV["APP_UUID"]), os.getenv(ENV["CLIENT_UUID"])
	if not (a_id and c_id):
		sys.exit("APOLLO_APP_UUID & APOLLO_CLIENT_UUID required.")
	try:
		uuid.UUID(a_id)
		uuid.UUID(c_id)
	except:
		sys.exit("Invalid UUID format.")
	app, client = rd / a_id, rd / a_id / c_id
	do_action(app, client, get_app_paths(app), action=cmd)


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit(1)
