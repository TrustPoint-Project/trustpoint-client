from __future__ import annotations

from pathlib import Path
from platformdirs import PlatformDirs


dirs = PlatformDirs(appname='trustpoint_client', appauthor='trustpoint')
WORKING_DIR = Path(dirs.user_data_dir)
INVENTORY_FILE_PATH = WORKING_DIR / Path('inventory.json')
CONFIG_FILE_PATH = WORKING_DIR / Path('config.json')




