from pathlib import Path
from .vagrant import VagrantProvider


TEMPLATES_DIR = Path(__file__).parent / 'templates'
SPECS_DIR = Path(__file__).parent / 'specs'
OS_PATH = SPECS_DIR / 'os.yml'
ROLES_PATH = SPECS_DIR / 'roles.yml'