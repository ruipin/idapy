"""
   Initializes logging library
"""

import sys, logging, os

from ida_kernwin import msg

# Settings
DEBUG_TO_FILE = False
CONSOLE_DEBUG = True

# Verbosity
DEFAULT_LOGGING_LEVEL = logging.INFO if not (DEBUG_TO_FILE or CONSOLE_DEBUG) else 1
CONSOLE_LOGGING_LEVEL = logging.DEBUG if CONSOLE_DEBUG else logging.INFO



########################
# Do not touch below here

# Configure root logger
logging.root.setLevel(DEFAULT_LOGGING_LEVEL)

# File handler
if DEBUG_TO_FILE:
	dest_file = "{}.log".format(os.path.splitext(os.path.basename(sys.argv[0]))[0])
	
	fh = logging.FileHandler(logging_path, mode='w')
	fh.setLevel(logging.DEBUG)
	fh_formatter = logging.Formatter('%(asctime)s [%(levelname)s:%(name)s] %(message)s')
	fh.setFormatter(fh_formatter)
	logging.root.addHandler(fh)
	
# Message window handler
class MsgHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        msg(log_entry + "\n")

# Console handler
ch = MsgHandler()
ch.setLevel(CONSOLE_LOGGING_LEVEL)
ch_formatter = logging.Formatter('[%(levelname)s:%(name)s] %(message)s')
ch.setFormatter(ch_formatter)
logging.root.addHandler(ch)


# Also log uncaught exceptions
def handle_exception(exc_type, exc_value, exc_traceback):
   if issubclass(exc_type, KeyboardInterrupt):
	   sys.__excepthook__(exc_type, exc_value, exc_traceback)
	   return
   logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
sys.excepthook = handle_exception