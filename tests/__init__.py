"""Keep package-style unittest imports from generating skill bytecode."""
import sys

sys.dont_write_bytecode = True
