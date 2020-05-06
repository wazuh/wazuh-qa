import ctypes
import os
from ctypes import wintypes

import wmi

# Imports and constants

SE_OWNER_DEFAULTED = 0x0001
SE_GROUP_DEFAULTED = 0x0002
SE_DACL_PRESENT = 0x0004
SE_DACL_DEFAULTED = 0x0008
SE_SACL_PRESENT = 0x0010
SE_SACL_DEFAULTED = 0x0020
SE_DACL_AUTO_INHERIT_REQ = 0x0100
SE_SACL_AUTO_INHERIT_REQ = 0x0200
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SACL_PROTECTED = 0x2000
SE_SELF_RELATIVE = 0x8000

OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
NO_PROPAGATE_INHERIT_ACE = 0x04
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10
SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
FAILED_ACCESS_ACE_FLAG = 0x80

ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
SYSTEM_AUDIT_ACE_TYPE = 2

FILE_READ_DATA = 0x00000001  # RD
FILE_LIST_DIRECTORY = 0x00000001
FILE_ADD_FILE = 0x00000002
FILE_APPEND_DATA = 0x00000004  # AD
FILE_ADD_SUBDIRECTORY = 0x00000004
FILE_READ_EA = 0x00000008  # REA
FILE_WRITE_EA = 0x00000010  # WEA
FILE_EXECUTE = 0x00000020  # X
FILE_TRAVERSE = 0x00000020
FILE_DELETE_CHILD = 0x00000040  # DC
FILE_READ_ATTRIBUTES = 0x00000080  # RA
READ_CONTROL = 0x00020000  # RC
WRITE_OWNER = 0x00080000  # WO
SYNCHRONIZE = 0x00100000  # S
ACCESS_SYSTEM_SECURITY = 0x01000000  # AS
GENERIC_READ = 0x80000000  # GR
GENERIC_WRITE = 0x40000000  # GW
GENERIC_EXECUTE = 0x20000000  # GE
GENERIC_ALL = 0x10000000  # GA

# Wazuh rules
WAZUH_RULES = {'DELETE': 0x00010000,  # DE
               'WRITE_DAC': 0x00040000,  # WDAC
               'FILE_WRITE_DATA': 0x00000002,  # WD
               'FILE_WRITE_ATTRIBUTES': 0x00000100}  # WA

FILE_GENERIC_READ = (FILE_READ_DATA |
                     FILE_READ_EA |
                     FILE_READ_ATTRIBUTES |
                     READ_CONTROL |
                     SYNCHRONIZE)

FILE_GENERIC_WRITE = (WAZUH_RULES['FILE_WRITE_DATA'] |
                      FILE_APPEND_DATA |
                      FILE_WRITE_EA |
                      WAZUH_RULES['FILE_WRITE_ATTRIBUTES'] |
                      READ_CONTROL |
                      SYNCHRONIZE)

FILE_GENERIC_EXECUTE = (FILE_EXECUTE |
                        FILE_READ_ATTRIBUTES |
                        READ_CONTROL |
                        SYNCHRONIZE)

FILE_ALL_ACCESS = 0x001F01FF

FILE_MODIIFY_ACCESS = FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD |
                                          WAZUH_RULES['WRITE_DAC'] |
                                          WRITE_OWNER)

FILE_READ_EXEC_ACCESS = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE

FILE_DELETE_ACCESS = WAZUH_RULES['DELETE'] | SYNCHRONIZE

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

ERROR_NOT_ALL_ASSIGNED = 0x0514
SE_PRIVILEGE_ENABLED = 0x00000002
TOKEN_ALL_ACCESS = 0x000F0000 | 0x01FF

# Classes

# Win32_LogicalFileSecuritySetting
WQL_LFSS = 'SELECT * FROM Win32_LogicalFileSecuritySetting WHERE Path="%s"'
wmi_ns = wmi.WMI()


class Luid(ctypes.Structure):
    _fields_ = (('LowPart', wintypes.DWORD),
                ('HighPart', wintypes.LONG))


class LuidAndAttributes(ctypes.Structure):
    _fields_ = (('Luid', Luid),
                ('Attributes', wintypes.DWORD))


class TokenPrivileges(ctypes.Structure):
    _fields_ = (('PrivilegeCount', wintypes.DWORD),
                ('Privileges', LuidAndAttributes * 1))

    def __init__(self, privilege_count=1, *args):
        super(TokenPrivileges, self).__init__(privilege_count, *args)


def get_file_security_descriptor(path):
    """
    Get file security descriptor from a given file or folder.

    Parameters
    ----------
    path : str
        Absolute path to file or folder

    Returns
    -------
    list
        File security descriptor (_wmi_object)
    """

    path = os.path.abspath(path)
    os.stat(path)
    lfss = wmi_ns.query(WQL_LFSS % (path,))[0]
    return lfss


def modify_sacl(lfss, mode, mask='DELETE'):
    """
    Add or delete a SACL rule from a given file security descriptor.

    Parameters
    ----------
    lfss : list
        File security descriptor (_wmi_object)
    mode : str
        String that decides whether to add or delete a rule from SACL
    mask : str, optional
        String used to get the hexadecimal mask. Default value is 'DELETE', which implies using the 'DELETE' mask
    """
    sd = lfss.GetSecurityDescriptor()[0]
    if sd.ControlFlags & SE_SACL_PRESENT:
        for entry in sd.SACL:
            # Delete rule if it exists
            if mode == 'delete' and WAZUH_RULES[mask] & entry.AccessMask == WAZUH_RULES[mask]:
                entry.AccessMask &= ~WAZUH_RULES[mask]
            # Add rule if it does not exist
            elif mode == 'add' and WAZUH_RULES[mask] & entry.AccessMask == 0:
                entry.AccessMask &= WAZUH_RULES[mask]
            else:
                raise ValueError
        lfss.SetSecurityDescriptor(sd)


def get_sacl(lfss) -> set:
    """
    Retrieve SACL from a given file security descriptor.

    Parameters
    ----------
    lfss : list
        File security descriptor (_wmi_object)

    Returns
    -------
    set
        SACL set
    """
    sd = lfss.GetSecurityDescriptor()[0]
    sacl_list = set()
    if sd.ControlFlags & SE_SACL_PRESENT:
        if sd.SACL:
            for entry in sd.SACL:
                for name, mask in WAZUH_RULES.items():
                    if mask & entry.AccessMask == mask:
                        sacl_list.add(name)
        return sacl_list


def control_privilege(privilege, status=None):
    """
    Enable or disable certain security privilege

    Parameters
    ----------
    privilege : str
        Privilege to get or remove.
    status : hexadecimal, optional
        Status of the privilege. It can either be 'SE_PRIVILEGE_ENABLED' to enable it or None (default) to disable it
    """
    status = 0 if status is None else status
    hToken = wintypes.HANDLE()
    luid = Luid()
    tp = TokenPrivileges()
    advapi32.LookupPrivilegeValueW(None, privilege, ctypes.byref(luid))
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = status
    advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                              TOKEN_ALL_ACCESS,
                              ctypes.byref(hToken))
    try:
        advapi32.AdjustTokenPrivileges(hToken, False,
                                       ctypes.byref(tp),
                                       ctypes.sizeof(tp),
                                       None, None)
        if ctypes.get_last_error() == ERROR_NOT_ALL_ASSIGNED:
            raise ctypes.WinError(ERROR_NOT_ALL_ASSIGNED)
    finally:
        kernel32.CloseHandle(hToken)


# Privileges context manager
class Privilege:
    def __init__(self, privilege):
        self.privilege = privilege

    def __enter__(self):
        control_privilege(self.privilege, SE_PRIVILEGE_ENABLED)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        control_privilege(self.privilege)
