import win32security
import win32file
import platform
import os
import win32con
import ntsecuritycon as con

sid = 'S-1-1-0'


def get_file_acl(file):
    """
    Get Access Control List of a file/directory
    @return: PyACL object
    """
    info = win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetFileSecurity(file, info)
    acl = sd.GetSecurityDescriptorDacl()

    return acl


def grantAccessToFile(filePath, userName='Todos'):
    """
    Allow Permission to userName on a file/directory
    @param file: path of the file/dir
    @param userName: name of the user to add to the acl of the file/dir
    """


    info = win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetFileSecurity(filePath, info)
    acl = get_file_acl(filePath)
    # user, domain, acType = win32security.LookupAccountName("", userName)
    #
    # acl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE |
    #                         con.FILE_DELETE_CHILD | con.DELETE | win32file.FILE_SHARE_DELETE, user)
    # sd.SetSecurityDescriptorDacl(1, acl, 0)
    # win32security.SetFileSecurity(filePath, win32security.DACL_SECURITY_INFORMATION, sd)
    print(dir(acl))


# grantAccessToFile(os.path.join('c:', os.sep, 'testdir'))

filePath = os.path.join('c:', os.sep, 'testdir')


grantAccessToFile(filePath)










def dump_acl(object_name, object_type_s, sd, options={}):
    dacl = sd
    if dacl is None:
        print("No Discretionary ACL")
        return []

    weak_perms = []
    for ace_no in range(0, dacl.GetAceCount()):
        # print "[D] ACE #%d" % ace_no
        ace = dacl.GetAce(ace_no)
        flags = ace[0][1]

        try:
            principle, domain, type = win32security.LookupAccountSid(remote_server, ace[2])
        except:
            principle = win32security.ConvertSidToStringSid(ace[2])
            domain = ""

        mask = ace[1]
        if ace[1] < 0:
            mask = ace[1] + 2 ** 32

        if ignore_trusted and principle_is_trusted(principle, domain):
            # print "[D] Ignoring trusted principle %s\\%s" % (principle, domain)
            continue

        if principle == "CREATOR OWNER":
            if ignore_trusted and principle_is_trusted(owner_name, owner_domain):
                # print "[D] Ignoring trusted principle (creator owner) %s\\%s" % (principle, domain)
                continue
            else:
                principle = "CREATOR OWNER [%s\%s]" % (domain, principle)

        for i in (
        "ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE", "SYSTEM_AUDIT_ACE_TYPE", "SYSTEM_ALARM_ACE_TYPE"):
            if getattr(ntsecuritycon, i) == ace[0][0]:
                ace_type_s = i

        ace_type_short = ace_type_s

        if ace_type_s == "ACCESS_DENIED_ACE_TYPE":
            ace_type_short = "DENY"

        if ace_type_s == "ACCESS_ALLOWED_ACE_TYPE":
            ace_type_short = "ALLOW"

        if weak_perms_only:
            perms = dangerous_perms_write
        else:
            perms = all_perms

        for mod, perms_tuple in perms[object_type_s].iteritems():
            for perm in perms_tuple:
                # print "Checking for perm %s in ACE %s" % (perm, mask)
                if getattr(mod, perm) & mask == getattr(mod, perm):
                    weak_perms.append([object_name, domain, principle, perm, ace_type_short])
    print_weak_perms(object_type_s, weak_perms, options)
