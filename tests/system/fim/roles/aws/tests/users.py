def test_user_exists(host,user):
    user_in_passwd_rc = host.run("grep " + user + " -q /etc/passwd").rc
    if (user_in_passwd_rc == 0):
        assert True
    else:
        assert False

def test_user_group_exists(host,user):
    assert (host.user(name=user).group == user)

def test_user_home_exists(host,user):
    user_home = "/home/" + user
    assert (host.user(name=user).home == user_home)

def test_user_home_correct_owner(host,user):
    user_home = host.file("/home/" + user)
    assert user_home.exists
    assert user_home.is_directory
    assert user_home.user == user
    assert user_home.group == user
    
def test_user_is_sudoer(host,user):
    error_user_not_found = "unknown user"
    error_user_not_sudoer = "is not allowed to run sudo"
    sudoer_check_command = "sudo -l -U " + user
    if (error_user_not_found in host.run(sudoer_check_command).stdout):
        assert False
    elif (error_user_not_sudoer in host.run(sudoer_check_command).stdout):
        assert False
    else:
        assert True