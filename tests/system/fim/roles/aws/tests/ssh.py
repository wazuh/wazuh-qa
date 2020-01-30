def test_custom_key_exists(host, user, ssh_key):
    authorized_keys_file = host.file("/home/" + user + "/.ssh/authorized_keys")
    assert authorized_keys_file.exists
    assert (ssh_key in authorized_keys_file.content_string)