import os

API_USER = 'molecule_user'
API_PASSWORD = 'MoleculePassword'
MOL_PLATFORM = os.getenv('MOL_PLATFORM', 'centos7')


def get_full_version(package):
    """ Build full package version by joining version and release """
    if hasattr(package, 'release'):
        return "{}-{}".format(package.version, package.release)
    return package.version
