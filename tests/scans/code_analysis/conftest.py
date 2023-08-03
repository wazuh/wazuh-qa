import shutil
import tempfile

import pytest
from git import Git, GitCommandError, Repo

DEFAULT_DIRECTORIES_TO_CHECK = 'framework/,api/,wodles/'
DEFAULT_DIRECTORIES_TO_EXCLUDE = 'tests,test'
DEFAULT_CONFIDENCE_LEVEL = 'MEDIUM'
DEFAULT_SEVERITY_LEVEL = 'LOW'


def pytest_addoption(parser):
    parser.addoption("--check_directories", action="store", default=DEFAULT_DIRECTORIES_TO_CHECK,
                     help=f"Set the directories to check, this must be a string with the directory name. "
                          f"If more than one is indicated, they must be separated with comma. "
                          f"Default: {DEFAULT_DIRECTORIES_TO_CHECK}")
    parser.addoption("--exclude_directories", action="store", default=DEFAULT_DIRECTORIES_TO_EXCLUDE,
                     help=f"Set the directories to exclude, this must be a string with the directory name. "
                          f"If more than one is indicated, they must be separated with comma. "
                          f"Default: {DEFAULT_DIRECTORIES_TO_EXCLUDE}")
    parser.addoption("--confidence", action="store", default=DEFAULT_CONFIDENCE_LEVEL,
                     help=f"Set the minimum value of confidence of the Bandit scan. "
                          f"This value must be 'UNDEFINED', 'LOW', 'MEDIUM' or 'HIGH'. "
                          f"Default: {DEFAULT_CONFIDENCE_LEVEL}")
    parser.addoption("--severity", action="store", default=DEFAULT_SEVERITY_LEVEL,
                     help=f"Set the minimum value of severity of the Bandit scan. "
                          f"This value must be 'UNDEFINED', 'LOW', 'MEDIUM' or 'HIGH'. "
                          f"Default: {DEFAULT_SEVERITY_LEVEL}")


@pytest.fixture(scope='session', autouse=True)
def clone_wazuh_repository(pytestconfig):
    """Fixture that clones a Wazuh repository in a temporary directory and checkout to the branch given by parameter.
    Remove the temporary directory once the test session using this fixture has finished.

    Args:
        pytestconfig (fixture): Session-scoped fixture that returns the :class:`_pytest.config.Config` object.

    Yields:
        Union[str, None]: The temporary directory name or None if the clone or checkout actions were not successful.
    """
    # Get Wazuh repository and branch
    repository_name = pytestconfig.getoption('repo')
    reference = pytestconfig.getoption('reference')

    # Create temporary dir
    repository_path = tempfile.mkdtemp()

    try:
        # Clone into temporary dir
        # depth=1 creates a shallow clone with a history truncated to 1 commit. Implies single_branch=True.
        try:
            Repo.clone_from(f"https://github.com/wazuh/{repository_name}.git",
                            repository_path,
                            depth=1,
                            branch=reference)
        except GitCommandError:
            repo = Repo.clone_from(f"https://github.com/wazuh/{repository_name}.git",
                                   repository_path, branch='master', no_single_branch=True)

            # Get all branches that contains the commit
            git_local = Git(repository_path)
            commit_branch = git_local.branch('-a', '--contains', reference).split('\n')
            commit_branch_head = False

            for branch in commit_branch:
                # Remove * in case of branch is the master
                branch_name = branch.replace('*', '').strip()
                repo.git.checkout(branch_name)
                # Check if the commit is the head of the branch
                if(str(repo.head.commit) == reference):
                    commit_branch_head = True
                    break
            if not commit_branch_head:
                raise Exception(f"{reference} was not found as any head branch")

        yield repository_path

    except Exception as e:
        print(f"Error cloning {repository_name}: {str(e)}")
        yield None

    # Remove the temporary directory when the test ends
    shutil.rmtree(repository_path)


@pytest.fixture(scope='session', autouse=True)
def get_test_parameters(pytestconfig):
    """Fixture returning the parameters passed for the test.

    Args:
        pytestconfig (fixture): Session-scoped fixture that returns the :class:`_pytest.config.Config` object.

    Returns:
        dict: Dictionary where each key is a parameter name and the value is its value.
    """
    directories_to_check = pytestconfig.getoption('check_directories').split(',')
    directories_to_exclude = pytestconfig.getoption('exclude_directories')
    min_confidence_level = pytestconfig.getoption('confidence')
    min_severity_level = pytestconfig.getoption('severity')
    repository = pytestconfig.getoption('repo')
    return {'directories_to_check': directories_to_check,
            'directories_to_exclude': directories_to_exclude,
            'min_confidence_level': min_confidence_level,
            'min_severity_level': min_severity_level,
            'repository': repository}
