import argparse
import os
import stat
import grp
import pwd
import json
import logging


script_logger = logging.getLogger('check_files')
_filemode_list = [
    {
        stat.S_IFLNK: "l",
        stat.S_IFREG: "-",
        stat.S_IFBLK: "b",
        stat.S_IFDIR: "d",
        stat.S_IFCHR: "c",
        stat.S_IFIFO: "p"
    },
    {
        stat.S_IRUSR: "r"
    },
    {
        stat.S_IWUSR: "w"
    },
    {
        stat.S_IXUSR | stat.S_ISUID: "s",
        stat.S_ISUID: "S",
        stat.S_IXUSR: "x"
    },
    {
        stat.S_IRGRP: "r"
    },
    {
        stat.S_IWGRP: "w"
    },
    {
        stat.S_IXGRP | stat.S_ISGID: "s",
        stat.S_ISGID: "S",
        stat.S_IXGRP: "x"
    },
    {
        stat.S_IROTH: "r"
    },
    {
        stat.S_IWOTH: "w"
    },
    {
        stat.S_IXOTH | stat.S_ISVTX: "t",
        stat.S_ISVTX: "T",
        stat.S_IXOTH: "x"
    }
]


def set_parameters(parameters):
    logging_level = logging.DEBUG if parameters.debug else logging.INFO
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(message)s')

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    script_logger.setLevel(logging_level)
    script_logger.addHandler(handler)


def get_check_files_data(path='/', ignored_paths=[]):
    files_items_dict = {}

    script_logger.info(f"Ignoring the following paths: {ignored_paths}")
    script_logger.info(f"Getting check-files data from {path}")

    for (dirpath, _, filenames) in os.walk(path, followlinks=False):
        skip_path_checking = False

        for ignore_path in ignored_paths:
            if ignore_path in dirpath:
                script_logger.debug(f"Skipping '{dirpath}' path")
                skip_path_checking = True

        if not skip_path_checking:
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                files_items_dict[dirpath] = get_data_information(dirpath)

                if file_path not in ignored_paths:
                    files_items_dict[file_path] = get_data_information(file_path)

    return files_items_dict


def get_filemode(mode):
    file_permission = []

    for item in _filemode_list:
        for stat_flag, stat_value in item.items():
            if mode & stat_flag == stat_flag:
                file_permission.append(stat_value)
                break
        else:
            file_permission.append('-')

    return ''.join(file_permission)


def get_data_information(item):
    stat_info = os.stat(item)
    user = pwd.getpwuid(stat_info.st_uid)[0]
    group = grp.getgrgid(stat_info.st_gid)[0]
    mode = oct(stat.S_IMODE(stat_info.st_mode))
    mode_str = str(mode).replace('o', '')
    mode = mode_str[-3:] if len(mode_str) > 3 else mode_str
    _type = 'directory' if os.path.isdir(item) else 'file'
    protection = get_filemode(stat_info.st_mode)

    return {'type': _type, 'user': user, 'group': group, 'mode': mode, 'prot': protection}


def write_data_to_file(data, output_file_path):
    output_dir = os.path.split(output_file_path)[0]

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    with open(output_file_path, 'w') as file:
        file.write(json.dumps(data, indent=4))

    script_logger.info(f"The check-files data has been written in {arguments.output_file} file")


def get_script_parameters():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-p", "--path", type=str, required=False, default='/',
                            help="Path base to inspect files recursively")
    arg_parser.add_argument("-i", "--ignore", type=str, nargs='+', help='List of paths to ignore')
    arg_parser.add_argument("-o", "--output-file", type=str, help='path to store the results')
    arg_parser.add_argument('-d', '--debug', action='store_true', help='Run in debug mode.')

    return arg_parser.parse_args()


if __name__ == '__main__':
    arguments = get_script_parameters()
    set_parameters(arguments)

    ignored_paths = arguments.ignore if arguments.ignore else []
    check_files_data = get_check_files_data(arguments.path, ignored_paths)

    if arguments.output_file:
        write_data_to_file(check_files_data, arguments.output_file)
    else:
        script_logger.info(json.dumps(check_files_data, indent=4))
