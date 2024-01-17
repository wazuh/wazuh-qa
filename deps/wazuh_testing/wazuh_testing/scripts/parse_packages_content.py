import argparse
import json
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("parse_packages_content.py")


def parse_packages_content(output_file, packages_file, n_packages):
    list_packages = []
    config = None

    with open(packages_file) as f:
        for line in f:
            if len(list_packages) >= n_packages:
                break

            if line.strip():
                config = json.loads(line)

                if 'payload' in config and 'containers' in config['payload'] \
                        and 'cna' in config['payload']['containers']:
                    if 'affected' in config['payload']['containers']['cna']:
                        for affected in config['payload']['containers']['cna']['affected']:
                            vendor = affected['vendor']
                            product = affected['product']

                            for affected_version in affected['versions']:
                                status, version = affected_version['status'], affected_version['version']

                                if status == 'affected':
                                    list_packages.append({
                                        'vendor': vendor,
                                        'product': product,
                                        'version': version
                                    })
                    else:
                        logger.debug("No affected found in package: %s", config)
                else:
                    logger.warning("No payload found for package: %s", config['id'])
                    logger.debug("Package: %s", config)

    with open(output_file, 'w') as f:
        json.dump(list_packages, f, indent=4)


def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-p', '--packages', metavar='<packages_file>', type=str, required=True,
                            help='Packages file', dest='packages_file')

    arg_parser.add_argument('-n', '--n_packages', metavar='<n_packages>', type=int, required=True,
                            help='Number of packages to parse', dest='n_packages')

    arg_parser.add_argument('-o', '--output', metavar='<output_file>', type=str, required=True,
                            help='Output file', dest='output_file')

    arg_parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode', dest='debug')


    args = arg_parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logging.info("Parsing packages content...")
    parse_packages_content(args.output_file, args.packages_file, args.n_packages)
    logging.info("Packages parsed successfully")


if __name__ == '__main__':
    main()
