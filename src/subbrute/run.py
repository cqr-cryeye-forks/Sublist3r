import sys

from src.subbrute.functions.process import (
    get_base_path,
    process_subdomain_filter,
    get_targets,
    get_record_type,
    process_targets,
    setup_output_files,
)
from src.subbrute.functions.setup_argument_parser import setup_argument_parser


def main() -> None:
    """Основная функция для запуска инструмента."""
    base_path = get_base_path()
    args = setup_argument_parser(base_path)

    if args.filter_subs:
        process_subdomain_filter(args.filter_subs)

    targets = get_targets(args)
    if not targets:
        sys.exit("No targets specified")

    output, json_output = setup_output_files(args.output, args.json)
    record_type = get_record_type(args.ipv4, args.type)

    try:
        process_targets(
            targets,
            record_type,
            args.subs,
            args.resolvers,
            args.process_count,
            output,
            json_output
        )
    finally:
        if output:
            output.close()
        if json_output:
            json_output.close()
