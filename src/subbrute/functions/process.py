import argparse
import json
import os
import sys
from typing import List, Optional, Tuple, TextIO

from src.subbrute.functions.check_open import check_open
from src.subbrute.functions.error import error
from src.subbrute.functions.extract_subdomains import extract_subdomains
from .run import run


def get_base_path() -> str:
    """Определяет базовый путь для скрипта или исполняемого файла."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    return base_path


def process_subdomain_filter(filter_file: str) -> None:
    """Обрабатывает файл фильтрации поддоменов и выводит результат."""
    for subdomain in extract_subdomains(filter_file):
        print(subdomain)
    sys.exit()


def get_targets(args: argparse.Namespace) -> List[str]:
    """Получает список целевых доменов из файла или аргументов."""
    if args.targets_file:
        return check_open(args.targets_file)
    return [args.target] if args.target else []


def setup_output_files(output_path: Optional[str], json_path: Optional[str]) -> Tuple[
    Optional[TextIO], Optional[TextIO]]:
    """Инициализирует файлы для вывода."""
    output = None
    json_output = None
    if output_path:
        try:
            output = open(output_path, "w", encoding="utf-8")
        except OSError as e:
            error(f"Failed writing to file {output_path}: {e}")
    if json_path:
        try:
            json_output = open(json_path, "w", encoding="utf-8")
        except OSError as e:
            error(f"Failed writing to file {json_path}: {e}")
    return output, json_output


def get_record_type(ipv4: bool, record_type: Optional[str]) -> Optional[str]:
    """Определяет тип DNS-записи на основе аргументов."""
    if ipv4:
        return "A"
    if record_type:
        return str(record_type).upper()
    return None


def process_targets(
        targets: List[str],
        record_type: Optional[str],
        subs: str,
        resolvers: str,
        process_count: int,
        output: Optional[TextIO],
        json_output: Optional[TextIO]
) -> None:
    """Обрабатывает каждую цель, используя run."""
    json_results = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        if output:
            output.write(f"[*] Processing: {target}\n")
        for result in run(target, record_type, subs, resolvers, process_count):
            # Предполагается, что run возвращает кортеж (hostname, record_type, answers)
            hostname = result[0]
            print(hostname)
            if output:
                output.write(f"{hostname}\n")
            if json_output:
                json_results.append({"hostname": hostname, "record_type": result[1], "answers": result[2]})
    if json_output and json_results:
        json.dump(json_results, json_output, indent=2)
