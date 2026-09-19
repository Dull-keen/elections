#!/usr/bin/env python3
"""Проверка локального HAR и необязательного отчёта deg-verify.

Первый аргумент — HAR. Второй, необязательный, — JSON-отчёт.

Примеры:
    python3 tools/check_2026_capture.py capture.har
    python3 tools/check_2026_capture.py capture.har deg-verify.json

Скрипт не обращается к сети и не утверждает включение транзакции в блокчейн.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


BASELINE_PATH = Path(__file__).with_name("canonical_hashes_2026.json")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
HASHED_JS_RE = re.compile(r"^(?P<stem>.+)\.[0-9a-f]{8,64}$", re.IGNORECASE)
SOURCE_MAP_LINE_RE = re.compile(
    r"^[ \t]*(?://[#@][ \t]*sourceMappingURL=.*|/\*[#@][ \t]*sourceMappingURL=.*\*/)[ \t]*$",
    re.MULTILINE,
)

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


class EvidenceError(Exception):
    """Ошибка входных локальных данных."""


def colored(mark: str, text: str, color: str | None = None) -> str:
    """Вернуть строку статуса с цветом только при поддержке терминала."""
    if color is None or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return f"{mark} {text}"
    return f"{color}{mark} {text}{RESET}"


def ok_line(text: str) -> None:
    print(colored("🟢", text, GREEN))


def bad_line(text: str) -> None:
    print(colored("🔴", text, RED))


def warn_line(text: str) -> None:
    print(colored("🟡", text, YELLOW))


def neutral_line(text: str) -> None:
    print(f"⚪ {text}")


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"не удалось прочитать JSON {path}: {exc}") from exc


def response_bytes(entry: dict[str, Any]) -> bytes | None:
    content = (entry.get("response") or {}).get("content") or {}
    text = content.get("text")
    if text is None:
        return None
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text, validate=True)
        except (ValueError, TypeError) as exc:
            raise EvidenceError("в HAR обнаружен некорректный base64") from exc
    if not isinstance(text, str):
        raise EvidenceError("HAR response.content.text имеет неверный тип")
    return text.encode("utf-8")


def request_text(entry: dict[str, Any]) -> str | None:
    post_data = (entry.get("request") or {}).get("postData") or {}
    text = post_data.get("text")
    return text if isinstance(text, str) else None


def path_of(url: str) -> str:
    return urlsplit(str(url)).path or "/"


def canonical_name(url: str, kind: str) -> str:
    """Вернуть независимую от URL роль из предварительного baseline."""
    parsed = urlsplit(str(url))
    path = unquote(parsed.path or "/").replace("\\", "/")
    if kind == "html":
        return f"html:{parsed.netloc.lower()}:{path}"

    clean = path.lstrip("/")
    if clean.startswith("elections/"):
        clean = clean[len("elections/"):]
    if clean.endswith(".Без названия"):
        clean = clean[:-len(".Без названия")]
    if not clean.lower().endswith(".js"):
        return f"js:{clean}"
    stem = clean[:-3]
    parent, _, name = stem.rpartition("/")
    match = HASHED_JS_RE.match(name)
    if match:
        name = match.group("stem")
    name += ".js"
    clean = f"{parent}/{name}" if parent else name
    # Some save-page archives relocate this file while the production URL does not.
    if clean == "env.js":
        clean = "assets/env.js"
    return f"js:{clean}"


def entry_kind(entry: dict[str, Any]) -> str | None:
    request = entry.get("request") or {}
    response = entry.get("response") or {}
    content = response.get("content") or {}
    path = path_of(request.get("url", ""))
    mime = str(content.get("mimeType", "")).lower()
    if path.lower().endswith(".js") or "javascript" in mime or "ecmascript" in mime:
        return "js"
    if path.lower().endswith(".html") or "html" in mime:
        return "html"
    return None


def canonical_bytes(body: bytes, kind: str) -> bytes:
    """Нормализовать только транспортные различия, не меняя содержимое приложения."""
    text = body.decode("utf-8-sig")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if kind == "js":
        text = SOURCE_MAP_LINE_RE.sub("", text)
    return text.encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def collect_files(har: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    entries = ((har.get("log") or {}).get("entries"))
    if not isinstance(entries, list):
        raise EvidenceError("HAR не содержит массива log.entries")
    manifest: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = entry_kind(entry)
        if kind is None:
            continue
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = str(request.get("url", ""))
        name = canonical_name(url, kind)
        body = response_bytes(entry)
        item = {
            "kind": kind,
            "name": name,
            "path": path_of(url),
            "status": response.get("status"),
            "body": body,
            "bytes": len(body) if body is not None else None,
            "sha256": sha256(canonical_bytes(body, kind)) if body is not None else None,
        }
        # HARs can contain a cached duplicate and a body-bearing response.
        old = manifest.setdefault(name, [])
        if not any(x["sha256"] == item["sha256"] and x["body"] is not None
                   for x in old):
            old.append(item)
    return manifest


def required_baseline() -> dict[str, Any]:
    try:
        value = read_json(BASELINE_PATH)
    except EvidenceError as exc:
        raise EvidenceError(f"нет файла канонических хэшей {BASELINE_PATH}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("required"), list):
        raise EvidenceError("канонический baseline имеет неверную структуру")
    if not isinstance(value.get("files"), dict):
        raise EvidenceError("в baseline отсутствует files")
    return value


def print_file_hashes(manifest: dict[str, list[dict[str, Any]]],
                      baseline: dict[str, Any]) -> bool:
    required = set(str(x) for x in baseline["required"])
    baseline_files = baseline["files"]
    seen_required: set[str] = set()
    failed = False
    print("\n=== Хэши JavaScript и HTML ===")
    print("Канонизация: UTF-8, BOM/переводы строк; для JavaScript удалён только sourceMappingURL.")
    for name in sorted(manifest):
        items = manifest[name]
        for number, item in enumerate(items, 1):
            suffix = f" [{number}/{len(items)}]" if len(items) > 1 else ""
            required_mark = "обязательный" if name in required else "необязательный"
            if name in required:
                seen_required.add(name)
            if item["body"] is None:
                if name in required:
                    bad_line(f"{name}{suffix}: {required_mark}; тело отсутствует в HAR")
                    failed = True
                else:
                    neutral_line(f"{name}{suffix}: {required_mark}; тело отсутствует в HAR")
                continue
            value = item["sha256"]
            if name in required:
                allowed = set((baseline_files.get(name) or {}).get("hashes") or [])
                if value in allowed:
                    ok_line(f"{name}{suffix}: {required_mark}; sha256={value}")
                else:
                    bad_line(f"{name}{suffix}: {required_mark}; sha256={value}; нет в baseline")
                    failed = True
            else:
                neutral_line(f"{name}{suffix}: {required_mark}; sha256={value}")

    for name in sorted(required - seen_required):
        bad_line(f"{name}: обязательный файл отсутствует в HAR")
        failed = True
    print(f"Обязательных ролей: {len(required)}; найдено: {len(required & seen_required)}.")
    return failed


def vote_entries(har: dict[str, Any]) -> list[dict[str, Any]]:
    entries = ((har.get("log") or {}).get("entries"))
    return [
        entry for entry in entries or []
        if isinstance(entry, dict)
        and str((entry.get("request") or {}).get("method", "")).upper() == "POST"
        and path_of((entry.get("request") or {}).get("url", "")).rstrip("/") == "/api/vote"
    ]


def parse_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def vote_value(tx: dict[str, Any]) -> str | None:
    for param in tx.get("params") or []:
        if isinstance(param, dict) and param.get("key") == "vote":
            value = param.get("value")
            return str(value) if value is not None else None
    return None


def decode_base64_value(value: str) -> bytes:
    encoded = value[len("base64:"):] if value.startswith("base64:") else value
    return base64.b64decode(encoded, validate=True)


def ballot_models(har: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = ((har.get("log") or {}).get("entries"))
    models: dict[str, dict[str, Any]] = {}
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        url = str((entry.get("request") or {}).get("url", ""))
        if path_of(url).rstrip("/") != "/api/ballot-models":
            continue
        body = response_bytes(entry)
        if body is None:
            continue
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        for item in data.get("data") or []:
            ballot = item.get("ballot") if isinstance(item, dict) else None
            contract_id = ballot.get("contractId") if isinstance(ballot, dict) else None
            if contract_id:
                models[str(contract_id)] = item
    return models


def answer_text(answer: Any) -> str | None:
    if not isinstance(answer, dict):
        return None
    attributes = answer.get("attributes")
    if isinstance(attributes, dict):
        for key in ("text", "name", "title"):
            if isinstance(attributes.get(key), str):
                return attributes[key]
    for key in ("text", "name", "title"):
        if isinstance(answer.get(key), str):
            return answer[key]
    return None


def point_hex(point: Any, curve: Any) -> str:
    if point is None:
        return "infinity"
    return curve.compress(point).hex()


def load_pydeg() -> tuple[Any, Any]:
    """Загрузить независимую реализацию bulletin и curve из репозитория."""
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        package_root = parent / "verification"
        if (package_root / "pydeg").is_dir():
            sys.path.insert(0, str(package_root))
            from pydeg import bulletin, curve  # type: ignore
            return bulletin, curve
    raise EvidenceError("не найден локальный пакет verification/pydeg для разбора бюллетеня")


def derive_scalar(draw: bytes, curve: Any) -> int:
    """Воспроизвести genKeyPair elliptic с HmacDRBG для одного 192-байтного draw."""
    if len(draw) != 192:
        raise ValueError(f"ожидался entropy draw длиной 192 байта, получено {len(draw)}")
    key = b"\x00" * 32
    value = b"\x01" * 32
    seed = draw + curve.Q.to_bytes(32, "big")

    def mac(secret: bytes, message: bytes) -> bytes:
        return hmac.new(secret, message, hashlib.sha256).digest()

    key = mac(key, value + b"\x00" + seed)
    value = mac(key, value)
    key = mac(key, value + b"\x01" + seed)
    value = mac(key, value)
    while True:
        value = mac(key, value)
        raw = value
        # generate() performs _update(undefined) after every generated block.
        key = mac(key, value + b"\x00")
        value = mac(key, value)
        candidate = int.from_bytes(raw, "big")
        if candidate <= curve.Q - 2:
            return candidate + 1


def entropy_draws(report: dict[str, Any], vote: dict[str, Any]) -> list[tuple[int, str]]:
    all_draws = report.get("rng")
    if not isinstance(all_draws, list):
        all_draws = vote.get("rng")
    if not isinstance(all_draws, list):
        raise EvidenceError("отчёт не содержит массива rng")
    start, end = vote.get("from"), vote.get("to")
    if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start <= end <= len(all_draws):
        raise EvidenceError("у записи голоса неверный диапазон entropy")
    result = []
    for index in range(start, end):
        draw = all_draws[index]
        raw = draw.get("hex") if isinstance(draw, dict) else None
        if not isinstance(raw, str) or len(raw) != 384 or not HEX_RE.fullmatch(raw):
            raise EvidenceError(f"entropy draw #{index} имеет неверный формат")
        result.append((index, raw))
    return result


def main_key_point(model: dict[str, Any], curve: Any) -> tuple[str, Any]:
    ballot = model.get("ballot") or {}
    raw = str(model.get("mainKey") or ballot.get("mainKey") or "")
    if not raw:
        raise ValueError("в ballot-model отсутствует mainKey")
    key_hex = raw.lower()
    if len(key_hex) == 64:
        # Older captures sometimes omit the compressed-point prefix.
        key_hex = "02" + key_hex
    key = curve.decompress(bytes.fromhex(key_hex))
    return key_hex, key


def selected_indexes(vote: dict[str, Any]) -> set[int]:
    result = set()
    for choice in vote.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        number = choice.get("number")
        # deg-verify records one-based card numbers; the model index is zero-based.
        if isinstance(number, int) and number >= 1:
            result.add(number - 1)
    return result


def check_recorded_names(vote: dict[str, Any], model_questions: list[Any],
                         vote_number: int) -> bool:
    """Сопоставить показанный recorder текст с захваченным ballot-model."""
    choices = vote.get("choices") or []
    if not choices:
        return True
    failed = False
    answers = (model_questions[0].get("answers")
               if model_questions and isinstance(model_questions[0], dict) else []) or []
    for choice in choices:
        if not isinstance(choice, dict) or not isinstance(choice.get("number"), int):
            continue
        index = choice["number"] - 1
        expected = answer_text(answers[index]) if 0 <= index < len(answers) else None
        actual = choice.get("text")
        if expected is not None and isinstance(actual, str) and expected.strip() != actual.strip():
            bad_line(f"голос #{vote_number}: choices text не совпадает для index={index}")
            failed = True
    if failed:
        return False
    ok_line(f"голос #{vote_number}: choices text совпадает с ballot-model")
    return True


def compare_vote_transport(report: dict[str, Any], har: dict[str, Any]) -> bool:
    votes = report.get("votes")
    if not isinstance(votes, list):
        bad_line("JSON: отсутствует массив votes")
        return True
    entries = vote_entries(har)
    failed = False
    if len(votes) == len(entries):
        ok_line(f"/api/vote: число запросов совпадает ({len(votes)})")
    else:
        bad_line(f"/api/vote: HAR содержит {len(entries)}, JSON содержит {len(votes)}")
        failed = True
    for number, vote in enumerate(votes, 1):
        entry = entries[number - 1] if number <= len(entries) else None
        sent = vote.get("sent") if isinstance(vote, dict) else None
        if not isinstance(sent, str) or entry is None:
            continue
        if request_text(entry) == sent:
            ok_line(f"голос #{number}: request body совпадает с HAR")
        else:
            bad_line(f"голос #{number}: request body не совпадает с HAR")
            failed = True
        body = response_bytes(entry)
        receipt = vote.get("receipt")
        if body is not None and isinstance(receipt, str) and body == receipt.encode("utf-8"):
            ok_line(f"голос #{number}: response body совпадает с HAR")
        else:
            bad_line(f"голос #{number}: response body не совпадает с HAR или отсутствует")
            failed = True
        status = (entry.get("response") or {}).get("status")
        if status == vote.get("status"):
            ok_line(f"голос #{number}: HTTP status совпадает ({status})")
        else:
            bad_line(f"голос #{number}: HTTP status не совпадает")
            failed = True
    return failed


def inspect_votes(report: dict[str, Any], har: dict[str, Any]) -> bool:
    """Разобрать захваченные bulletin с помощью entropy и mainKey."""
    try:
        bulletin, curve = load_pydeg()
    except EvidenceError as exc:
        bad_line(str(exc))
        return True
    models = ballot_models(har)
    votes = report.get("votes")
    if not isinstance(votes, list):
        bad_line("JSON: отсутствует массив votes")
        return True
    failed = False
    print("\n=== Кодирование бюллетеня ===")
    print("Используется формула: A = rG; B = rQ + vG; Q = mainKey; v = число отметок.")
    print("r — эфемерный скаляр, восстановленный из entropy; публикация r раскрывает голос.")
    print("Названия берутся из записанного ответа /api/ballot-models в этом HAR.")
    print("Точки A, B, G, Q, rG, rQ и vG напечатаны в сжатом hex.")

    for vote_number, vote in enumerate(votes, 1):
        if not isinstance(vote, dict):
            bad_line(f"голос #{vote_number}: запись имеет неверный формат")
            failed = True
            continue
        tx = parse_object(vote.get("sent"))
        if tx is None:
            bad_line(f"голос #{vote_number}: sent не является JSON-транзакцией")
            failed = True
            continue
        contract_id = str(tx.get("contractId") or "")
        model_item = models.get(contract_id)
        if model_item is None:
            bad_line(f"голос #{vote_number}: для contractId {contract_id} нет ballot-model в HAR")
            failed = True
            continue
        try:
            key_hex, main_key = main_key_point(model_item, curve)
            raw_vote = vote_value(tx)
            if raw_vote is None:
                raise ValueError("в транзакции отсутствует параметр vote")
            questions = bulletin.decode_bulletin(decode_base64_value(raw_vote))
            draws = [(index, derive_scalar(bytes.fromhex(draw_hex), curve))
                     for index, draw_hex in entropy_draws(report, vote)]
        except (ValueError, TypeError, KeyError, IndexError, OverflowError) as exc:
            bad_line(f"голос #{vote_number}: не удалось разобрать бюллетень: {exc}")
            failed = True
            continue

        ballot = model_item.get("ballot") or {}
        model_questions = ballot.get("questions") or []
        print(f"\nГолос #{vote_number}; contractId={contract_id}")
        print(f"mainKey={key_hex}")
        print(f"Q={key_hex}")
        print(f"G={point_hex(curve.G, curve)}")
        print(f"Вопросов в bulletin: {len(questions)}")
        recovered_by_question: list[set[int]] = []
        report_by_question: list[set[int]] = [selected_indexes(vote)]
        if not check_recorded_names(vote, model_questions, vote_number):
            failed = True

        for question_number, question in enumerate(questions, 1):
            answers = (model_questions[question_number - 1].get("answers")
                       if question_number <= len(model_questions)
                       and isinstance(model_questions[question_number - 1], dict) else []) or []
            recovered: set[int] = set()
            print(f"Вопрос #{question_number}; вариантов: {len(question.options)}")
            for option_number, proof in enumerate(question.options):
                answer = answers[option_number] if option_number < len(answers) else None
                name = answer_text(answer) or f"Вариант {option_number}"
                answer_num = answer.get("num") if isinstance(answer, dict) else None
                answer_num_text = str(answer_num) if answer_num is not None else "unknown"
                try:
                    point_a = curve.decompress(proof.A)
                    point_b = curve.decompress(proof.B)
                except ValueError as exc:
                    bad_line(f"  index={option_number}; num={answer_num_text}; name={name}; точки A/B некорректны: {exc}")
                    failed = True
                    continue
                match = next(((draw_index, scalar) for draw_index, scalar in draws
                              if curve.mul_generator(scalar) == point_a), None)
                if match is None:
                    bad_line(f"  index={option_number}; num={answer_num_text}; name={name}; r не найден по A")
                    failed = True
                    continue
                draw_index, scalar = match
                masked = curve.sub(point_b, curve.mul(main_key, scalar))
                value = next((candidate for candidate in range(33)
                              if curve.mul_generator(candidate) == masked), None)
                a_ok = curve.mul_generator(scalar) == point_a
                b_ok = value is not None and curve.add(curve.mul(main_key, scalar),
                                                        curve.mul_generator(value)) == point_b
                if value is not None and value > 0:
                    recovered.add(option_number)
                if value is None or not (a_ok and b_ok):
                    bad_line(f"  index={option_number}; num={answer_num_text}; name={name}; результат не подтверждён")
                    failed = True
                else:
                    ok_line(f"  index={option_number}; num={answer_num_text}; name={name}; result={value}; "
                            f"draw_index={draw_index}; A/B проверены")
                # Keep variable names unchanged: they are the protocol variables.
                print(f"    r={scalar:064x}")
                print(f"    rG={point_hex(curve.mul_generator(scalar), curve)}")
                print(f"    A={point_hex(point_a, curve)}")
                print(f"    B={point_hex(point_b, curve)}")
                print(f"    rQ={point_hex(curve.mul(main_key, scalar), curve)}")
                print(f"    v={value if value is not None else 'unknown'}")
                print(f"    vG={point_hex(curve.mul_generator(value), curve) if value is not None else 'unknown'}")
                print(f"    B-rQ={point_hex(masked, curve)}")
                print(f"    B_expected={point_hex(curve.add(curve.mul(main_key, scalar), curve.mul_generator(value)), curve) if value is not None else 'unknown'}")
            recovered_by_question.append(recovered)

        for question_index, indexes in enumerate(recovered_by_question):
            answers = (model_questions[question_index].get("answers")
                       if question_index < len(model_questions)
                       and isinstance(model_questions[question_index], dict) else []) or []
            for index in sorted(indexes):
                name = answer_text(answers[index]) if index < len(answers) else None
                answer = answers[index] if index < len(answers) else None
                answer_num = answer.get("num") if isinstance(answer, dict) else "unknown"
                print(f"Выбранный кандидат: index={index}; num={answer_num}; name={name or f'Вариант {index}'}; result=1")

        reported = report_by_question[0] if report_by_question else set()
        recovered_union = set().union(*recovered_by_question) if recovered_by_question else set()
        if recovered_union == reported:
            ok_line(f"голос #{vote_number}: recorded choices совпадают с восстановленными result: {sorted(recovered_union)}")
        else:
            bad_line(f"голос #{vote_number}: recorded choices {sorted(reported)} не совпадают с result {sorted(recovered_union)}")
            failed = True
        print("index — нулевой индекс answers; num — поле ballot-model; choices.number — номер карточки начиная с 1.")

    return failed


def final_data_notice() -> None:
    print("\n=== Незавершённые проверки ===")
    warn_line("ballot text: здесь показан только захваченный текст из ballot-model; финальная проверка требует опубликованных данных.")
    warn_line("mainKey: здесь использован только захваченный mainKey; финальная проверка требует опубликованного mainKey.")
    warn_line("recorded-as-cast: локальное совпадение с choices не заменяет финальную проверку; она возможна только после публикации финальных данных.")
    neutral_line("Совпадение HAR, entropy и ciphertext не доказывает включение транзакции или корректность итогов блокчейна.")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Проверить HAR и необязательный JSON-отчёт без сетевых запросов.",
        add_help=False,
    )
    parser._positionals.title = "позиционные аргументы"
    parser._optionals.title = "параметры"
    parser.add_argument("-h", "--help", action="help", help="показать эту справку")
    parser.add_argument("har", type=Path, metavar="HAR", help="HAR-файл")
    parser.add_argument("json_report", nargs="?", type=Path, metavar="JSON",
                        help="необязательный JSON-отчёт")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    for path in (args.har, args.json_report):
        if path is not None and not path.is_file():
            print(f"Ошибка: файл не найден: {path}", file=sys.stderr)
            return 2
    try:
        har = read_json(args.har)
        baseline = required_baseline()
        manifest = collect_files(har)
        failed = print_file_hashes(manifest, baseline)
        if args.json_report is not None:
            report = read_json(args.json_report)
            failed = compare_vote_transport(report, har) or failed
            failed = inspect_votes(report, har) or failed
        final_data_notice()
    except EvidenceError as exc:
        print(f"Ошибка входных данных: {exc}", file=sys.stderr)
        return 2
    except (ValueError, TypeError, KeyError, IndexError, OverflowError) as exc:
        print(f"Ошибка разбора: {exc}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
