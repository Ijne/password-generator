"""Учебный автоматический мутационный тестер на стандартной библиотеке.

Изменяет по одному узлу AST, запускает неизменный набор unittest.
Не изменяет исходные файлы. Это ограниченный набор операторов мутации,
а не замена полноценному промышленному инструменту.
"""

import ast
import copy
import io
import json
from pathlib import Path
import types
import unittest

import password_generator
import test_password_generator


ROOT = Path(__file__).resolve().parent


def run_suite(module):
    test_password_generator.pg = module
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_password_generator)
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    return result


def mutations(tree):
    operators = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE,
                 ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
                 ast.Is: ast.IsNot, ast.IsNot: ast.Is}
    for index, node in enumerate(ast.walk(tree)):
        variants = []
        if isinstance(node, ast.Compare):
            for position, operator in enumerate(node.ops):
                if type(operator) in operators:
                    replacement = copy.deepcopy(node)
                    replacement.ops[position] = operators[type(operator)]()
                    variants.append((f"{type(operator).__name__} -> {type(replacement.ops[position]).__name__}", replacement))
        elif isinstance(node, ast.Constant) and type(node.value) is int:
            for shift in (-1, 1):
                variants.append((f"integer {node.value} -> {node.value + shift}", ast.Constant(node.value + shift)))
        elif isinstance(node, ast.Constant) and node.value in ("weak", "medium", "strong"):
            for label in ("weak", "medium", "strong"):
                if label != node.value:
                    variants.append((f"label {node.value} -> {label}", ast.Constant(label)))
        elif isinstance(node, ast.BoolOp):
            replacement = copy.deepcopy(node)
            replacement.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
            variants.append(("and <-> or", replacement))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            replacement = copy.deepcopy(node)
            replacement.op = ast.Sub() if isinstance(node.op, ast.Add) else ast.Add()
            variants.append(("+ <-> -", replacement))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            variants.append(("remove not", copy.deepcopy(node.operand)))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "any":
            replacement = copy.deepcopy(node)
            replacement.func.id = "all"
            variants.append(("any -> all", replacement))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "string" and node.attr == "digits":
            variants.append(("remove digit 9", ast.Constant("012345678")))
        for description, replacement in variants:
            mutant = copy.deepcopy(tree)
            target = list(ast.walk(mutant))[index]
            ast.copy_location(replacement, target)
            for parent in ast.walk(mutant):
                for field, value in ast.iter_fields(parent):
                    if value is target:
                        setattr(parent, field, replacement)
                    elif isinstance(value, list):
                        for position, item in enumerate(value):
                            if item is target:
                                value[position] = replacement
            yield node.lineno, description, ast.fix_missing_locations(mutant)


def main():
    baseline = run_suite(password_generator)
    if not baseline.wasSuccessful():
        raise SystemExit("Baseline tests must pass before mutation testing")
    tree = ast.parse((ROOT / "password_generator.py").read_text(encoding="utf-8"))
    records = []
    for number, (line, description, mutant) in enumerate(mutations(tree), 1):
        module = types.ModuleType("password_generator")
        try:
            exec(compile(mutant, str(ROOT / "password_generator.py"), "exec"), module.__dict__)
        except Exception as error:
            records.append(dict(id=number, line=line, mutation=description,
                                status="invalid", error=repr(error)))
            continue
        result = run_suite(module)
        failures = [str(test) for test, _ in result.failures + result.errors]
        records.append(dict(id=number, line=line, mutation=description,
                            status="survived" if result.wasSuccessful() else "killed",
                            detecting_tests=failures))
    test_password_generator.pg = password_generator
    killed = sum(record["status"] == "killed" for record in records)
    survived = sum(record["status"] == "survived" for record in records)
    invalid = sum(record["status"] == "invalid" for record in records)
    report = dict(baseline_tests=baseline.testsRun, total=len(records), killed=killed,
                  survived=survived, invalid=invalid,
                  mutation_score=100 * killed / (killed + survived) if killed + survived else None,
                  operators="comparison boundaries and negation, integer shifts, strength labels, boolean operators, arithmetic, not removal, any/all, digit removal",
                  mutants=records)
    (ROOT / "mutation_results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Baseline: {baseline.testsRun} tests passed")
    print(f"Mutants: {len(records)}; killed: {killed}; survived: {survived}; invalid: {invalid}")
    print(f"Mutation score: {report['mutation_score']:.1f}%")
    for record in records:
        if record["status"] != "killed":
            print(record)


if __name__ == "__main__":
    main()
