"""A small evaluator for GitHub Actions expressions (${{ ... }}), enough for the feed tier workflows.

Supports literals, context lookups (github.event.x, inputs.x, steps.id.outputs.x, ...), ! && || == != and
parentheses, and the status functions. Semantics follow the Actions docs:
- && and || return one of their operands, not a boolean;
- false, 0, '', null are falsy;
- == compares strings case-insensitively, and coerces mismatched types to numbers;
- a missing property is null, and null renders as ''.
"""

from __future__ import annotations

import math
import re

_TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?)|(?P<op>&&|\|\||==|!=|!|\(|\)|\.|,|\[|\])|(?P<ident>[A-Za-z_][A-Za-z0-9_-]*))"
)
_TEMPLATE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
STATUS_FUNCTIONS = ("success", "failure", "always", "cancelled")


class ExpressionError(Exception):
    pass


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ExpressionError(f"can't parse {text!r} at {text[pos:]!r}")
        kind = m.lastgroup
        tokens.append((kind, m.group(kind)))
        pos = m.end()
    return tokens


def truthy(value) -> bool:
    return not (value is None or value is False or value == 0 or value == "")


def to_string(value) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _to_number(value) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        if value.strip() == "":
            return 0.0
        try:
            return float(value)
        except ValueError:
            return math.nan
    return math.nan


def _equal(a, b) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    if type(a) is type(b) or (a is None and b is None):
        return a == b
    return _to_number(a) == _to_number(b)


class _Parser:
    def __init__(self, tokens, context, status):
        self.tokens, self.pos, self.context, self.status = tokens, 0, context, status

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def take(self, value=None):
        token = self.peek()
        if value is not None and token[1] != value:
            raise ExpressionError(f"expected {value!r}, got {token[1]!r}")
        self.pos += 1
        return token

    def parse(self):
        value = self.or_()
        if self.pos != len(self.tokens):
            raise ExpressionError(f"unexpected {self.peek()[1]!r}")
        return value

    def or_(self):
        value = self.and_()
        while self.peek()[1] == "||":
            self.take()
            right = self.and_()
            value = value if truthy(value) else right
        return value

    def and_(self):
        value = self.eq()
        while self.peek()[1] == "&&":
            self.take()
            right = self.eq()
            value = right if truthy(value) else value
        return value

    def eq(self):
        value = self.unary()
        if self.peek()[1] in ("==", "!="):
            op = self.take()[1]
            right = self.unary()
            value = _equal(value, right) if op == "==" else not _equal(value, right)
        return value

    def unary(self):
        if self.peek()[1] == "!":
            self.take()
            return not truthy(self.unary())
        return self.primary()

    def primary(self):
        kind, value = self.take()
        if value == "(":
            inner = self.or_()
            self.take(")")
            return inner
        if kind == "str":
            return value[1:-1].replace("''", "'")
        if kind == "num":
            return float(value)
        if kind != "ident":
            raise ExpressionError(f"unexpected {value!r}")
        if value in ("true", "false"):
            return value == "true"
        if value == "null":
            return None
        if self.peek()[1] == "(":
            return self.call(value)
        current = self.context.get(value)
        while self.peek()[1] in (".", "["):
            if self.take()[1] == ".":
                key = self.take()[1]
            else:
                key = to_string(self.or_())
                self.take("]")
            current = current.get(key) if isinstance(current, dict) else None
        return current

    def call(self, name):
        self.take("(")
        args = []
        while self.peek()[1] != ")":
            args.append(self.or_())
            if self.peek()[1] == ",":
                self.take()
        self.take(")")
        if name in STATUS_FUNCTIONS:
            return {"success": self.status == "success", "failure": self.status == "failure", "always": True, "cancelled": False}[name]
        if name == "contains":
            haystack, needle = args
            if isinstance(haystack, list):
                return any(_equal(item, needle) for item in haystack)
            return to_string(needle).lower() in to_string(haystack).lower()
        if name == "startsWith":
            return to_string(args[0]).lower().startswith(to_string(args[1]).lower())
        raise ExpressionError(f"unsupported function {name}")


def evaluate(expression: str, context: dict, status: str = "success"):
    return _Parser(_tokenize(expression), context, status).parse()


def render(text: str, context: dict) -> str:
    """Replaces each ${{ ... }} in text with its value as a string."""
    return _TEMPLATE.sub(lambda m: to_string(evaluate(m.group(1), context)), text)


def condition(expression, context: dict, status: str) -> bool:
    """Evaluates a job or step `if:`. Without a status function, success() is implied."""
    if expression is None:
        return status == "success"
    if isinstance(expression, bool):
        return expression and status == "success"
    text = str(expression).strip()
    match = _TEMPLATE.fullmatch(text)
    if match:
        text = match.group(1)
    if not any(re.search(rf"\b{name}\s*\(", text) for name in STATUS_FUNCTIONS):
        if status != "success":
            return False
    return truthy(evaluate(text, context, status))
