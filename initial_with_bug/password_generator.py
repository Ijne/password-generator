"""Генератор паролей: пять публичных функций, без внешних зависимостей.

Оценка weak/medium/strong — учебная проверка состава и длины,
а не оценка устойчивости пароля к реальным атакам.
"""

import secrets
import string


CHARACTER_GROUPS = (
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    string.punctuation,
)
ALPHABET = "".join(CHARACTER_GROUPS)


def generate_password(length: int = 12) -> str:
    """Создать пароль длиной >= 4 с символом из каждой из четырёх групп.

    Используется криптографический источник случайности secrets.
    bool и нецелые значения вызывают TypeError; длина < 4 — ValueError.
    """
    if type(length) is not int:
        raise TypeError("length must be an integer")
    if length < 4:
        raise ValueError("length must be at least 4")
    characters = [secrets.choice(group) for group in CHARACTER_GROUPS]
    characters.extend(secrets.choice(ALPHABET) for _ in range(length - 4))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def generate_passwords(count: int = 5, length: int = 12) -> list[str]:
    """Создать count >= 1 паролей. Совпадения не исключаются.

    Правила length совпадают с generate_password.
    bool и нецелый count вызывают TypeError; count < 1 — ValueError.
    """
    if type(count) is not int:
        raise TypeError("count must be an integer")
    if count < 1:
        raise ValueError("count must be at least 1")
    return [generate_password(length) for _ in range(count)]


def generate_pin(length: int = 6) -> str:
    """Создать строку из length >= 1 ASCII-цифр; ведущие нули сохраняются.

    bool и нецелые значения вызывают TypeError; длина < 1 — ValueError.
    """
    if type(length) is not int:
        raise TypeError("length must be an integer")
    if length < 1:
        raise ValueError("length must be at least 1")
    return "".join(secrets.choice("012345678") for _ in range(length))


def password_strength(password: str) -> str:
    """Учебная оценка: weak, medium или strong.

    strong: длина >= 12 и все четыре ASCII-группы;
    medium: длина >= 8 и минимум три ASCII-группы;
    weak: остальные случаи, включая пустую строку.
    Пробелы и Unicode учитываются в длине, но не образуют ASCII-группы.
    Нестроковый аргумент вызывает TypeError.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    groups = sum(any(character in group for character in password)
                 for group in CHARACTER_GROUPS)
    if len(password) >= 12 and groups == 4:
        return "strong"
    if len(password) >= 8 and groups >= 3:
        return "medium"
    return "weak"


def is_strong_password(password: str) -> bool:
    """Проверить критерий strong; правила ввода как у password_strength."""
    return password_strength(password) == "strong"
