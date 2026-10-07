"""Тесты контракта, подготовленные до запуска мутационного тестирования."""

import itertools
import string
import unittest
from unittest.mock import patch

import password_generator as pg


class PasswordGeneratorTests(unittest.TestCase):
    def test_password_lengths_and_required_groups(self):
        for length in (4, 5, 8, 11, 12, 13, 64):
            with self.subTest(length=length):
                password = pg.generate_password(length)
                self.assertIsInstance(password, str)
                self.assertEqual(len(password), length)
                self.assertTrue(set(password) <= set(string.ascii_letters + string.digits + string.punctuation))
                for group in (string.ascii_lowercase, string.ascii_uppercase,
                              string.digits, string.punctuation):
                    self.assertTrue(any(char in group for char in password))

    def test_password_default(self):
        self.assertEqual(len(pg.generate_password()), 12)

    def test_password_rejects_short_lengths(self):
        for length in (-10, -1, 0, 1, 2, 3):
            with self.subTest(length=length), self.assertRaises(ValueError):
                pg.generate_password(length)

    def test_generators_reject_non_integer_lengths(self):
        for function in (pg.generate_password, pg.generate_pin):
            for length in (True, False, 4.0, "12", None, [], {}):
                with self.subTest(function=function.__name__, length=length), self.assertRaises(TypeError):
                    function(length)

    def test_password_random_source_and_shuffle(self):
        groups = (string.ascii_lowercase, string.ascii_uppercase,
                  string.digits, string.punctuation)
        alphabet = "".join(groups)
        for pick in (lambda chars: chars[0], lambda chars: chars[-1]):
            with patch.object(pg.secrets, "choice", side_effect=pick) as choice, \
                    patch.object(pg.secrets, "SystemRandom") as random:
                random.return_value.shuffle.side_effect = lambda chars: chars.reverse()
                password = pg.generate_password(6)
                expected = [pick(chars) for chars in groups] + [pick(alphabet)] * 2
                self.assertEqual(password, "".join(reversed(expected)))
                self.assertEqual([call.args[0] for call in choice.call_args_list], list(groups) + [alphabet, alphabet])
                random.return_value.shuffle.assert_called_once()

    def test_password_batch(self):
        for count, length in ((1, 4), (2, 5), (5, 12), (8, 20)):
            with self.subTest(count=count, length=length):
                passwords = pg.generate_passwords(count, length)
                self.assertIsInstance(passwords, list)
                self.assertEqual(len(passwords), count)
                for password in passwords:
                    self.assertEqual(len(password), length)
                    for group in (string.ascii_lowercase, string.ascii_uppercase,
                                  string.digits, string.punctuation):
                        self.assertTrue(any(char in group for char in password))

    def test_batch_defaults(self):
        passwords = pg.generate_passwords()
        self.assertEqual(len(passwords), 5)
        self.assertTrue(all(len(password) == 12 for password in passwords))

    def test_batch_calls_generator_for_each_password(self):
        with patch.object(pg, "generate_password", side_effect=["first", "second", "third"]) as generate:
            self.assertEqual(pg.generate_passwords(3, 14), ["first", "second", "third"])
            self.assertEqual([call.args for call in generate.call_args_list], [(14,), (14,), (14,)])

    def test_batch_rejects_invalid_count(self):
        for count in (-10, -1, 0):
            with self.subTest(count=count), self.assertRaises(ValueError):
                pg.generate_passwords(count)
        for count in (True, False, 1.0, "2", None, [], {}):
            with self.subTest(count=count), self.assertRaises(TypeError):
                pg.generate_passwords(count)

    def test_batch_propagates_length_errors(self):
        for length in (-1, 0, 3):
            with self.subTest(length=length), self.assertRaises(ValueError):
                pg.generate_passwords(1, length)
        for length in (True, False, 12.0, "12", None):
            with self.subTest(length=length), self.assertRaises(TypeError):
                pg.generate_passwords(1, length)

    def test_pin_lengths_alphabet_and_default(self):
        self.assertEqual(len(pg.generate_pin()), 6)
        for length in (1, 2, 5, 6, 7, 32):
            with self.subTest(length=length):
                pin = pg.generate_pin(length)
                self.assertIsInstance(pin, str)
                self.assertEqual(len(pin), length)
                self.assertTrue(set(pin) <= set("0123456789"))

    def test_pin_rejects_short_lengths(self):
        for length in (-10, -1, 0):
            with self.subTest(length=length), self.assertRaises(ValueError):
                pg.generate_pin(length)

    def test_pin_keeps_leading_zero(self):
        with patch.object(pg.secrets, "choice", side_effect=itertools.cycle("0123456789")) as choice:
            self.assertEqual(pg.generate_pin(12), "012345678901")
            self.assertEqual(choice.call_count, 12)
            self.assertTrue(all(call.args == ("0123456789",) for call in choice.call_args_list))

    def test_pin_can_generate_both_digit_endpoints(self):
        for index, expected in ((0, "0"), (-1, "9")):
            with self.subTest(index=index), patch.object(pg.secrets, "choice", side_effect=lambda chars: chars[index]):
                self.assertEqual(pg.generate_pin(1), expected)

    def test_strength_all_group_combinations_and_length_boundaries(self):
        representatives = "aA0!"
        for mask in range(1, 16):
            selected = "".join(char for index, char in enumerate(representatives) if mask & (1 << index))
            for length in (1, 3, 4, 7, 8, 9, 11, 12, 13, 20):
                if length < len(selected):
                    continue
                password = selected + selected[0] * (length - len(selected))
                expected = ("strong" if length >= 12 and mask == 15 else
                            "medium" if length >= 8 and mask.bit_count() >= 3 else "weak")
                with self.subTest(mask=mask, length=length):
                    self.assertEqual(pg.password_strength(password), expected)
                    self.assertIs(pg.is_strong_password(password), expected == "strong")

    def test_empty_unicode_spaces_and_all_punctuation(self):
        cases = [("", "weak"), (" " * 20, "weak"), ("Яё９🙂" * 4, "weak"),
                 ("aA0" + " " * 9, "medium"), ("aA0!" + " " * 8, "strong")]
        cases.extend(("aA0" + char + "a" * 8, "strong") for char in string.punctuation)
        for password, expected in cases:
            with self.subTest(password=password):
                self.assertEqual(pg.password_strength(password), expected)
                self.assertIs(pg.is_strong_password(password), expected == "strong")

    def test_strength_functions_reject_non_strings(self):
        for function in (pg.password_strength, pg.is_strong_password):
            for password in (None, True, False, 123, 1.5, b"aA0!aaaaaaaa", [], {}):
                with self.subTest(function=function.__name__, password=password), self.assertRaises(TypeError):
                    function(password)

    def test_generated_default_password_is_strong(self):
        password = pg.generate_password()
        self.assertEqual(pg.password_strength(password), "strong")
        self.assertIs(pg.is_strong_password(password), True)


if __name__ == "__main__":
    unittest.main()
