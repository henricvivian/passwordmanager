# tests/test_password_manager.py

import unittest
import os
from src.password_manager import validate_password_strength, generate_strong_password

class TestPasswordManager(unittest.TestCase):

    def test_validate_password_strength(self):
        self.assertEqual(validate_password_strength("WeakPass1!")[0], False)
        self.assertEqual(validate_password_strength("StrongPass123!@#")[0], True)

    def test_generate_strong_password(self):
        password = generate_strong_password(16)
        self.assertTrue(len(password) == 16)
        self.assertTrue(any(char.islower() for char in password))
        self.assertTrue(any(char.isupper() for char in password))
        self.assertTrue(any(char.isdigit() for char in password))
        self.assertTrue(any(char in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for char in password))

if __name__ == '__main__':
    unittest.main()
