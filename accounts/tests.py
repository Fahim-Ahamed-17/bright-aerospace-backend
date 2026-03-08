from django.db import connection
from django.test import TestCase

from .models import User


class UserPasswordHashingTests(TestCase):
    """Test that passwords are hashed when using create_user and set_password."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        db_name = connection.settings_dict["NAME"]
        if not db_name.startswith("test_"):
            raise RuntimeError(
                "Tests must not run against the main database. "
                f"Current database name: {db_name!r}. "
                "Django normally uses a database prefixed with 'test_' (e.g. test_bright_aerospace)."
            )

    def test_create_user_hashes_password(self):
        """Password must not be stored in plain text."""
        raw_password = "mySecretPass123"
        user = User.objects.create_user(
            username="testuser",
            password=raw_password,
            role="student",
        )
        self.assertNotEqual(user.password, raw_password)
        self.assertTrue(len(user.password) > 20)
        # Argon2 hashes start with 'argon2'
        self.assertTrue(
            user.password.startswith("argon2"),
            "Expected Argon2 hasher; password should start with 'argon2'",
        )

    def test_check_password_returns_true_for_correct_password(self):
        """check_password must accept the original password."""
        raw_password = "correctPassword456"
        user = User.objects.create_user(
            username="checkuser",
            password=raw_password,
            role="company",
        )
        self.assertTrue(user.check_password(raw_password))

    def test_check_password_returns_false_for_wrong_password(self):
        """check_password must reject wrong passwords."""
        user = User.objects.create_user(
            username="wronguser",
            password="theRealPassword",
            role="student",
        )
        self.assertFalse(user.check_password("wrongGuess"))
        self.assertFalse(user.check_password(""))

    def test_set_password_hashes_before_save(self):
        """set_password() must hash the password; save() persists it."""
        user = User.objects.create_user(username="setpassuser", password="initial", role="admin")
        new_password = "newHashedPass789"
        user.set_password(new_password)
        user.save()
        user.refresh_from_db()
        self.assertNotEqual(user.password, new_password)
        self.assertTrue(user.check_password(new_password))
        self.assertFalse(user.check_password("initial"))


from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

class RegistrationTokenTests(APITestCase):
    """Test that the registration API returns JWT tokens."""

    def test_registration_returns_tokens(self):
        url = '/api/register/'  # Hardcoded or use reverse if named
        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "Password123!",
            "role": "student"
        }
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('tokens', response.data)
        self.assertIn('access', response.data['tokens'])
        self.assertIn('refresh', response.data['tokens'])
        
        # Verify that the tokens are not empty
        self.assertTrue(len(response.data['tokens']['access']) > 0)
        self.assertTrue(len(response.data['tokens']['refresh']) > 0)

    def test_registration_duplicate_username(self):
        # First registration
        data = {
            "username": "duplicate",
            "email": "first@example.com",
            "password": "Password123!",
            "role": "student"
        }
        self.client.post('/api/register/', data, format='json')
        
        # Second registration with same username
        data["email"] = "second@example.com"
        response = self.client.post('/api/register/', data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], "Username already taken")


class LoginTokenTests(APITestCase):
    """Test that the login API authenticates users and returns JWT tokens."""

    def setUp(self):
        self.username = "loginuser"
        self.password = "LoginPass123!"
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
            email="login@example.com",
            role="company"
        )
        self.url = '/api/login/'

    def test_login_success_returns_tokens(self):
        data = {
            "username": self.username,
            "password": self.password
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.username)
        self.assertEqual(response.data['role'], 'company')
        self.assertIn('tokens', response.data)
        self.assertIn('access', response.data['tokens'])
        self.assertIn('refresh', response.data['tokens'])

    def test_login_failure_invalid_credentials(self):
        data = {
            "username": self.username,
            "password": "wrongpassword"
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Invalid credentials")

    def test_login_missing_fields(self):
        data = {"username": self.username}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
