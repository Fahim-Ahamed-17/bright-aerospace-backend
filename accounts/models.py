from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .validators import validate_strong_password

class User(AbstractUser):
    ROLE_CHOICES = (
        ('student', 'Student'),
        ('company', 'Company'),
        ('admin', 'Admin'),
    )

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='student'
    )


    email = models.EmailField(unique=True)

    def clean(self):
        super().clean()
        try:
            validate_email(self.email)
        except ValidationError:
            raise ValidationError("Invalid email address.")
        validate_strong_password(self.password)
        

    def __str__(self):
        return f"{self.username} - {self.role}"
