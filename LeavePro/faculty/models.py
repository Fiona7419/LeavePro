from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Permission, Group
from django.core.validators import RegexValidator

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, role=None, department=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)

        valid_roles = dict(self.model.ROLE_CHOICES)  # Extract valid role keys
        if role not in valid_roles:
            raise ValueError(f"Invalid role '{role}'. Choose from: {list(valid_roles.keys())}")

        if role is None:
            raise ValueError("Role must be specified when creating a user.")

        user = self.model(username=username, email=email, role=role, department=department, **extra_fields)
        user.set_password(password or username)  # Set password

        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields["role"] = "admin"

        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ("admin", "Admin"),
        ("hod", "HOD"),
    ]

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default="admin")
    department = models.ForeignKey("Department", on_delete=models.SET_NULL, null=True, blank=True)
    email = models.EmailField(unique=True, null=False, blank=False)

    # ✅ Override username validation (ALLOW SPACES)
    username = models.CharField(
        max_length=150,
        unique=True,
        validators=[
            RegexValidator(
                regex=r"^[\w\s]+$",  # Allows letters, numbers, spaces, and underscores
                message="Username can only contain letters, numbers, and spaces.",
            )
        ],
    )

    def __str__(self):
        return f"{self.username} ({self.role})"


class Department(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

class LeaveEntitlement(models.Model):
    FACULTY_TYPES = [
        ("Permanent", "Permanent"),
        ("Temporary", "Temporary"),
        ("Non-Teaching", "Non-Teaching"),
    ]
    faculty_type = models.CharField(max_length=50, choices=FACULTY_TYPES, unique=True)  # Permanent, Temporary, etc.
    casual_leave = models.FloatField(default=12)
    sick_leave = models.FloatField(default=22.5)
    earned_leave = models.FloatField(default=15)
    personal_leave = models.FloatField(default=10)
    lwop = models.FloatField(default=0)

    def __str__(self):
        return f"{self.faculty_type} Entitlement"

class Faculty(models.Model):
    faculty_id = models.CharField(max_length=20, unique=True, primary_key=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    department = models.ForeignKey(Department, on_delete=models.CASCADE, null=True, blank=True)
    designation = models.CharField(max_length=100, null=True, blank=True)

    total_leaves = models.FloatField(default=0)  # Default leave entitlement
    leaves_taken = models.FloatField(default=0)  # Track approved leaves
    leave_balance = models.FloatField(default=0)  # Remaining leaves

    phone_number = models.CharField(max_length=15, null=True, blank=True)
    date_of_joining = models.DateField(null=True, blank=True)

    faculty_type = models.CharField(max_length=50, null=True, blank=True)
    leave_entitlement = models.ForeignKey(LeaveEntitlement, on_delete=models.SET_NULL, null=True, blank=True)

    def save(self, *args, **kwargs):
        """Automatically assigns leave entitlement based on faculty type."""
        if not self.leave_entitlement:  # Only assign if it's not set
            try:
                entitlement = LeaveEntitlement.objects.get(faculty_type=self.faculty_type)
                self.leave_entitlement = entitlement
                self.total_leaves = entitlement.casual_leave + entitlement.sick_leave + entitlement.earned_leave + entitlement.personal_leave
                self.leave_balance = self.total_leaves  # Initial balance = total leaves
            except ObjectDoesNotExist:
                print(f"No LeaveEntitlement found for faculty_type: {self.faculty_type}")

        super().save(*args, **kwargs)

    def update_leave_balance(self):
        """ Updates leave balance when a leave is approved """
        approved_leaves = Leave.objects.filter(faculty=self, status="Approved")

        # Calculate total leave days taken
        leave_days = sum((leave.end_date - leave.start_date).days + 1 for leave in approved_leaves)

        self.leaves_taken = leave_days
        self.leave_balance = max(0, self.total_leaves - leave_days)  # Prevent negative balance
        self.save()

    def __str__(self):
        return self.name


from django.db import models


class Leave(models.Model):
    LEAVE_TYPES = [
        ('Sick Leave', 'Sick Leave'),
        ('Casual Leave', 'Casual Leave'),
        ('Earned Leave', 'Earned Leave'),
        ('Privilege Leave', 'Privilege Leave'),
        ('Leave Without Pay', 'Leave Without Pay'),
        ('Other', 'Other'),
    ]

    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    ]

    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE, related_name='leave_set')
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPES)
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="Pending")

    def save(self, *args, **kwargs):
        """ Override save method to update faculty leave balance when approved """
        super().save(*args, **kwargs)  # Save leave request first

        if self.status == "Approved":
            self.faculty.update_leave_balance()  # Update faculty's leave balance


