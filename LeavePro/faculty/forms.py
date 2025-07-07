from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm
from .models import Faculty, Leave, Department, CustomUser

ROLE_CHOICES = [
    ("admin", "Admin"),
    ("hod", "HOD"),
]

class CustomLoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={"id": "id_username", "class": "form-control", "placeholder": "Enter Username"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"id": "id_password", "class": "form-control", "placeholder": "Enter Password"})
    )
    role = forms.ChoiceField(
        choices=CustomUser.ROLE_CHOICES,  # ✅ Use role choices from the model
        widget=forms.Select(attrs={"id": "id_role", "class": "form-control"})
    )
    department = forms.ModelChoiceField(
        queryset=Department.objects.all(),
        required=False,
        widget=forms.Select(attrs={"id": "id_department", "class": "form-control"})
    )

    def clean_role(self):
        """Ensure role is always lowercase to match the database."""
        return self.cleaned_data["role"].strip().lower()

class SignupForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Enter Password"}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Confirm Password"}))

    class Meta:
        model = CustomUser
        fields = ["username", "email", "password", "role", "department"]

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")

        return cleaned_data

class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))

class FacultyForm(forms.ModelForm):
    department = forms.ModelChoiceField(
        queryset=Department.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="Select Department"
    )

    class Meta:
        model = Faculty
        fields = ['faculty_id', 'name', 'email', 'department', 'designation', 'phone_number', 'date_of_joining', 'faculty_type']
        widgets = {
            'faculty_id': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Faculty ID'}),
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Faculty Name'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter Email'}),
            'designation': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Designation'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Phone Number'}),
            'date_of_joining': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'faculty_type': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Faculty Type'}),
        }

class LeaveForm(forms.ModelForm):
    faculty_id = forms.CharField(max_length=20, label="Faculty ID")
    faculty_name = forms.CharField(max_length=100, label="Faculty Name")
    leave_type = forms.ChoiceField(choices=Leave.LEAVE_TYPES, label="Leave Type")
    start_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), label="Start Date")
    end_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), label="End Date")
    reason_for_leave = forms.CharField(widget=forms.Textarea(attrs={'rows': 4, 'cols': 50}), required=False,
                                       label="Reason for Leave")
    person_detailed_to = forms.CharField(max_length=255, required=False, label="Person Detailed To")
    place_of_application = forms.CharField(max_length=255, required=False, label="Place of Application")

    class Meta:
        model = Leave
        exclude = ['faculty', 'status', 'sanctioned_by', 'sanctioned_date']
        fields = ['faculty_id', 'faculty_name', 'leave_type', 'start_date', 'end_date',
                  'reason_for_leave', 'person_detailed_to', 'place_of_application']
        widgets = {'faculty': forms.HiddenInput()}

    def clean(self):
        cleaned_data = super().clean()
        faculty_id = cleaned_data.get('faculty_id')
        faculty_name = cleaned_data.get('faculty_name')
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        leave_type = cleaned_data.get('leave_type')

        # Validate faculty existence
        try:
            faculty = Faculty.objects.get(faculty_id=faculty_id, name=faculty_name)
        except Faculty.DoesNotExist:
            raise forms.ValidationError("Faculty with this ID and Name does not exist.")

        # Validate leave dates
        if start_date and end_date:
            if end_date < start_date:
                raise forms.ValidationError("End date cannot be before start date.")
            if start_date < date.today():
                raise forms.ValidationError("Leave cannot start in the past.")

        # Set faculty in cleaned data
        cleaned_data['faculty'] = faculty
        return cleaned_data

    def clean(self):
        cleaned_data = super().clean()
        faculty_id = cleaned_data.get('faculty_id')
        faculty_name = cleaned_data.get('faculty_name')

        try:
            faculty = Faculty.objects.get(faculty_id=faculty_id, name=faculty_name)
        except Faculty.DoesNotExist:
            raise forms.ValidationError("Faculty with this ID and Name does not exist.")

        cleaned_data['faculty'] = faculty
        return cleaned_data

class ReportForm(forms.Form):
    department = forms.CharField(max_length=100, required=False, label="Department")  # If it's a CharField
    faculty = forms.ModelChoiceField(queryset=Faculty.objects.all(), required=False, label="Faculty")
    start_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), required=False, label="Start Date")
    end_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), required=False, label="End Date")
    report_type = forms.ChoiceField(
        choices=[('all', 'All'), ('weekly', 'Weekly'), ('monthly', 'Monthly'), ('yearly', 'Yearly')],
        required=False,
        label="Report Type"
    )
