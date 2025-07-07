from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.views import PasswordResetView
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from fuzzywuzzy import process
from collections import Counter
from .forms import FacultyForm, CustomLoginForm, LeaveForm, SignupForm
from .models import Faculty, Leave, CustomUser, Department
from datetime import timedelta, date, datetime
from django.utils import timezone
from django.core.paginator import Paginator
import csv
import json
from django.urls import reverse_lazy
from django.http import HttpResponse
from openpyxl import Workbook
import pandas as pd
import re
import spacy, dateparser
from django.contrib.auth.decorators import login_required

def home(request):
    return render(request, 'index.html')

def custom_login(request):
    print("DEBUG: Entered custom_login view")
    form = CustomLoginForm(request.POST or None)
    departments = Department.objects.all()

    if request.method == "POST":
        print("DEBUG: Received POST request")
        if form.is_valid():
            print("DEBUG: Form is valid")
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            role = form.cleaned_data["role"].strip().lower()

            # Authenticate user
            user = authenticate(request, username=username, password=password)

            if user is None:
                print("DEBUG: Authentication failed")
                messages.error(request, "Invalid username or password.")
                return redirect("login")

            if user.role and user.role.lower() != role:
                print(f"DEBUG: User role mismatch. Expected: {role}, Found: {user.role}")
                messages.error(request, "Invalid role detected.")
                return redirect("login")

            print(f"DEBUG: Logging in user {user.username}")
            login(request, user)

            print(f"DEBUG: Session Key After Login: {request.session.session_key}")
            print(f"DEBUG: User in Session: {request.user}")

            return redirect("dashboard")

    return render(request, "login.html", {"form": form, "departments": departments})

def signup(request):
    print("DEBUG: Entered signup view")
    form=SignupForm(request.POST or None)
    departments = Department.objects.all()

    if request.method == "POST":
        print("DEBUG: Received POST request")

        username = request.POST.get("username", "").strip()  # ✅ Strip spaces
        password = request.POST.get("password", "")
        email = request.POST.get("email", "").strip()
        role = request.POST.get("role", "admin").strip().lower()
        department_id = request.POST.get("department", None)

        # ✅ Basic validations
        if not username or not password or not email:
            messages.error(request, "All fields are required.")
            print("DEBUG: Missing required fields")
            return redirect("signup")

        if " " in username:  # ❌ Prevent spaces in username
            messages.error(request, "Username cannot contain spaces.")
            print("DEBUG: Invalid username format")
            return redirect("signup")

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            print("DEBUG: Username already exists")
            return redirect("signup")

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            print("DEBUG: Email already exists")
            return redirect("signup")

        # ✅ Get department (if applicable)
        department = None
        if department_id:
            try:
                department = Department.objects.get(id=department_id)
            except Department.DoesNotExist:
                messages.error(request, "Invalid department selected.")
                print("DEBUG: Invalid department ID")
                return redirect("signup")

        # ✅ Create new user
        user = CustomUser.objects.create(
            username=username,
            email=email,
            role=role,
            department=department,
            password=make_password(password),  # Hashing the password manually
        )

        print(f"DEBUG: User {user.username} created successfully")

        # ✅ Auto-login user after signup
        login(request, user)
        print(f"DEBUG: Logged in user {user.username}")

        return redirect("dashboard")  # Redirect to dashboard after signup

    return render(request, "signup.html",  {"form": form, "departments": departments})

@login_required(login_url='login')
def dashboard(request):
    user = request.user

    # Debug logs
    print(f"DEBUG: Logged-in user: {user.username if user.is_authenticated else 'Anonymous'}, "
          f"Role: {user.role if hasattr(user, 'role') else 'No Role'}, "
          f"Department: {user.department if hasattr(user, 'department') else 'No Department'}")

    # Ensure the user is authenticated before accessing attributes
    if not user.is_authenticated:
        print("DEBUG: User is not authenticated. Redirecting to login.")
        return redirect("login")

    # Ensure role is assigned
    if not hasattr(user, 'role') or not user.role:
        messages.error(request, "No role assigned. Contact admin.")
        return redirect("login")

    role = user.role.lower().strip()

    if role == "admin":
        leave_records = Leave.objects.select_related("faculty").all()
        total_faculty = Faculty.objects.count()
        upcoming_leaves = Leave.objects.filter(start_date__gte=date.today())
        leave_data = Leave.objects.values_list('leave_type', flat=True)
        leave_count = dict(Counter(leave_data))

        leave_count_json=json.dumps(leave_count, ensure_ascii=False)

        faculty_leave_summary = {
            faculty.faculty_id: {
                "name": faculty.name,
                "total_leaves": faculty.total_leaves,
                "leaves_taken": faculty.leaves_taken,
                "remaining_leaves": faculty.total_leaves - faculty.leaves_taken,
            }
            for faculty in Faculty.objects.all()
        }

        print(
            f"DEBUG: Admin Dashboard Loaded - Total Faculty: {total_faculty}, Upcoming Leaves: {len(upcoming_leaves)}")

        return render(request, "dashboard.html", {
            "user": user,
            "total_faculty": total_faculty,
            "upcoming_leaves": upcoming_leaves,
            "leave_summary": faculty_leave_summary,
            "leave_count_json": leave_count_json,
        })

    elif role == "hod":
        if not hasattr(user, "department") or not user.department:
            messages.error(request, "No department assigned. Contact admin.")
            return redirect("login")

        department_faculty = user.department.faculty_set.all()
        total_faculty = department_faculty.count()
        pending_leaves = Leave.objects.filter(faculty__department=user.department, status="Pending")
        total_leaves = Leave.objects.filter(faculty__department=user.department).count()

        print(
            f"DEBUG: HOD Dashboard Loaded - Department: {user.department}, Total Faculty: {total_faculty}, Pending Leaves: {len(pending_leaves)}")

        return render(request, "hod_dashboard.html", {
            "user": user,
            "department": user.department,
            "pending_leaves": pending_leaves,
            "total_faculty": total_faculty,
            "total_leaves": total_leaves,
        })

    # If role is invalid
    messages.error(request, "Invalid role detected.")
    print(f"DEBUG: Invalid Role Detected for User: {user.username} - Role: {user.role}")
    return redirect("login")

@login_required
def approve_leave(request, leave_id):
    user = request.user

    if user.role.lower() != "hod":
        messages.error(request, "Unauthorized access!")
        return redirect("dashboard")

    leave = get_object_or_404(Leave, id=leave_id)

    # Ensure the leave belongs to the HOD's department
    if leave.faculty.department != user.department:
        messages.error(request, "You can only approve leaves for your department!")
        return redirect("dashboard")

    leave.status = "Approved"
    leave.save()

    messages.success(request, f"Leave request for {leave.faculty.name} approved!")
    return redirect("dashboard")

def custom_logout(request):
    logout(request)
    return redirect('login')

class CustomPasswordResetView(PasswordResetView):
    template_name = "password_reset.html"
    success_url = reverse_lazy("password_reset_done")
    email_template_name = "password_reset_email"

EXPECTED_COLUMNS = {
    "Faculty Id": ["Faculty Id", "ID", "Faculty Code"],
    "Name": ["Name", "Faculty Name", "Full Name"],
    "Email": ["Email", "Email ID", "Email Address"],
    "Phone Number": ["Phone", "Phone Number", "Mobile Number", "Contact No"],
    "Department": ["Department", "Dept", "Faculty Department"],
    "Designation": ["Designation", "Title", "Role"],
    "Faculty Type": ["Faculty Type", "Type"],
    "Date of Joining": ["Date of Joining", "Joining Date", "DOJ"]
}

def clean_date_column(df, column_name):
    """
    Convert the 'Date of Joining' column to YYYY-MM-DD format.
    Handles both 'DD-MM-YYYY' and 'YYYY-MM-DD HH:MM:SS' formats.
    """
    if column_name in df.columns:
        df[column_name] = pd.to_datetime(df[column_name], errors="coerce").dt.strftime("%Y-%m-%d")
    return df

def match_columns(df):
    """
    Matches actual columns in the Excel file to expected columns using fuzzy logic.
    Returns a dictionary of {actual_column: expected_column}.
    """
    column_mapping = {}
    for expected, variations in EXPECTED_COLUMNS.items():
        best_match, score = process.extractOne(expected, df.columns, score_cutoff=70)
        if best_match:
            column_mapping[best_match] = expected  # Map actual name to expected name

    return column_mapping

def add_faculty(request):
    if request.method == "POST":
        print("POST request received")  # Debugging

        if "excel_file" in request.FILES:
            print("Excel file detected")  # Debugging

            excel_file = request.FILES["excel_file"]

            try:
                df = pd.read_excel(excel_file, engine="openpyxl")

                # Standardize column names: strip spaces, convert to title case
                df.columns = df.columns.str.strip().str.title()

                df = clean_date_column(df, "Date Of Joining")

                # Debugging: Print detected column names
                print("DEBUG: Original Excel Columns:", df.columns.tolist())

                # Get column mappings
                column_mapping = match_columns(df)
                print("DEBUG: Column Mapping:", column_mapping)

                # Rename columns based on mapping
                df.rename(columns=column_mapping, inplace=True)

                # Fill missing values with placeholders
                df.fillna({
                    "Name": "Unknown",
                    "Email": "no-email@example.com",
                    "Phone Number": "0000000000",
                    "Department": "Not Assigned",
                    "Designation": "Unknown",
                    "Faculty Type": "Unknown",
                    "Date of Joining": "2000-01-01",
                }, inplace=True)

                # Debugging: Print processed data
                print("DEBUG: Processed Excel data:\n", df.head())

                # Save to database
                for _, row in df.iterrows():
                    # Get or create Department instance
                    department_name = row["Department"]
                    department, _ = Department.objects.get_or_create(name=department_name)

                    # Create Faculty instance
                    Faculty.objects.create(
                        faculty_id=row.get("Faculty Id", None),
                        name=row["Name"],
                        email=row["Email"],
                        phone_number=row["Phone Number"],  # FIXED: Match DB field name
                        department=department,  # FIXED: Pass Department instance
                        designation=row["Designation"],
                        faculty_type=row["Faculty Type"],
                        date_of_joining=row["Date of Joining"],
                    )

                messages.success(request, "✅ Data uploaded successfully! Missing fields were filled with placeholders.")
                return redirect("faculty_list")

            except Exception as e:
                messages.error(request, f"❌ Error processing file: {str(e)}")
                return redirect("faculty_list")

        print("No Excel file detected")  # Debugging

        # Manual Form Submission Handling
        form = FacultyForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ Faculty added successfully!")
            return redirect("faculty_list")
        else:
            messages.error(request, "❌ Error submitting form. Please check for errors.")
            return render(request, "faculty_form.html", {"form": form})

    else:
        form = FacultyForm()

    return render(request, "faculty_form.html", {"form": form})

def faculty_list(request):
    faculties = Faculty.objects.all()
    return render(request, 'faculty_list.html', {'faculties': faculties})

def faculty_detail(request, faculty_id):
    faculty = get_object_or_404(Faculty, pk=faculty_id)
    leaves = Leave.objects.filter(faculty=faculty).order_by('-start_date')

    # Calculate leave balance (Example: 12 Casual Leaves per year)
    total_cl = 12  # Adjust based on your institution's rules
    used_cl = leaves.filter(leave_type="Casual Leave", status="Approved").count()
    leave_balance = total_cl - used_cl

    return render(request, 'faculty_detail.html', {
        'faculty': faculty,
        'leaves': leaves,
        'leave_balance': leave_balance,
    })

nlp = spacy.load("en_core_web_sm")

def extract_dates(text):
    # 🔹 Try regex-based date range extraction first
    date_range_match = re.search(r"(\d{1,2}(?:st|nd|rd|th)?\s+\w+\s+\d{4})\s*(to|-)\s*(\d{1,2}(?:st|nd|rd|th)?\s+\w+\s+\d{4})", text, re.IGNORECASE)
    if date_range_match:
        start_date = dateparser.parse(date_range_match.group(1), settings={'PREFER_DATES_FROM': 'future'})
        end_date = dateparser.parse(date_range_match.group(3), settings={'PREFER_DATES_FROM': 'future'})
        return start_date.date() if start_date else None, end_date.date() if end_date else None

    # 🔹 Fallback: Use NLP extraction if regex fails
    dates = []
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ == "DATE":
            parsed_date = dateparser.parse(ent.text, settings={'PREFER_DATES_FROM': 'future'})
            if parsed_date:
                dates.append(parsed_date.date())

    start_date = dates[0] if len(dates) > 0 else None
    end_date = dates[1] if len(dates) > 1 else start_date  # Single date means same start & end

    return start_date, end_date

def extract_leave_details(text):
    doc = nlp(text)

    # Debug: Show extracted NLP entities
    print("\n🔍 DEBUG: Extracted Named Entities (NLP)")
    for ent in doc.ents:
        print(f"  {ent.text} → {ent.label_}")

    # ✅ 1️⃣ Extract Faculty Name (Improved)
    faculty_name = None
    leave_keywords = [
        "casual leave", "sick leave", "medical leave", "earned leave",
        "compensatory leave", "on duty leave", "maternity leave", "paternity leave"
    ]

    for ent in doc.ents:
        if ent.label_ == "PERSON" and "leave" not in ent.text.lower():
            faculty_name = ent.text.strip()
            faculty_name = re.sub(r'\s*(Faculty ID|EmpID|HOD).*$', '', faculty_name, flags=re.IGNORECASE)
            break

    # 🔹 Backup Strategy: Find "Best regards, [Name]"
    if not faculty_name:
        name_match = re.search(r"Best regards,\s*\r?\n([\w\s]+)", text, re.IGNORECASE)
        if name_match:
            faculty_name = name_match.group(1).strip()

    # 🔹 LAST RESORT: Extract the first two capitalized words (Heuristic)
    if not faculty_name:
        name_match = re.search(r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b", text)
        if name_match:
            faculty_name = f"{name_match.group(1)} {name_match.group(2)}"

    faculty_name = faculty_name or "Unknown"

    start_date, end_date = extract_dates(text)

    # ✅ 3️⃣ Extract Faculty ID (More Flexible)
    faculty_id = "Unknown"
    faculty_id_match = re.search(r"(Faculty\s*ID|Employee\s*ID|EmpID|Faculty\s*No|ID)\s*[:\-]?\s*(\d{3,6})", text,
                                 re.IGNORECASE)
    if faculty_id_match:
        faculty_id = faculty_id_match.group(2).strip()

    # ✅ 4️⃣ Extract Leave Type
    leave_type = "Other"
    for key in leave_keywords:
        if key in text.lower():
            leave_type = key.title()
            break

    # ✅ 5️⃣ Extract Reason for Leave
    reason = "Not provided"
    reason_match = re.search(r"(because|due to|for the reason that|as I|since|I am applying for leave due to)(.*)",
                             text, re.IGNORECASE)
    if reason_match:
        reason = reason_match.group(2).strip()

    return leave_type, start_date, end_date, faculty_name, faculty_id, reason

def apply_leave(request):
    message = None  # UI feedback message
    extracted_data = None  # Store extracted leave details
    form = LeaveForm()  # Ensure form instance for manual entry mode

    if request.method == 'POST':
        entry_mode = request.POST.get('entry_mode')

        # 🛑 Handle "Confirm and Submit" Button
        if 'confirm' in request.POST:
            print("✅ DEBUG: Confirm button clicked!")  # Debugging log

            faculty_id = request.POST.get('faculty_id')
            faculty = Faculty.objects.filter(faculty_id=faculty_id).first()

            if faculty:
                leave = Leave(
                    faculty=faculty,
                    leave_type=request.POST.get('leave_type', 'Other'),
                    start_date=request.POST.get('start_date'),
                    end_date=request.POST.get('end_date'),
                    reason=request.POST.get('reason', 'Not provided'),
                    status="Pending"
                )
                leave.save()

                messages.success(request, "✅ Leave application submitted successfully!")
                return redirect('faculty_list')  # Redirect after saving

            else:
                messages.error(request, "❌ Faculty record not found! Contact admin.")
                return redirect('apply_leave')

        # 📌 NLP-Based Email Extraction Mode
        elif entry_mode == 'email':
            email_text = request.POST.get('email_text', '').strip()
            extracted_data = extract_leave_details(email_text)
            print("Extracted Data:", extracted_data)

            if extracted_data:
                leave_type, start_date, end_date, faculty_name, faculty_id, reason = extracted_data

                # ✅ Fix: Check if Dates are Missing
                if not start_date or not end_date:
                    messages.error(request, "Error: Unable to extract leave dates. Please check the email content.")
                    return redirect('apply_leave')

                faculty = Faculty.objects.filter(faculty_id=faculty_id).first()

                if faculty:
                    messages.info(request, "Please review the extracted details before confirming.")
                    return render(request, 'leave_form.html', {
                        "faculty_name": faculty.name,
                        "faculty_email": faculty.email,
                        "faculty_id": faculty.faculty_id,
                        "department": faculty.department.name,
                        "designation": faculty.designation,  # ✅ Just for display, NOT saved in Leave model
                        "leave_type": leave_type,
                        "start_date": start_date.strftime("%Y-%m-%d") if start_date else "",
                        "end_date": end_date.strftime("%Y-%m-%d") if end_date else "",
                        "reason": reason,
                        "email_text": email_text,  # Retain email text for reference
                        "show_summary": True  # Flag to show the summary
                    })

                else:
                    messages.error(request, "Faculty not found for the extracted details.")
                    return redirect('apply_leave')

        # 📌 Manual Entry Mode
        elif entry_mode == 'manual':
            form = LeaveForm(request.POST)
            if form.is_valid():
                leave = form.save(commit=False)

                faculty_id = request.POST.get('faculty_id')
                faculty = Faculty.objects.filter(faculty_id=faculty_id).first()

                if faculty:
                    leave.faculty = faculty
                    leave.person_detailed_to = request.POST.get('person_detailed_to', '')
                    leave.place_of_application = request.POST.get('place_of_application', '')
                    leave.status = 'Pending'
                    leave.save()

                    messages.success(request, "Leave application submitted successfully!")
                    return redirect('faculty_list')
                else:
                    messages.error(request, "Faculty record not found. Contact admin.")
            else:
                messages.error(request, "There were errors in the form. Please check your inputs.")

    return render(request, 'leave_form.html', {'form': form, 'message': message})

def calculate_leave_data(faculty, leave_records):
    leave_types = ["Casual Leave", "Earned Leave", "Sick Leave", "Personal Leave", "LWOP"]
    leave_data = {}

    for leave_type in leave_types:
        # Fetch all leaves of this type for the faculty
        leaves = leave_records.filter(faculty=faculty, leave_type=leave_type)

        # 🔹 Entitled: Default values (modify as needed)
        entitled = {
            "Casual Leave": 12,
            "Sick Leave": 22.5,
            "Earned Leave": 15,
            "Personal Leave": 10,
            "LWOP": 0,
        }.get(leave_type, 0)

        # 🔹 Availed: Approved leave days
        availed = sum(
            (leave.end_date - leave.start_date).days + 1 for leave in leaves.filter(status="Approved")
        )

        # 🔹 Availing: Pending leave days
        availing = sum(
            (leave.end_date - leave.start_date).days + 1 for leave in leaves.filter(status="Pending")
        )

        # 🔹 Balance: Remaining leave balance
        balance = entitled - availed - availing if entitled >= availed + availing else 0

        leave_data[leave_type] = {
            "Entitled": entitled,
            "Availed": availed,
            "Availing": availing,
            "Balance": balance
        }

    return leave_data

def generate_report(request):
    sort_by = request.GET.get('sort_by', 'name')  # Default sorting by name

    # Sorting Faculty Data
    faculties = Faculty.objects.all().order_by(sort_by)
    faculty_leave_data = {faculty: Leave.objects.filter(faculty=faculty) for faculty in faculties}

    # Pagination
    paginator = Paginator(list(faculty_leave_data.items()), 10)  # Show 10 records per page
    page_number = request.GET.get('page')
    paginated_faculty_data = paginator.get_page(page_number)

    return render(request, 'reporting.html', {
        'paginated_faculty_data': paginated_faculty_data,
        'sort_by': sort_by
    })


def export_to_csv(data):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="leave_report.csv"'
    writer = csv.writer(response)
    writer.writerow(['Faculty/Department', 'Leave Type', 'Start Date', 'End Date', 'Description', 'Status'])

    for key, leaves in data.items():
        writer.writerow([key])
        for leave in leaves:
            writer.writerow([
                leave.faculty.name if hasattr(leave.faculty, 'name') else key,
                leave.leave_type,
                leave.start_date,
                leave.end_date,
                leave.description,
                leave.status,
            ])
    return response

def export_to_excel(data):
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(['Faculty/Department', 'Leave Type', 'Start Date', 'End Date', 'Description', 'Status'])

    for key, leaves in data.items():
        sheet.append([f'{key}'])
        for leave in leaves:
            sheet.append([
                leave.faculty.name if hasattr(leave.faculty, 'name') else key,
                leave.leave_type,
                leave.start_date,
                leave.end_date,
                leave.description,
                leave.status,
            ])

    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="leave_report.xlsx"'
    workbook.save(response)
    return response

def faculty_delete(request, faculty_id):
    faculty = get_object_or_404(Faculty, pk=faculty_id)
    faculty.delete()
    return redirect('faculty_list')
