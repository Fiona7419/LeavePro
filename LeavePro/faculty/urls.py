from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .views import CustomPasswordResetView

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path("password_reset/", CustomPasswordResetView.as_view(), name="password_reset"),
    path("password_reset/done/", auth_views.PasswordResetDoneView.as_view(template_name="password_reset_done.html"), name="password_reset_done"),
    path("reset/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view(template_name="password_reset_confirm.html"), name="password_reset_confirm"),
    path("reset/done/", auth_views.PasswordResetCompleteView.as_view(template_name="password_reset_complete.html"), name="password_reset_complete"),
    path("approve-leave/<int:leave_id>/", views.approve_leave, name="approve_leave"),
    path('list/', views.faculty_list, name='faculty_list'),
    path('add/', views.add_faculty, name='faculty_form'),
    path('apply_leave/', views.apply_leave, name='apply_leave'),
    path('generate-report/', views.generate_report, name='generate_report'),
    path('report/export/csv/', views.export_to_csv, name='export_to_csv'),
    path('report/export/excel/', views.export_to_excel, name='export_to_excel'),
    path('reporting/', views.generate_report, name='reporting'),
    path('faculty/delete/<str:faculty_id>/', views.faculty_delete, name='faculty_delete'),
    path('faculty/<str:faculty_id>/', views.faculty_detail, name='faculty_detail'),

]