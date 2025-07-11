# Generated by Django 5.1.3 on 2025-03-06 15:14

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('faculty', '0008_leave_reason'),
    ]

    operations = [
        migrations.CreateModel(
            name='LeaveEntitlement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('faculty_type', models.CharField(max_length=50, unique=True)),
                ('casual_leave', models.FloatField(default=12)),
                ('sick_leave', models.FloatField(default=22.5)),
                ('earned_leave', models.FloatField(default=15)),
                ('personal_leave', models.FloatField(default=10)),
                ('lwop', models.FloatField(default=0)),
            ],
        ),
        migrations.AddField(
            model_name='faculty',
            name='leave_entitlement',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='faculty.leaveentitlement'),
        ),
    ]
