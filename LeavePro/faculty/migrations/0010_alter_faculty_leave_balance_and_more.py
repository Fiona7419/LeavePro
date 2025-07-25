# Generated by Django 5.1.3 on 2025-03-06 15:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('faculty', '0009_leaveentitlement_faculty_leave_entitlement'),
    ]

    operations = [
        migrations.AlterField(
            model_name='faculty',
            name='leave_balance',
            field=models.FloatField(default=0),
        ),
        migrations.AlterField(
            model_name='faculty',
            name='leaves_taken',
            field=models.FloatField(default=0),
        ),
        migrations.AlterField(
            model_name='faculty',
            name='total_leaves',
            field=models.FloatField(default=0),
        ),
    ]
