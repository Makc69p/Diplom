from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField, FloatField, SubmitField, PasswordField
from wtforms.validators import Optional, DataRequired, Length


class MachineFilterForm(FlaskForm):
    model = StringField('Модель техники', validators=[Optional()])
    engine_model = StringField('Модель двигателя', validators=[Optional()])
    transmission_model = StringField('Модель трансмиссии', validators=[Optional()])
    controlled_bridge_model = StringField('Модель управляемого моста', validators=[Optional()])
    drive_bridge_model = StringField('Модель ведущего моста', validators=[Optional()])
    submit = SubmitField('Применить фильтр')

class MaintenanceFilterForm(FlaskForm):
    maintenance_type = StringField('Вид ТО', validators=[Optional()])
    machine_serial_number = StringField('Зав. номер машины', validators=[Optional()])
    service_company = StringField('Сервисная компания', validators=[Optional()])
    submit = SubmitField('Применить фильтр')

class ClaimFilterForm(FlaskForm):
    failure_node = StringField('Узел отказа', validators=[Optional()])
    recovery_method = StringField('Способ восстановления', validators=[Optional()])
    service_company = StringField('Сервисная компания', validators=[Optional()])
    submit = SubmitField('Применить фильтр')

class MachineSearchForm(FlaskForm):
    serial_number = StringField('Заводской номер', validators=[DataRequired()])
    submit = SubmitField('Поиск')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6, max=200)])
    submit = SubmitField('Войти')