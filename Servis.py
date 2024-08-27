from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_security import Security, SQLAlchemyUserDatastore
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from forms import MachineFilterForm, MaintenanceFilterForm, ClaimFilterForm, LoginForm, MachineSearchForm
from datetime import datetime, timedelta


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forklifts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# Модели
class Role(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    fs_uniquifier = db.Column(db.String(100), unique=True)
    role = db.relationship('Role', backref='users')

class Machine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    model = db.Column(db.String(100), nullable=False)
    engine_model = db.Column(db.String(100), nullable=False)
    engine_serial_number = db.Column(db.String(100), nullable=False)
    transmission_model = db.Column(db.String(100), nullable=False)
    transmission_serial_number = db.Column(db.String(100), nullable=False)
    drive_bridge_model = db.Column(db.String(100), nullable=False)
    drive_bridge_serial_number = db.Column(db.String(100), nullable=False)
    controlled_bridge_model = db.Column(db.String(100), nullable=False)
    controlled_bridge_serial_number = db.Column(db.String(100), nullable=False)
    supply_contract_number = db.Column(db.String(100), nullable=False)
    supply_contract_date = db.Column(db.Date, nullable=False)
    end_user = db.Column(db.String(100), nullable=False)
    delivery_address = db.Column(db.String(200), nullable=False)
    configuration = db.Column(db.String(200), nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
class Maintenance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    maintenance_type = db.Column(db.String(100), nullable=False)
    maintenance_date = db.Column(db.Date, nullable=False)
    runtime = db.Column(db.Float, nullable=False)  # Наработка в м/час
    order_number = db.Column(db.String(100), nullable=False)
    order_date = db.Column(db.Date, nullable=False)
    organization = db.Column(db.String(100), nullable=False)
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'), nullable=False)
    service_company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    refusal_date = db.Column(db.Date, nullable=False)
    runtime = db.Column(db.Float, nullable=False)  # Наработка в м/час
    failure_node = db.Column(db.String(100), nullable=False)
    failure_description = db.Column(db.String(200), nullable=False)
    recovery_method = db.Column(db.String(100), nullable=False)
    spare_parts_used = db.Column(db.String(200), nullable=True)
    recovery_date = db.Column(db.Date, nullable=False)
    downtime = db.Column(db.Float, nullable=False)  # Время простоя техники
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'), nullable=False)
    service_company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Forklift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    equipment = db.Column(db.String(200), nullable=False)
    usage_location = db.Column(db.String(200), nullable=False)
    last_service_date = db.Column(db.DateTime, nullable=False)
    service_interval_days = db.Column(db.Integer, nullable=False)

    def is_due_for_service(self):
        return datetime.now() >= self.last_service_date + timedelta(days=self.service_interval_days)

class ServiceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    forklift_id = db.Column(db.Integer, db.ForeignKey('forklift.id'), nullable=False)
    service_date = db.Column(db.DateTime, nullable=False)
    details = db.Column(db.String(200), nullable=True)

class Reference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entity_name = db.Column(db.String(100), nullable=False)  # Название сущности (справочника)
    name = db.Column(db.String(100), nullable=False)  # Название
    description = db.Column(db.String(200), nullable=True)  # Описание

# Инициализация Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Форма для авторизации
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6, max=200)])
    submit = SubmitField('Войти')

# Маршруты для аутентификации
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
         login_user(user)
         return jsonify({'message': 'Login successful!'}), 200
    return jsonify({'message': 'Invalid credentials'}), 401
    return render_template('login.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully!'}), 200


# Регистрация машины
@app.route('/machines', methods='POST')
@login_required
def addmachine():
    if current_user.role_id not in [1, 3]:
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    newmachine = Machine(
    serialnumber=data['serial_number'],
    model=data['model'],
    enginemodel=data['enginemodel'],
    engineserialnumber=data['engine_serial_number'],
    transmissionmodel=data['transmissionmodel'],
    transmissionserialnumber=data['transmission_serial_number'],
    drivebridgemodel=data['drive_bridge_model'],
    drivebridgeserialnumber=data['drivebridgeserialnumber'],
    controlledbridgemodel=data['controlled_bridge_model'],
    controlledbridgeserialnumber=data['controlledbridgeserialnumber'],
    supplycontractnumber=data['supply_contract_number'],
    supplycontractdate=datetime.strptime(data['supply_contract_date'], '%Y-%m-%d'),
    enduser=data['enduser'],
    deliveryaddress=data['deliveryaddress'],
    configuration=data.get('configuration', ''),
    clientid=current_user.id,  # Установка текущего клиента как владельца
    servicecompanyid=data['service_company_id']  # ID сервисной компании
    )
    db.session.add(newmachine)
    db.session.commit()
    return jsonify({'message': 'Machine added!'}), 201

# Регистрация технического обслуживания
@app.route('/maintenance', methods=['POST'])
@login_required
def addmaintenance():
    if current_user.role_id not in [2, 3]:  # Проверка роли (2 - сервисная организация, 3 - менеджер)
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    newmaintenance = Maintenance(
        maintenancetype=data['maintenancetype'],
        maintenancedate=datetime.strptime(data['maintenancedate'], '%Y-%m-%d'),
        runtime=data['runtime'],
    ordernumber=data['ordernumber'],
    orderdate=datetime.strptime(data['orderdate'], '%Y-%m-%d'),
    organization=data['organization'],
    machineid=data['machineid'],
    servicecompanyid= current_user.id  # ID сервисной компании
    )
    db.session.add(newmaintenance)
    db.session.commit()
    return jsonify({'message': 'Maintenance record added!'}), 201

@app.route('/addmachine', methods=['POST'])
@login_required
def add_machine():
    if current_user.role_id not in [1, 3]:  # Проверка роли (1 - клиент, 3 - менеджер)
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    new_machine = Machine(
        serial_number=data['serial_number'],
        model=data['model'],
        engine_model=data['engine_model'],
        engine_serial_number=data['engine_serial_number'],
        transmission_model=data['transmission_model'],
        transmission_serial_number=data['transmission_serial_number'],
        drive_bridge_model=data['drive_bridge_model'],
        drive_bridge_serial_number=data['drive_bridge_serial_number'],
        controlled_bridge_model=data['controlled_bridge_model'],
        controlled_bridge_serial_number=data['controlled_bridge_serial_number'],
        supply_contract_number=data['supply_contract_number'],
        supply_contract_date=datetime.strptime(data['supply_contract_date'], '%Y-%m-%d'),
        end_user=data['end_user'],
        delivery_address=data['delivery_address'],
        configuration=data.get('configuration', ''),
        client_id=current_user.id,
        service_company_id=data['service_company_id']
    )
    db.session.add(new_machine)
    db.session.commit()
    return jsonify({'message': 'Machine added!'}), 201

# Регистрация рекламации
@app.route('/claims', methods='POST')
@login_required
def addclaim():
    if current_user.role_id not in [2, 3]:  # Проверка роли (2 - сервисная организация, 3 - менеджер)
        # Проверка роли (2 - сервисная организация)
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    downtime_calculation = (datetime.strptime(data['recovery_date'], '%Y-%m-%d') -
                            datetime.strptime(data['refusal_date'], '%Y-%m-%d')).days

    new_claim = Claim(
        refusal_date=datetime.strptime(data['refusal_date'], '%Y-%m-%d'),
        runtime=data['runtime'],
        failure_node=data['failure_node'],
        failure_description=data['failure_description'],
        recovery_method=data['recovery_method'],
        spare_parts_used=data.get('spare_parts_used', ''),
        recovery_date=datetime.strptime(data['recovery_date'], '%Y-%m-%d'),
        downtime=downtime_calculation,  # Время простоя
        machine_id=data['machine_id'],
        service_company_id=current_user.id  # ID сервисной компании
    )
    db.session.add(new_claim)
    db.session.commit()
    return jsonify({'message': 'Claim record added!'}), 201

# Получение отчетов по жизненному циклу машины
@app.route('/machine_report/<int:machine_id>', methods=['GET'])
@login_required
def get_machine_report(machine_id):
    if current_user.role_id not in [1, 2, 3]:  # Проверка роли (1 - клиент, 2 - сервисная организация, 3 - менеджер)
        return jsonify({'message': 'Access denied!'}), 403

    machine = Machine.query.get_or_404(machine_id)
    maintenance_records = Maintenance.query.filter_by(machine_id=machine_id).all()
    claims = Claim.query.filter_by(machine_id=machine_id).all()

    report = {
        'machine': {
            'serial_number': machine.serial_number,
            'model': machine.model,
            'engine_model': machine.engine_model,
            'engine_serial_number': machine.engine_serial_number,
            'transmission_model': machine.transmission_model,
            'transmission_serial_number': machine.transmission_serial_number,
            'drive_bridge_model': machine.drive_bridge_model,
            'drive_bridge_serial_number': machine.drive_bridge_serial_number,
            'controlled_bridge_model': machine.controlled_bridge_model,
            'controlled_bridge_serial_number': machine.controlled_bridge_serial_number,
            'supply_contract_number': machine.supply_contract_number,
            'supply_contract_date': machine.supply_contract_date.strftime('%Y-%m-%d'),
            'end_user': machine.end_user,
            'delivery_address': machine.delivery_address,
            'configuration': machine.configuration
        },
        'maintenance_records': [{
            'maintenance_type': m.maintenance_type,
            'maintenance_date': m.maintenance_date.strftime('%Y-%m-%d'),
            'runtime': m.runtime,
            'order_number': m.order_number,
            'order_date': m.order_date.strftime('%Y-%m-%d'),
            'organization': m.organization
        } for m in maintenance_records],
        'claims': [{
            'refusal_date': c.refusal_date.strftime('%Y-%m-%d'),
            'runtime': c.runtime,
            'failure_node': c.failure_node,
            'failure_description': c.failure_description,
            'recovery_method': c.recovery_method,
            'spare_parts_used': c.spare_parts_used,
            'recovery_date': c.recovery_date.strftime('%Y-%m-%d'),
            'downtime': c.downtime
        } for c in claims]
    }

    return jsonify(report), 20

# Маршруты для работы со справочниками
@app.route('/references', methods=['POST'])
@login_required
def add_reference():
    if current_user.role_id != 1:  # Проверка роли (1 - клиент)
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    new_reference = Reference(
        entity_name=data['entity_name'],
        name=data['name'],
        description=data.get('description', '')
    )
    db.session.add(new_reference)
    db.session.commit()
    return jsonify({'message': 'Reference added!'}), 201

@app.route('/references', methods=['GET'])
@login_required
def get_references():
    references = Reference.query.all()
    return jsonify([{
        'id': r.id,
        'entity_name': r.entity_name,
        'name': r.name,
        'description': r.description
    } for r in references]), 200

# Маршруты для работы с машинами
@app.route('/machines', methods=['POST'])
@login_required
def add_machine():
    if current_user.role_id != 1:  # Проверка роли (1 - клиент)
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    new_machine = Machine(
        serial_number=data['serial_number'],
        model=data['model'],
        engine_model=data['engine_model'],
        engine_serial_number=data['engine_serial_number'],
        transmission_model=data['transmission_model'],
        transmission_serial_number=data['transmission_serial_number'],
        drive_bridge_model=data['drive_bridge_model'],
        drive_bridge_serial_number=data['drive_bridge_serial_number'],
        controlled_bridge_model=data['controlled_bridge_model'],
        controlled_bridge_serial_number=data['controlled_bridge_serial_number'],
        supply_contract_number=data['supply_contract_number'],
        supply_contract_date=datetime.strptime(data['supply_contract_date'], '%Y-%m-%d'),
        end_user=data['end_user'],
        delivery_address=data['delivery_address'],
        configuration=data.get('configuration', ''),
        client_id=current_user.id,  # Установка текущего клиента как владельца
        service_company_id=data['service_company_id']  # ID сервисной компании
    )
    db.session.add(new_machine)
    db.session.commit()
    return jsonify({'message': 'Machine added!'}), 201

@app.route('/machines', methods=['GET'])
@login_required
def get_machines():
    if current_user.role_id != 1:  # Проверка роли (1 - клиент)
        return jsonify({'message': 'Access denied!'}), 403

    machines = Machine.query.filter_by(client_id=current_user.id).all()
    return jsonify([{
        'id': m.id,
        'serial_number': m.serial_number,
        'model': m.model,
        'engine_model': m.engine_model,
        'engine_serial_number': m.engine_serial_number,
        'transmission_model': m.transmission_model,
        'transmission_serial_number': m.transmission_serial_number,
        'drive_bridge_model': m.drive_bridge_model,
        'drive_bridge_serial_number': m.drive_bridge_serial_number,
        'controlled_bridge_model': m.controlled_bridge_model,
        'controlled_bridge_serial_number': m.controlled_bridge_serial_number,
        'supply_contract_number': m.supply_contract_number,
        'supply_contract_date': m.supply_contract_date.strftime('%Y-%m-%d'),
        'end_user': m.end_user,
        'delivery_address': m.delivery_address,
        'configuration': m.configuration
    } for m in machines]), 200

@app.route('/machines/<int:machine_id>', methods=['GET'])
@login_required
def get_machine(machine_id):
    if current_user.role_id != 1:  # Проверка роли (1 - клиент)
        return jsonify({'message': 'Access denied!'}), 403

    machine = Machine.query.get_or_404(machine_id)
    return jsonify({
        'id': machine.id,
        'serial_number': machine.serial_number,
        'model': machine.model,
        'engine_model': machine.engine_model,
        'engine_serial_number': machine.engine_serial_number,
        'transmission_model': machine.transmission_model,
        'transmission_serial_number': machine.transmission_serial_number,
        'drive_bridge_model': machine.drive_bridge_model,
        'drive_bridge_serial_number': machine.drive_bridge_serial_number,
        'controlled_bridge_model': machine.controlled_bridge_model,
        'controlled_bridge_serial_number': machine.controlled_bridge_serial_number,
        'supply_contract_number': machine.supply_contract_number,
        'supply_contract_date': machine.supply_contract_date.strftime('%Y-%m-%d'),
        'end_user': machine.end_user,
        'delivery_address': machine.delivery_address,
        'configuration': machine.configuration
    }), 200

# Маршруты для работы с техническим обслуживанием
@app.route('/maintenance', methods=['POST'])
@login_required
def add_maintenance():
    if current_user.role_id != 2:  # Проверка роли (2 - сервисная организация)
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    new_maintenance = Maintenance(
        maintenance_type=data['maintenance_type'],
        maintenance_date=datetime.strptime(data['maintenance_date'], '%Y-%m-%d'),
        runtime=data['runtime'],
        order_number=data['order_number'],
        order_date=datetime.strptime(data['order_date'], '%Y-%m-%d'),
        organization=data['organization'],
        machine_id=data['machine_id'],
        service_company_id=current_user.id  # ID сервисной компании
    )
    db.session.add(new_maintenance)
    db.session.commit()
    return jsonify({'message': 'Maintenance record added!'}), 201

@app.route('/maintenance/<int:machine_id>', methods=['GET'])
@login_required
def get_maintenance_records(machine_id):
    if current_user.role_id != 1 and current_user.role_id != 2:  # Проверка роли (1 - клиент, 2 - сервисная организация)
        return jsonify({'message': 'Access denied!'}), 403

    maintenance_records = Maintenance.query.filter_by(machine_id=machine_id).all()
    return jsonify([{
        'id': m.id,
        'maintenance_type': m.maintenance_type,
        'maintenance_date': m.maintenance_date.strftime('%Y-%m-%d'),
        'runtime': m.runtime,
        'order_number': m.order_number,
        'order_date': m.order_date.strftime('%Y-%m-%d'),
        'organization': m.organization,
        'machine_id': m.machine_id,
        'service_company_id': m.service_company_id
    } for m in maintenance_records]), 200

# Маршруты для работы с рекламациями
@app.route('/claims', methods=['POST'])
@login_required
def add_claim():
    if current_user.role_id != 2:  # Проверка роли (2 - сервисная организация)
        return jsonify({'message': 'Access denied!'}), 403

    data = request.json
    downtime_calculation = (datetime.strptime(data['recovery_date'], '%Y-%m-%d') -
                            datetime.strptime(data['refusal_date'], '%Y-%m-%d')).days

    new_claim = Claim(
        refusal_date=datetime.strptime(data['refusal_date'], '%Y-%m-%d'),
        runtime=data['runtime'],
        failure_node=data['failure_node'],
        failure_description=data['failure_description'],
        recovery_method=data['recovery_method'],
        spare_parts_used=data.get('spare_parts_used', ''),
        recovery_date=datetime.strptime(data['recovery_date'], '%Y-%m-%d'),
        downtime=downtime_calculation,  # Время простоя
        machine_id=data['machine_id'],
        service_company_id=current_user.id  # ID сервисной компании
    )
    db.session.add(new_claim)
    db.session.commit()
    return jsonify({'message': 'Claim record added!'}), 201

@app.route('/claims/<int:machine_id>', methods=['GET'])
@login_required
def get_claims(machine_id):
    if current_user.role_id != 1 and current_user.role_id != 2:  # Проверка роли (1 - клиент, 2 - сервисная организация)
        return jsonify({'message': 'Access denied!'}), 403

    claims = Claim.query.filter_by(machine_id=machine_id).all()
    return jsonify([{
        'id': c.id,
        'refusal_date': c.refusal_date.strftime('%Y-%m-%d'),
        'runtime': c.runtime,
        'failure_node': c.failure_node,
        'failure_description': c.failure_description,
        'recovery_method': c.recovery_method,
        'spare_parts_used': c.spare_parts_used,
        'recovery_date': c.recovery_date.strftime('%Y-%m-%d'),
        'downtime': c.downtime,
        'machine_id': c.machine_id,
        'service_company_id': c.service_company_id
    } for c in claims]), 200
    # Сортировка по дате отгрузки
    return render_template('machines.html', machines=machines)

@app.route('/maintenance', methods=['GET'])
@login_required
def get_maintenance_records():
    if current_user.role_id not in [2, 3]:  # Проверка ролей
        return jsonify({'message': 'Access denied!'}), 403

    maintenance_records = Maintenance.query.order_by(Maintenance.maintenance_date).all()

# Сортировка по дате ТО
    return render_template('maintenance.html', maintenance_records=maintenance_records)

@app.route('/claims', methods=['GET'])
@login_required
def get_claims():
    if current_user.role_id not in [1, 2, 3]:  # Проверка ролей
        return jsonify({'message': 'Access denied!'}), 403

    claims = Claim.query.order_by(Claim.refusal_date).all()  # Сортировка по дате отказа
    return render_template('claims.html', claims=claims)
@app.route('/machines', methods=['GET', 'POST'])
@login_required
def get_machines():
    form = MachineFilterForm()
    query = Machine.query  # Начнем с общего запроса
    # Фильтрация по полям
    if form.validate_on_submit():
        if form.model.data:
            query = query.filter(Machine.model.ilike(f"%{form.model.data}%"))
        if form.engine_model.data:
            query = query.filter(Machine.engine_model.ilike(f"%{form.engine_model.data}%"))
        if form.transmission_model.data:
            query = query.filter(Machine.transmission_model.ilike(f"%{form.transmission_model.data}%"))
        if form.controlled_bridge_model.data:
            query = query.filter(Machine.controlled_bridge_model.ilike(f"%{form.controlled_bridge_model.data}%"))
        if form.drive_bridge_model.data:
            query = query.filter(Machine.drive_bridge_model.ilike(f"%{form.drive_bridge_model.data}%"))

    machines = query.order_by(Machine.supply_contract_date).all()
    return render_template('machines.html', machines=machines, form=form)

@app.route('/maintenance', methods=['GET', 'POST'])
@login_required
def get_maintenance_records():
    form = MaintenanceFilterForm()
    query = Maintenance.query  # Начнем с общего запроса
    # Фильтрация по полям
    if form.validate_on_submit():
        if form.maintenance_type.data:
            query = query.filter(Maintenance.maintenance_type.ilike(f"%{form.maintenance_type.data}%"))
        if form.machine_serial_number.data:
            query= query.join(Machine).filter(Machine.serialnumber.ilike(f"%{form.machineserialnumber.data}%"))
        if form.servicecompany.data:
            query = query.filter(Maintenance.organization.ilike(f"%{form.servicecompany.data}%"))

    maintenancerecords = query.orderby(Maintenance.maintenancedate).all()
    return render_template('maintenance.html', maintenancerecords=maintenancerecords, form=form)

@app.route('/claims', methods=['GET', 'POST'])
@login_required
def getclaims():
    form = ClaimFilterForm()
    query = Claim.query  # Начнем с общего запроса

    # Фильтрация по полям
    if form.validateonsubmit():
        if form.failurenode.data:
            query = query.filter(Claim.failurenode.ilike(f"%{form.failurenode.data}%"))
        if form.recoverymethod.data:
            query = query.filter(Claim.recoverymethod.ilike(f"%{form.recoverymethod.data}%"))
        if form.servicecompany.data:
            query = query.filter(Claim.servicecompanyid == current_user.id)  # Предположим, что вы знаете, как получить ID

    claims = query.orderby(Claim.refusaldate).all()
    return render_template('claims.html', claims=claims, form=form)

@app.route('/machine/<int:machine_id>', methods=['GET'])
@login_required
def get_machine_details(machine_id):
    # Получаем информацию о машине по ID
    machine = Machine.query.get_or_404(machine_id)
    # Здесь вы можете добавить дополнительные данные, например, ТО и рекламации
    maintenance_records = Maintenance.query.filter_by(machine_id=machine.id).all()
    claims = Claim.query.filter_by(machine_id=machine.id).all()

    return render_template('machine_details.html', machine=machine, maintenance_records=maintenance_records, claims=claims)

@app.route('/search_machine', methods=['GET', 'POST'])
def search_machine():
    form = MachineSearchForm()
    machine = None

    if form.validate_on_submit():
        serial_number = form.serial_number.data
        machine = Machine.query.filter_by(serial_number=serial_number).first()

    return render_template('search_machine.html', form=form, machine=machine)

@app.route('/dashboard/<int:machine_id>', methods=['GET'])
@login_required
def dashboard(machine_id):
    machine = Machine.query.get_or_404(machine_id)
    maintenance_records = Maintenance.query.filter_by(machine_id=machine_id).all()
    claims = Claim.query.filter_by(machine_id=machine_id).all()

    return render_template('dashboard.html', machine=machine, maintenance_records=maintenance_records, claims=claims)


@app.route('/', methods=['GET'])
def welcome():
    return render_template('welcome.html')
# Функция для инициализации базы данных
def init_db():
    db.create_all()  # Создание всех таблиц

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Инициализация базы данных при запуске приложения
    db.create_all()
    app.run(debug=True)

