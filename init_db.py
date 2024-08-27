from Servis import db, Role, User

# Инициализация базы данных
def init_db():
    # Создание всех таблиц
    db.create_all()

    # Добавление ролей
    client_role = Role(name='Клиент')
    service_org_role = Role(name='Сервисная организация')
    manager_role = Role(name='Менеджер')

    # Добавление ролей в базу данных
    db.session.add(client_role)
    db.session.add(service_org_role)
    db.session.add(manager_role)
    db.session.commit()

    # Добавление пользователей (пример)
    client_user = User(username='client_user', password='password123', role_id=client_role.id)
    service_org_user = User(username='service_org_user', password='password123', role_id=service_org_role.id)
    manager_user = User(username='manager_user', password='password123', role_id=manager_role.id)

    # Добавление пользователей в базу данных
    db.session.add(client_user)
    db.session.add(service_org_user)
    db.session.add(manager_user)
    db.session.commit()

    print("База данных инициализирована!")

if __name__ == '__main__':
    from Servis import Servis  # Импорт приложения для контекста
    with Servis.app_context():
        init_db()  # Инициализация базы данных
    init_db()