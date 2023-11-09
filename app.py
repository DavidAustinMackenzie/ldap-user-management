import sys
import os
if sys.version_info.major == 3 and sys.version_info.minor >= 10:
    import collections
    setattr(collections, "MutableMapping", collections.abc.MutableMapping)
from flask import Flask, render_template, request, redirect, url_for, flash
from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, Reader, ObjectDef, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager, login_user, UserMixin, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
uri = 'sqlite:///' + os.path.join(basedir, 'database.db')
key = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SECRET_KEY'] = key

# LDAP server configuration
LDAP_SERVER = 'ldap://rule141.i4t.swin.edu.au'
LDAP_PORT = 389
LDAP_BIND_DN = 'cn=admin,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au'
LDAP_BIND_PASSWORD = 'admin'
LDAP_DN = 'dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au'
LDAP_OU = 'ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au'
SERVER_URI = f"ldap://rule141.i4t.swin.edu.au:389"
SERVER = Server(SERVER_URI, get_info=ALL)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


# User login class
class User(db.Model, UserMixin):
    username = db.Column(db.String(30), nullable=False, primary_key=True)
    firstname = db.Column(db.String(30), nullable=False)
    lastname = db.Column(db.String(30), nullable=False)
    fullname = db.Column(db.String(50), nullable=False)

    def get_id(self):
        return self.username


# Create database tables for User login
with app.app_context():
    db.init_app(app)
    db.create_all()


def get_ldap_connection():
    try:
        # Provide the hostname and port number of the openLDAP
        server_uri = f"ldap://rule141.i4t.swin.edu.au:389"
        server = Server(server_uri, get_info=ALL)
        # username and password can be configured during openldap setup
        connection = Connection(server,
                                user='cn=admin,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au',
                                password='admin')
        bind_response = connection.bind()  # Returns True or False
        return connection
    except LDAPBindError as e:
        connection = e


def get_ldap_server():
    try:
        # Provide the hostname and port number of the openLDAP
        server_uri = f"ldap://rule141.i4t.swin.edu.au:389"
        server = Server(server_uri, get_info=ALL)
        return server
    except LDAPException as e:
        server = e


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    user_dn = f'uid={username},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au'

    server = get_ldap_server()
    # Authenticate user, using LDAP server
    conn = Connection(server,
                      user=user_dn,
                      password=password)
    bind_response = conn.bind()  # Returns True or False
    if bind_response:
        user = User.query.filter_by(username=username).first()
        print(user)
        try:
            # If the user doesn't exit in DB, add them
            if user is None:
                search_user = f"(uid={username})"
                with conn as connection:
                    connection.search(LDAP_DN, search_user, attributes=[
                        'uid', 'givenName', 'sn', 'cn'])
                    user_data = conn.entries[0]
                    print(user_data['uid'])
                    print(user_data['givenName'])
                    print(user_data['sn'])
                    print(user_data['cn'])
                    newUser = User(username=str(user_data['uid']),
                                   firstname=str(user_data['givenName']),
                                   lastname=str(user_data['sn']),
                                   fullname=str(user_data['cn']))

                    # add the new user to the database
                    db.session.add(newUser)
                    db.session.commit()
                    user = User.query.filter_by(username=username).first()

            login_user(user)
        except Exception as e:
            print(e)

        return redirect(url_for('home'))
    else:
        print(bind_response)
        flash('Invalid username or password!')
        return redirect(url_for('login'))


@app.route('/')
@login_required
def home():
    return render_template('home.html', current_user=current_user)


@app.route('/users')
@login_required
def users():
    # Page only for admin user
    if (current_user.username != "admin"):
        return redirect(url_for('home'))

    ldap_bind_connection = get_ldap_connection()
    search_users = f"(objectclass=inetOrgPerson)"
    with ldap_bind_connection as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn', 'loginShell', 'homeDirectory'])
        users = conn.entries
        headings = ("ID", "Username", "First name", "Last Name",
                    "Full Name", "Login Shell", " Home Folder", "Update", "Change Password", "Reset Password", "Remove User")
    return render_template('users.html', headings=headings, users=users, current_user=current_user)


@app.route('/add_user', methods=['get'])
@login_required
def add_user():
    # Page only for admin user
    if (current_user.username != "admin"):
        return redirect(url_for('home'))

    return render_template('addUser.html', current_user=current_user)


@app.route('/add_user', methods=['post'])
@login_required
def add_user_post():

    # Get form inputs
    uid = request.form.get('uid')
    uidNumber = request.form.get('uidNumber')
    gidNumber = request.form.get('gidNumber')
    givenName = request.form.get('first_name')
    sn = request.form.get('last_name')
    password = request.form.get('password')
    cn = f'{givenName} {sn}'
    shell = request.form.get('login_shell')

    # get the connection
    c = get_ldap_connection()

    c.bind()
    print(f"Connection to server: {c.bind()}")

    dn = f'uid={uid},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au'
    # perform the Add operation
    c.add(dn,
          ['inetOrgPerson', 'posixAccount', 'shadowAccount', 'top'],
          {'uidNumber': uidNumber,
           'gidNumber': gidNumber,
           'givenName': givenName,
           'sn': sn,
           'cn': cn,
           'userPassword': password,
           'homeDirectory': f'/home/{uid}',
           'loginShell': shell
           })

    print(c.result)

    # close the connection
    c.unbind()

    return redirect(url_for('users'))


@app.route('/update_user/<id>', methods=['get'])
@login_required
def update_user(id):
    # Page only for admin user
    if (current_user.username != "admin"):
        return redirect(url_for('home'))

    ldap_bind_connection = get_ldap_connection()
    search_users = f"(uidNumber={id})"
    with ldap_bind_connection as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn', 'loginShell'])
        user = conn.entries[0]
    return render_template('updateUser.html', user=user, current_user=current_user)


@app.route('/update_user/<id>', methods=['post'])
@login_required
def update_user_post(id):
    # Get form details
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    full_name = request.form.get('full_name')
    login_shell = request.form.get('login_shell')

    c = get_ldap_connection()

    search_users = f"(uidNumber={id})"
    with c as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn', 'loginShell'])
        user = conn.entries[0]

    # Update password
    c.bind()

    dn = f"uid={user['uid']},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au"
    # perform the Modify operation
    c.modify(dn,
             {'givenName': [(MODIFY_REPLACE, first_name)],
              'sn': [(MODIFY_REPLACE, last_name)],
              'cn': [(MODIFY_REPLACE, full_name)],
              'loginShell': [(MODIFY_REPLACE, login_shell)]})
    print(c.result)

    # close the connection
    c.unbind()

    return redirect(url_for('users'))


@app.route('/delete_user/display/<id>', methods=['get'])
@login_required
def delete_user_display(id):
    # Page only for admin user
    if (current_user.username != "admin"):
        return redirect(url_for('home'))

    ldap_bind_connection = get_ldap_connection()
    search_users = f"(uidNumber={id})"
    with ldap_bind_connection as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn'])
        user = conn.entries[0]
    return render_template('deleteUser.html', user=user, current_user=current_user)


@app.route('/delete_user/<id>', methods=['get'])
@login_required
def delete_user(id):
    # Page only for admin user
    if (current_user.username != "admin"):
        return redirect(url_for('home'))

    # get the connection
    c = get_ldap_connection()

    c.bind()
    print(f"Connection to server: {c.bind()}")

    dn = f'uid={id},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au'
    print(f"Deleting this user: {dn}")

    # perform the Delete operation
    c.delete(dn)

    print(c.result)

    # close the connection
    c.unbind()

    return redirect(url_for('users'))


@app.route('/update_user_password/<id>', methods=['get'])
@login_required
def update_user_password(id):
    # Page only for admin user
    if (current_user.username != "admin"):
        return redirect(url_for('home'))

    ldap_bind_connection = get_ldap_connection()
    search_users = f"(uidNumber={id})"
    with ldap_bind_connection as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn'])
        user = conn.entries[0]
    return render_template('updatePassword.html', user=user, current_user=current_user)


@app.route('/update_user_password/<id>', methods=['post'])
@login_required
def update_user_password_post(id):
    # Get form inputs
    oldPassword = bytes(request.form.get('old_password'), encoding='UTF-8')
    newPassword = bytes(request.form.get('new_password'), encoding='UTF-8')
    confirmPassword = bytes(request.form.get(
        'confirm_password'), encoding='UTF-8')

    c = get_ldap_connection()
    search_users = f"(uidNumber={id})"
    with c as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn'])
        user = conn.entries[0]

    currentPassword = user['userPassword']
    print(f"oldPassword: {oldPassword}")
    print(f"currentPassword: {currentPassword}")
    print(currentPassword == oldPassword)

    # Check the old password against DB
    if currentPassword != oldPassword:
        flash('Incorrect old password!')
        return render_template('updatePassword.html', user=user, current_user=current_user)

    if newPassword != confirmPassword:
        flash("New password and Confirm Password don't match!")
        return render_template('updatePassword.html', user=user, current_user=current_user)

    # Update password
    c.bind()

    dn = f"uid={user['uid']},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au"
    # perform the Modify operation
    c.modify(dn,
             {'userPassword': [(MODIFY_REPLACE, newPassword)]})
    print(c.result)

    # close the connection
    c.unbind()

    return redirect(url_for('users'))


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/account', methods=['get'])
def account():
    ldap_bind_connection = get_ldap_connection()
    search_users = f"(uid={current_user.username})"
    with ldap_bind_connection as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn', 'loginShell'])
        user = conn.entries[0]
    return render_template('account.html', user=user, current_user=current_user)


@app.route('/account', methods=['post'])
def account_post():
    # Get form details
    uid = request.form.get('uid')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    full_name = request.form.get('full_name')
    login_shell = request.form.get('login_shell')

    c = get_ldap_connection()

    search_users = f"(uid={uid})"
    with c as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn', 'loginShell'])
        user = conn.entries[0]

    # Update password
    c.bind()

    dn = f"uid={user['uid']},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au"
    # perform the Modify operation
    c.modify(dn,
             {'givenName': [(MODIFY_REPLACE, first_name)],
              'sn': [(MODIFY_REPLACE, last_name)],
              'cn': [(MODIFY_REPLACE, full_name)],
              'loginShell': [(MODIFY_REPLACE, login_shell)]})
    print(c.result)

    # close the connection
    c.unbind()

    return redirect(url_for('home'))


@app.route('/accountPassword', methods=['get'])
@login_required
def accountPassword():
    ldap_bind_connection = get_ldap_connection()
    search_users = f"(uid={current_user.username})"
    with ldap_bind_connection as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn'])
        user = conn.entries[0]
    return render_template('accountPassword.html', user=user, current_user=current_user)


@app.route('/accountPassword', methods=['post'])
@login_required
def accountPassword_post():
    # Get form inputs
    uid = request.form.get('uid')
    oldPassword = bytes(request.form.get('old_password'), encoding='UTF-8')
    newPassword = bytes(request.form.get('new_password'), encoding='UTF-8')
    confirmPassword = bytes(request.form.get(
        'confirm_password'), encoding='UTF-8')

    # Get connection and retrieve current password
    c = get_ldap_connection()
    search_users = f"(uid={uid})"
    with c as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn'])
        user = conn.entries[0]

    currentPassword = user['userPassword']
    print(f"oldPassword: {oldPassword}")
    print(f"currentPassword: {currentPassword}")
    print(currentPassword == oldPassword)

    # Check the old password against DB
    if currentPassword != oldPassword:
        flash('Incorrect old password!')
        return render_template('updatePassword.html', user=user)

    if newPassword != confirmPassword:
        flash("New password and Confirm Password don't match!")
        return render_template('updatePassword.html', user=user)

    # Update password
    c.bind()

    dn = f"uid={user['uid']},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au"
    # perform the Modify operation
    c.modify(dn,
             {'userPassword': [(MODIFY_REPLACE, newPassword)]})
    print(c.result)

    # close the connection
    c.unbind()
    return redirect(url_for('home'))


@app.route('/reset_user_password/<id>', methods=['get'])
@login_required
def reset_user_password(id):
    # Page only for admin user
    if (current_user.username != "admin"):
        return redirect(url_for('home'))

    ldap_bind_connection = get_ldap_connection()
    search_users = f"(uidNumber={id})"
    with ldap_bind_connection as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn'])
        user = conn.entries[0]
    return render_template('resetPassword.html', user=user, current_user=current_user)


@app.route('/reset_user_password/<id>', methods=['post'])
@login_required
def reset_user_password_post(id):
    # Get form inputs
    newPassword = bytes(request.form.get('new_password'), encoding='UTF-8')
    confirmPassword = bytes(request.form.get(
        'confirm_password'), encoding='UTF-8')

    c = get_ldap_connection()
    search_users = f"(uidNumber={id})"
    with c as conn:
        conn.search(LDAP_DN, search_users, attributes=[
                    'uidNumber', 'givenName', 'sn', 'uid', 'userPassword', 'cn'])
        user = conn.entries[0]

    # Check new and confirm password match
    if newPassword != confirmPassword:
        flash("New password and Confirm Password don't match!")
        return render_template('resetPassword.html', user=user, current_user=current_user)

    # Update password
    c.bind()

    dn = f"uid={user['uid']},ou=people,dc=rule141,dc=i4t,dc=swin,dc=edu,dc=au"
    # perform the Modify operation
    c.modify(dn,
             {'userPassword': [(MODIFY_REPLACE, newPassword)]})
    print(c.result)

    # close the connection
    c.unbind()

    return redirect(url_for('users'))


if __name__ == '__main__':
    app.run(debug=True)
