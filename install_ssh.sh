#!/bin/bash

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Verificar root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Este script deve ser executado como root!${NC}"
    exit 1
fi

# Instalar dependências
install_dependencies() {
    echo -e "${YELLOW}Instalando dependências...${NC}"
    apt-get update
    apt-get install -y curl wget sudo ufw dropbear stunnel4 openssl \
    python3 python3-pip fail2ban squid apache2-utils cron \
    net-tools unzip screen nano
}

# Configurar firewall
configure_firewall() {
    echo -e "${YELLOW}Configurando firewall...${NC}"
    ufw allow 22/tcp
    ufw allow 443/tcp
    ufw allow 80/tcp
    ufw allow 3128/tcp
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
}

# Configurar SSH
configure_ssh() {
    echo -e "${YELLOW}Configurando SSH...${NC}"
    sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Configurar Dropbear
configure_dropbear() {
    echo -e "${YELLOW}Configurando Dropbear...${NC}"
    echo "/bin/false" >> /etc/shells
    sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
    echo 'DROPBEAR_EXTRA_ARGS="-p 80 -p 443"' >> /etc/default/dropbear
    service dropbear restart
}

# Configurar Squid Proxy
configure_squid() {
    echo -e "${YELLOW}Configurando Squid Proxy...${NC}"
    cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
    echo -e "acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localhost
http_access allow all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320" > /etc/squid/squid.conf
    systemctl restart squid
}

# Configurar Stunnel
configure_stunnel() {
    echo -e "${YELLOW}Configurando Stunnel...${NC}"
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=BR/ST=SP/L=SAO_PAULO/O=Server/CN=localhost" \
    -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem

    echo -e "cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 445
connect = 127.0.0.1:443" > /etc/stunnel/stunnel.conf

    sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
    systemctl restart stunnel4
}

# Criar usuário SSH
create_ssh_user() {
    echo -e "${YELLOW}Criando usuário SSH...${NC}"
    read -p "Digite o nome do usuário: " username
    read -sp "Digite a senha: " password
    echo
    useradd -m -s /bin/false $username
    echo "$username:$password" | chpasswd
    echo -e "${GREEN}Usuário $username criado com sucesso!${NC}"
}

# Instalar interface web
install_web_interface() {
    echo -e "${YELLOW}Instalando interface web...${NC}"
    pip3 install flask flask-basicauth
    
    mkdir -p /var/www/sshpanel
    cd /var/www/sshpanel

    # Criar app Flask
    cat > app.py <<EOF
from flask import Flask, render_template, request, redirect, url_for
from flask_basicauth import BasicAuth
import subprocess
import os

app = Flask(__name__)
app.config['BASIC_AUTH_USERNAME'] = 'admin'
app.config['BASIC_AUTH_PASSWORD'] = '$(openssl rand -hex 8)'
app.config['BASIC_AUTH_FORCE'] = True
basic_auth = BasicAuth(app)

@app.route('/')
def index():
    users = []
    with open('/etc/passwd', 'r') as f:
        for line in f:
            if '/bin/false' in line:
                users.append(line.split(':')[0])
    try:
        connections = subprocess.check_output(['netstat', '-tnpa']).decode('utf-8')
    except:
        connections = "Erro ao obter conexões"
    return render_template('index.html', users=users, connections=connections)

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    password = request.form['password']
    os.system(f'useradd -m -s /bin/false {username}')
    os.system(f'echo "{username}:{password}" | chpasswd')
    return redirect(url_for('index'))

@app.route('/del_user/<username>')
def del_user(username):
    os.system(f'userdel -r {username}')
    return redirect(url_for('index'))

@app.route('/restart_service/<service>')
def restart_service(service):
    os.system(f'systemctl restart {service}')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

    # Criar template HTML
    mkdir templates
    cat > templates/index.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Painel SSH</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: #f9f9f9; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        button { background: #4CAF50; color: white; border: none; padding: 5px 10px; cursor: pointer; }
        button.danger { background: #f44336; }
        input, button { padding: 8px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Painel de Controle SSH</h1>
        <div class="card">
            <h2>Adicionar Usuário</h2>
            <form action="/add_user" method="post">
                <input type="text" name="username" placeholder="Nome de usuário" required>
                <input type="password" name="password" placeholder="Senha" required>
                <button type="submit">Adicionar</button>
            </form>
        </div>
        <div class="card">
            <h2>Usuários Existentes</h2>
            <table>
                <tr><th>Usuário</th><th>Ação</th></tr>
                {% for user in users %}
                <tr>
                    <td>{{ user }}</td>
                    <td><a href="/del_user/{{ user }}"><button class="danger">Remover</button></a></td>
                </tr>
                {% endfor %}
            </table>
        </div>
        <div class="card">
            <h2>Conexões Ativas</h2>
            <pre>{{ connections }}</pre>
        </div>
        <div class="card">
            <h2>Serviços</h2>
            <a href="/restart_service/ssh"><button>Reiniciar SSH</button></a>
            <a href="/restart_service/dropbear"><button>Reiniciar Dropbear</button></a>
            <a href="/restart_service/stunnel4"><button>Reiniciar Stunnel</button></a>
            <a href="/restart_service/squid"><button>Reiniciar Squid</button></a>
        </div>
    </div>
</body>
</html>
EOF

    # Criar serviço systemd
    cat > /etc/systemd/system/sshpanel.service <<EOF
[Unit]
Description=SSH Panel Web Interface
After=network.target

[Service]
User=root
WorkingDirectory=/var/www/sshpanel
ExecStart=/usr/bin/python3 /var/www/sshpanel/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sshpanel
    systemctl start sshpanel

    echo -e "${GREEN}Interface web instalada com sucesso!${NC}"
    echo -e "${YELLOW}Acesse em: http://$(curl -s ifconfig.me):8080${NC}"
    echo -e "${YELLOW}Usuário: admin | Senha: $(grep 'BASIC_AUTH_PASSWORD' /var/www/sshpanel/app.py | cut -d'"' -f4)${NC}"
}

main() {
    clear
    echo -e "${BLUE}"
    echo "###################################################"
    echo "#          INSTALADOR DE SERVIDOR SSH             #"
    echo "#               COM INTERFACE WEB                 #"
    echo "###################################################"
    echo -e "${NC}"
    
    install_dependencies
    configure_firewall
    configure_ssh
    configure_dropbear
    configure_squid
    configure_stunnel
    create_ssh_user
    install_web_interface
    
    echo -e "${GREEN}"
    echo "###################################################"
    echo "#         INSTALAÇÃO CONCLUÍDA COM SUCESSO!       #"
    echo "#                                                 #"
    echo "# Portas abertas:                                 #"
    echo "# - SSH: 22                                       #"
    echo "# - Dropbear: 80, 443                             #"
    echo "# - Stunnel: 445                                  #"
    echo "# - Squid Proxy: 3128                             #"
    echo "# - Interface Web: 8080                           #"
    echo "#                                                 #"
    echo "# Acesse o painel web com:                        #"
    echo "# http://SEU_IP:8080                              #"
    echo "# Usuário: admin                                  #"
    echo "# Senha: $(grep 'BASIC_AUTH_PASSWORD' /var/www/sshpanel/app.py | cut -d'"' -f4)"
    echo "###################################################"
    echo -e "${NC}"
}

main
