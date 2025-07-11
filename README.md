#!/bin/bash

# Цвета для вывода
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция для проверки выполнения команд
check_command() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}Ошибка при выполнении: $1${NC}"
        exit 1
    else
        echo -e "${GREEN}Успешно: $1${NC}"
    fi
}

# Запрос ввода данных у пользователя
echo -e "${YELLOW}Введите доменное имя (например, domain.ru, как указывали в .env при настройке MD):${NC}"
read -r DOMAIN

echo -e "${YELLOW}Введите REALM (например, DOMAIN.RU):${NC}"
read -r REALM

echo -e "${YELLOW}Введите BASE DN (например, dc=domain,dc=ru):${NC}"
read -r LDAP_BASE_DN

echo -e "${YELLOW}Введите логин сервсиной учетной записи LDAP (например, cn=admin,ou=users,$LDAP_BASE_DN):${NC}"
read -r LOGIN

echo -e "${YELLOW}Введите пароль сервисной учетной записи LDAP:${NC}"
read -rs PASSWORD
echo

# Проверка введенных данных
if [[ -z "$DOMAIN" || -z "$REALM" || -z "$LDAP_BASE_DN" || -z "$LOGIN" || -z "$PASSWORD" ]]; then
    echo -e "${RED}Ошибка: Все поля должны быть заполнены!${NC}"
    exit 1
fi

# Автоматическое формирование остальных переменных
SUBSTRING=".$DOMAIN"
KDC=$DOMAIN
KADMIN=$DOMAIN
URI="ldap://$DOMAIN"
HOSTNAME=$(hostname -s)  # Только короткое имя хоста
COMPUTER_DN="cn=$HOSTNAME,ou=computers,$LDAP_BASE_DN"
LDAP_SEARCH_BASE=$LDAP_BASE_DN
LDAP_SUDO_BASE="cn=domain admins,cn=groups,$LDAP_BASE_DN"
LDAP_USER_BASE=$LDAP_BASE_DN
SSSD_NESTING_LEVEL='1000'
SUDO_GROUP='"%domain admins" ALL=(ALL) ALL'

# Обновление и установка необходимых пакетов
echo -e "${GREEN}Обновление системы и установка пакетов...${NC}"

# Создаем backup nsswitch.conf
cp /etc/nsswitch.conf /etc/nsswitch.conf.bak
check_command "Создание backup nsswitch.conf"

# Определение менеджера пакетов и установка пакетов
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
    export DEBIAN_FRONTEND=noninteractive
    echo -e "${GREEN}Обновление пакетов (APT)...${NC}"
    apt-get update -q > /dev/null
    check_command "Обновление пакетов APT"
    packages=(krb5-user libpam-krb5 sssd-ldap sssd-krb5 sssd sssd-tools ldap-utils jq curl)
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    echo -e "${GREEN}Обновление пакетов (YUM)...${NC}"
    yum makecache fast > /dev/null
    check_command "Обновление пакетов YUM"
    packages=(krb5-workstation pam_krb5 sssd-ldap sssd-krb5 sssd sssd-tools openldap-clients jq curl)
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    echo -e "${GREEN}Обновление пакетов (DNF)...${NC}"
    dnf makecache > /dev/null
    check_command "Обновление пакетов DNF"
    packages=(krb5-workstation pam_krb5 sssd-ldap sssd-krb5 sssd sssd-tools openldap-clients jq curl)
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    echo -e "${GREEN}Обновление пакетов (Pacman)...${NC}"
    pacman -Sy --noconfirm > /dev/null
    check_command "Обновление пакетов Pacman"
    packages=(krb5 pam-krb5 sssd openldap jq curl)
else
    echo -e "${RED}Менеджер пакетов не найден!${NC}"
    exit 1
fi

# Установка необходимых пакетов
for pkg in "${packages[@]}"; do
    case "$PKG_MANAGER" in
        apt-get)
            if ! dpkg -l | grep -qw "$pkg"; then
                echo -e "${GREEN}Установка $pkg...${NC}"
                apt-get install -y -q "$pkg" > /dev/null
                check_command "Установка $pkg"
            else
                echo -e "${GREEN}$pkg уже установлен.${NC}"
            fi
            ;;
        yum|dnf)
            if ! rpm -q "$pkg" &> /dev/null; then
                echo -e "${GREEN}Установка $pkg...${NC}"
                $PKG_MANAGER install -y "$pkg" > /dev/null
                check_command "Установка $pkg"
            else
                echo -e "${GREEN}$pkg уже установлен.${NC}"
            fi
            ;;
        pacman)
            if ! pacman -Qi "$pkg" &> /dev/null; then
                echo -e "${GREEN}Установка $pkg...${NC}"
                pacman -S --noconfirm "$pkg" > /dev/null
                check_command "Установка $pkg"
            else
                echo -e "${GREEN}$pkg уже установлен.${NC}"
            fi
            ;;
    esac
done

# Удаление конфликтующих пакетов
rm_packages=(nscd nslcd)
for pkg in "${rm_packages[@]}"; do
    case "$PKG_MANAGER" in
        apt-get)
            if dpkg -l | grep -qw "$pkg"; then
                echo -e "${YELLOW}Удаление $pkg...${NC}"
                apt-get remove -y -q "$pkg" > /dev/null
                check_command "Удаление $pkg"
            fi
            ;;
        yum|dnf)
            if rpm -q "$pkg" &> /dev/null; then
                echo -e "${YELLOW}Удаление $pkg...${NC}"
                $PKG_MANAGER remove -y "$pkg" > /dev/null
                check_command "Удаление $pkg"
            fi
            ;;
        pacman)
            if pacman -Qi "$pkg" &> /dev/null; then
                echo -e "${YELLOW}Удаление $pkg...${NC}"
                pacman -R --noconfirm "$pkg" > /dev/null
                check_command "Удаление $pkg"
            fi
            ;;
    esac
done

# Конфигурация Kerberos
echo -e "${GREEN}Настройка Kerberos...${NC}"
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM
    kdc_timesync = 1
    ccache_type = 4
    forwardable = true
    proxiable = true
    fcc-mit-ticket-flags = true
[realms]
    $REALM = {
        kdc = $KDC
        admin_server = $KADMIN
    }
[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF
check_command "Настройка Kerberos"

# Конфигурация SSSD
echo -e "${GREEN}Настройка SSSD...${NC}"
mkdir -p /etc/sssd
cat > /etc/sssd/sssd.conf <<EOF
[sssd]
    config_file_version = 2
    domains = $DOMAIN
    services = nss, pam, ssh

[domain/$DOMAIN]
    ldap_schema = rfc2307bis 
    ldap_group_nesting_level = $SSSD_NESTING_LEVEL
    ldap_default_bind_dn = $LOGIN
    ldap_default_authtok = $PASSWORD
    ldap_default_authtok_type = password
    id_provider = ldap
    ldap_uri = $URI
    ldap_search_base = $LDAP_SEARCH_BASE
    auth_provider = krb5
    krb5_server = $KDC
    krb5_kpasswd = $KDC
    krb5_realm = $REALM
    cache_credentials = True
    ldap_id_use_start_tls = false
    ldap_group_search_base = $LDAP_SEARCH_BASE
    ldap_sudo_search_base = $LDAP_SUDO_BASE
    ldap_user_search_base = $LDAP_USER_BASE
EOF
check_command "Настройка SSSD"

# Настройка прав доступа
chmod 600 /etc/sssd/sssd.conf
chown root:root /etc/sssd/sssd.conf
chmod 755 /usr/bin/klist /usr/bin/kinit /usr/bin/kdestroy
chmod 644 /etc/krb5.conf

# Настройка PAM для автоматического создания домашних каталогов
echo -e "${GREEN}Настройка PAM...${NC}"
if [ -f /etc/pam.d/common-session ]; then
    # Для Debian-based
    pam-auth-update --enable mkhomedir
    sed -i 's/session optional pam_mkhomedir.so/session required pam_mkhomedir.so/' /etc/pam.d/common-session
elif [ -f /etc/pam.d/system-auth ]; then
    # Для RedHat-based
    if ! grep -q "pam_mkhomedir.so" /etc/pam.d/system-auth; then
        sed -i '/session.*required.*pam_unix.so/a session     required      pam_mkhomedir.so skel=/etc/skel umask=0077' /etc/pam.d/system-auth
    fi
fi
check_command "Настройка PAM"

# Настройка nsswitch
echo -e "${GREEN}Настройка nsswitch.conf...${NC}"
cat > /etc/nsswitch.conf <<EOF
passwd:         files systemd sss
group:          files systemd sss
shadow:         files systemd sss
gshadow:        files systemd
sudoers:        files sss

hosts:          files mdns4_minimal [NOTFOUND=return] dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
automount:      files sss
EOF
check_command "Настройка nsswitch.conf"

# Настройка SSH (сохраняем оригинальный конфиг)
echo -e "${GREEN}Настройка SSH...${NC}"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config <<EOF
# Основные настройки
Port 22
AddressFamily inet
SyslogFacility AUTHPRIV
LogLevel DEBUG

# Аутентификация
PermitRootLogin yes
PasswordAuthentication no
ChallengeResponseAuthentication yes
UsePAM yes
PubkeyAuthentication yes

# Kerberos
KerberosAuthentication yes
KerberosOrLocalPasswd no
KerberosTicketCleanup yes

# GSSAPI
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes

# Безопасность
AllowTcpForwarding no
ClientAliveInterval 120
ClientAliveCountMax 2
X11Forwarding yes
PrintMotd no

# Шифрование
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

Include /etc/ssh/sshd_config.d/*.conf
EOF
check_command "Настройка SSH"

# Добавление группы в sudoers
echo -e "${GREEN}Настройка sudoers...${NC}"
if ! grep -Fxq "$SUDO_GROUP" /etc/sudoers; then
    echo '%#513 ALL=(ALL) ALL'
    echo "$SUDO_GROUP" >> /etc/sudoers
    check_command "Добавление прав sudo для domain admins"
else
    echo -e "${GREEN}Права sudo для domain admins уже настроены.${NC}"
fi

# Запуск и включение служб
echo -e "${GREEN}Запуск служб...${NC}"
systemctl restart sssd sshd
systemctl enable sssd
check_command "Запуск служб"

echo -e "${GREEN}\nНастройка завершена успешно!${NC}"
echo -e "${YELLOW}Рекомендуется перезагрузить систему для применения всех изменений.${NC}"
