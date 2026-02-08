/**
 * Service installer tool - just-in-time database/service installation with resource checking.
 */
export function getServiceInstallerScript(): string {
  return `#!/bin/bash
SERVICE="$1"
GREEN='\\033[32m'
CYAN='\\033[36m'
YELLOW='\\033[33m'
RED='\\033[31m'
NC='\\033[0m'

log() { echo -e "\${CYAN}[install]\${NC} $1"; }
success() { echo -e "\${GREEN}*\${NC} $1"; }
warn() { echo -e "\${YELLOW}!\${NC} $1"; }
error() { echo -e "\${RED}x\${NC} $1"; exit 1; }

check_resources() {
  AVAILABLE_RAM=$(free -m | awk '/^Mem:/{print $7}')
  LOAD_AVG=$(cat /proc/loadavg | awk '{print $1}')
  CPU_COUNT=$(nproc)

  log "Checking resources..."
  echo "  Free RAM: \${AVAILABLE_RAM}MB"
  echo "  Load Avg: \${LOAD_AVG} / \${CPU_COUNT} CPUs"

  MIN_RAM_REQUIRED=500

  if [ "$AVAILABLE_RAM" -lt "$MIN_RAM_REQUIRED" ]; then
    echo ""
    warn "LOW MEMORY DETECTED"
    echo "  You have \${AVAILABLE_RAM}MB free, but a database needs ~\${MIN_RAM_REQUIRED}MB headroom."
    echo "  Installing this MIGHT crash your server during builds."
    echo ""
    echo -e "  \${YELLOW}RECOMMENDATION: Upgrade your server size in the dashboard.\${NC}"
    echo ""
    read -p "Proceed anyway? (y/N) " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
      echo "Aborted."
      exit 0
    fi
  else
    success "Resources look good."
  fi
}

install_postgres() {
  if command -v psql &>/dev/null; then
    success "Postgres is already installed."
    return 0
  fi
  check_resources

  log "Installing PostgreSQL..."
  apt-get update
  apt-get install -y postgresql postgresql-contrib

  log "Configuring for user 'dev'..."
  sudo -u postgres createuser --superuser dev 2>/dev/null || true
  sudo -u postgres createdb -O dev dev 2>/dev/null || true

  PG_VERSION=$(ls /etc/postgresql/ | head -1)
  mkdir -p /etc/postgresql/$PG_VERSION/main/conf.d
  echo "shared_buffers = 128MB" > /etc/postgresql/$PG_VERSION/main/conf.d/tuning.conf
  systemctl restart postgresql

  echo ""
  success "PostgreSQL installed!"
  echo -e "  URL: \${GREEN}postgresql://dev@localhost/dev\${NC}"
  echo -e "  Auth: Peer authentication (works automatically for 'dev' user)"
  echo ""
}

install_redis() {
  if command -v redis-server &>/dev/null; then
    success "Redis is already installed."
    return 0
  fi
  check_resources

  log "Installing Redis..."
  apt-get update
  apt-get install -y redis-server

  if grep -q "^maxmemory " /etc/redis/redis.conf; then
    sed -i 's/^maxmemory .*/maxmemory 256mb/' /etc/redis/redis.conf
  else
    echo "maxmemory 256mb" >> /etc/redis/redis.conf
  fi

  if grep -q "^maxmemory-policy " /etc/redis/redis.conf; then
    sed -i 's/^maxmemory-policy .*/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
  else
    echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf
  fi

  systemctl enable redis-server
  systemctl restart redis-server

  echo ""
  success "Redis installed!"
  echo -e "  URL: \${GREEN}redis://localhost:6379\${NC}"
  echo ""
}

install_mysql() {
  if command -v mysql &>/dev/null; then
    success "MySQL/MariaDB is already installed."
    return 0
  fi
  check_resources

  log "Installing MariaDB..."
  apt-get update
  apt-get install -y mariadb-server

  systemctl enable mariadb
  systemctl start mariadb

  log "Configuring for user 'dev'..."
  mysql -e "CREATE USER IF NOT EXISTS 'dev'@'localhost' IDENTIFIED VIA unix_socket;" 2>/dev/null || true
  mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'dev'@'localhost' WITH GRANT OPTION;" 2>/dev/null || true
  mysql -e "CREATE DATABASE IF NOT EXISTS dev;" 2>/dev/null || true
  mysql -e "FLUSH PRIVILEGES;"

  echo ""
  success "MariaDB installed!"
  echo -e "  User: \${GREEN}dev\${NC} (No password, unix_socket auth)"
  echo -e "  Database: dev"
  echo -e "  Connect: mysql -u dev dev"
  echo ""
}

if [ -z "$SERVICE" ]; then
  echo ""
  echo -e "\${CYAN}Phone Stack Service Installer\${NC}"
  echo ""
  echo "Usage: sudo phonestack-install [service]"
  echo ""
  echo "Services:"
  echo "  postgres  - PostgreSQL database"
  echo "  redis     - Redis cache/queue"
  echo "  mysql     - MariaDB database"
  echo ""
  echo "Features:"
  echo "  - Checks available RAM before installing"
  echo "  - Warns if resources are low"
  echo "  - Configures services for low-memory environments"
  echo "  - Sets up 'dev' user with socket auth (no passwords)"
  echo ""
  exit 0
fi

case "$SERVICE" in
  postgres|postgresql) install_postgres ;;
  redis) install_redis ;;
  mysql|mariadb) install_mysql ;;
  *)
    error "Unknown service: $SERVICE"
    echo "Available: postgres, redis, mysql"
    exit 1
    ;;
esac`;
}
