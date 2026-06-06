/**
 * System Provisioning Playbooks
 * Pre-defined playbooks for common server setup tasks
 */

import { Playbook, AccessMode } from '../types/index.js';

/**
 * Ubuntu/Debian base system setup
 */
export const baseSystemSetup: Playbook = {
  id: 'base-system-setup',
  name: 'Base System Setup',
  description: 'Basic system configuration for Ubuntu/Debian servers',
  requiredMode: AccessMode.PROVISION,
  variables: {
    SWAP_SIZE: '2G',
    TIMEZONE: 'UTC',
  },
  steps: [
    {
      id: 'update-packages',
      name: 'Update Package Lists',
      command: 'apt-get update',
      description: 'Update apt package lists',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'upgrade-packages',
      name: 'Upgrade Packages',
      command: 'apt-get upgrade -y',
      description: 'Upgrade all installed packages',
      requiredMode: AccessMode.PROVISION,
      requiresApproval: true,
    },
    {
      id: 'install-essentials',
      name: 'Install Essential Packages',
      command: 'apt-get install -y curl wget git vim htop unzip software-properties-common',
      description: 'Install commonly used utilities',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'set-timezone',
      name: 'Set Timezone',
      command: 'timedatectl set-timezone ${TIMEZONE}',
      description: 'Configure system timezone',
      requiredMode: AccessMode.PROVISION,
      validate: 'timedatectl | grep "Time zone"',
    },
    {
      id: 'configure-swap',
      name: 'Configure Swap',
      command: 'fallocate -l ${SWAP_SIZE} /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile',
      description: 'Create and enable swap file',
      requiredMode: AccessMode.PROVISION,
      validate: 'swapon --show',
      rollback: 'swapoff /swapfile && rm -f /swapfile',
    },
    {
      id: 'persist-swap',
      name: 'Persist Swap on Boot',
      command: 'echo "/swapfile none swap sw 0 0" >> /etc/fstab',
      description: 'Add swap to fstab for persistence',
      requiredMode: AccessMode.PROVISION,
    },
  ],
};

/**
 * Docker installation playbook
 */
export const dockerInstall: Playbook = {
  id: 'docker-install',
  name: 'Docker Installation',
  description: 'Install Docker CE and Docker Compose on Ubuntu/Debian',
  requiredMode: AccessMode.PROVISION,
  variables: {
    DOCKER_USER: 'ubuntu',
  },
  steps: [
    {
      id: 'install-prerequisites',
      name: 'Install Docker Prerequisites',
      command: 'apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release',
      description: 'Install required packages for Docker',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'add-docker-gpg',
      name: 'Add Docker GPG Key',
      command: 'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg',
      description: 'Add Docker official GPG key',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'add-docker-repo',
      name: 'Add Docker Repository',
      command: 'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null',
      description: 'Add Docker apt repository',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'update-apt',
      name: 'Update Package Lists',
      command: 'apt-get update',
      description: 'Refresh apt package lists',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'install-docker',
      name: 'Install Docker Engine',
      command: 'apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin',
      description: 'Install Docker CE and related packages',
      requiredMode: AccessMode.PROVISION,
      validate: 'docker --version',
    },
    {
      id: 'start-docker',
      name: 'Start Docker Service',
      command: 'systemctl start docker && systemctl enable docker',
      description: 'Start and enable Docker service',
      requiredMode: AccessMode.PROVISION,
      validate: 'systemctl is-active docker',
    },
    {
      id: 'add-user-docker-group',
      name: 'Add User to Docker Group',
      command: 'usermod -aG docker ${DOCKER_USER}',
      description: 'Allow non-root user to run Docker',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'verify-docker',
      name: 'Verify Docker Installation',
      command: 'docker run --rm hello-world',
      description: 'Test Docker with hello-world container',
      requiredMode: AccessMode.PROVISION,
    },
  ],
};

/**
 * Nginx installation playbook
 */
export const nginxInstall: Playbook = {
  id: 'nginx-install',
  name: 'Nginx Installation',
  description: 'Install and configure Nginx web server',
  requiredMode: AccessMode.PROVISION,
  variables: {
    SERVER_NAME: 'localhost',
    UPSTREAM_PORT: '3000',
  },
  steps: [
    {
      id: 'install-nginx',
      name: 'Install Nginx',
      command: 'apt-get install -y nginx',
      description: 'Install Nginx from apt repository',
      requiredMode: AccessMode.PROVISION,
      validate: 'nginx -v',
    },
    {
      id: 'start-nginx',
      name: 'Start Nginx Service',
      command: 'systemctl start nginx && systemctl enable nginx',
      description: 'Start and enable Nginx service',
      requiredMode: AccessMode.PROVISION,
      validate: 'systemctl is-active nginx',
    },
    {
      id: 'test-config',
      name: 'Test Nginx Configuration',
      command: 'nginx -t',
      description: 'Validate Nginx configuration syntax',
      requiredMode: AccessMode.PROVISION,
    },
  ],
};

/**
 * UFW Firewall setup playbook
 */
export const firewallSetup: Playbook = {
  id: 'firewall-setup',
  name: 'UFW Firewall Setup',
  description: 'Configure UFW firewall with basic rules',
  requiredMode: AccessMode.PROVISION,
  variables: {
    SSH_PORT: '22',
  },
  steps: [
    {
      id: 'install-ufw',
      name: 'Install UFW',
      command: 'apt-get install -y ufw',
      description: 'Install UFW firewall',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'default-deny',
      name: 'Set Default Deny Incoming',
      command: 'ufw default deny incoming',
      description: 'Block all incoming traffic by default',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'default-allow-outgoing',
      name: 'Set Default Allow Outgoing',
      command: 'ufw default allow outgoing',
      description: 'Allow all outgoing traffic',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'allow-ssh',
      name: 'Allow SSH',
      command: 'ufw allow ${SSH_PORT}/tcp',
      description: 'Allow SSH connections',
      requiredMode: AccessMode.PROVISION,
      requiresApproval: true,
    },
    {
      id: 'allow-http',
      name: 'Allow HTTP',
      command: 'ufw allow 80/tcp',
      description: 'Allow HTTP traffic',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'allow-https',
      name: 'Allow HTTPS',
      command: 'ufw allow 443/tcp',
      description: 'Allow HTTPS traffic',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'enable-ufw',
      name: 'Enable UFW',
      command: 'ufw --force enable',
      description: 'Enable firewall',
      requiredMode: AccessMode.PROVISION,
      requiresApproval: true,
      validate: 'ufw status',
    },
  ],
};

/**
 * SSL Certificate setup with Certbot
 */
export const sslSetup: Playbook = {
  id: 'ssl-setup',
  name: 'SSL Certificate Setup',
  description: 'Install SSL certificate using Certbot',
  requiredMode: AccessMode.PROVISION,
  variables: {
    DOMAIN: '',
    EMAIL: '',
  },
  steps: [
    {
      id: 'install-certbot',
      name: 'Install Certbot',
      command: 'apt-get install -y certbot python3-certbot-nginx',
      description: 'Install Certbot and Nginx plugin',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'obtain-certificate',
      name: 'Obtain SSL Certificate',
      command: 'certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos -m ${EMAIL}',
      description: 'Obtain and install SSL certificate',
      requiredMode: AccessMode.PROVISION,
      requiresApproval: true,
      validate: 'certbot certificates',
    },
    {
      id: 'test-renewal',
      name: 'Test Certificate Renewal',
      command: 'certbot renew --dry-run',
      description: 'Verify auto-renewal works',
      requiredMode: AccessMode.PROVISION,
    },
  ],
};

/**
 * Node.js installation playbook
 */
export const nodeInstall: Playbook = {
  id: 'node-install',
  name: 'Node.js Installation',
  description: 'Install Node.js LTS via NodeSource',
  requiredMode: AccessMode.PROVISION,
  variables: {
    NODE_VERSION: '20',
  },
  steps: [
    {
      id: 'add-nodesource',
      name: 'Add NodeSource Repository',
      command: 'curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -',
      description: 'Add NodeSource apt repository',
      requiredMode: AccessMode.PROVISION,
    },
    {
      id: 'install-nodejs',
      name: 'Install Node.js',
      command: 'apt-get install -y nodejs',
      description: 'Install Node.js from NodeSource',
      requiredMode: AccessMode.PROVISION,
      validate: 'node --version',
    },
    {
      id: 'install-pm2',
      name: 'Install PM2',
      command: 'npm install -g pm2',
      description: 'Install PM2 process manager',
      requiredMode: AccessMode.PROVISION,
      validate: 'pm2 --version',
    },
  ],
};

/**
 * All available playbooks
 */
export const ALL_PLAYBOOKS: Playbook[] = [
  baseSystemSetup,
  dockerInstall,
  nginxInstall,
  firewallSetup,
  sslSetup,
  nodeInstall,
];

/**
 * Get playbook by ID
 */
export function getPlaybookById(id: string): Playbook | undefined {
  return ALL_PLAYBOOKS.find(p => p.id === id);
}

/**
 * List available playbooks with summary
 */
export function listPlaybooks(): { id: string; name: string; description: string; requiredMode: AccessMode }[] {
  return ALL_PLAYBOOKS.map(p => ({
    id: p.id,
    name: p.name,
    description: p.description,
    requiredMode: p.requiredMode,
  }));
}

export default ALL_PLAYBOOKS;
