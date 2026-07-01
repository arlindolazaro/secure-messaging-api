# 🔐 SecureMessaging API

<div align="center">

![SecureMessaging](https://img.shields.io/badge/SecureMessaging-API-blue?style=for-the-badge&logo=lock)
![Java](https://img.shields.io/badge/Java-21-orange?style=for-the-badge&logo=java)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3+-green?style=for-the-badge&logo=spring-boot)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Latest-336791?style=for-the-badge&logo=postgresql)

**API segura para mensagens criptografadas com autenticação JWT, certificados digitais e criptografia híbrida (RSA + AES)**

[📖 Documentação](#-documentação) • [🚀 Quick Start](#-quick-start) • [🏗️ Arquitetura](#-arquitetura) • [🔧 Configuração](#-configuração)

</div>

---

## 📋 Visão Geral

O **SecureMessaging API** é um backend robusto construído com Spring Boot que fornece:

- ✅ **Autenticação segura** com JWT tokens
- ✅ **Criptografia de ponta a ponta** (RSA 2048 + AES 256)
- ✅ **Gerenciamento de certificados digitais** X.509
- ✅ **WebSockets** para comunicação em tempo real
- ✅ **APIs RESTful** bem documentadas (Swagger/OpenAPI)
- ✅ **Suporte HTTPS/TLS** em desenvolvimento e produção
- ✅ **Testes automatizados** para criptografia e segurança

---

## 🚀 Features Principais

### 🔑 Autenticação & Autorização
- Registro e login com validação de email
- JWT com refresh tokens
- Controle de acesso baseado em papéis (RBAC)
- Recuperação de senha segura

### 🛡️ Criptografia & Segurança
- Criptografia RSA-2048 para troca de chaves
- Criptografia AES-256 para dados em repouso
- Assinatura digital de mensagens
- CORS configurável
- Proteção contra CSRF

### 📧 Gerenciamento de Mensagens
- Envio de mensagens privadas criptografadas
- Histórico de conversa seguro
- Notificações em tempo real via WebSocket
- Exclusão segura de mensagens

### 📜 Gerenciamento de Certificados
- Geração de CSR (Certificate Signing Request)
- Upload e validação de certificados X.509
- Renovação de certificados
- Revogação de certificados

### 🎨 Gerenciamento de Recursos
- Upload de imagens com validação
- Geração de PDFs (certificados, relatórios)
- API de configurações de usuário

---

## 🛠️ Stack Tecnológico

### Backend Framework
- **Spring Boot 3.3+** — Framework principal
- **Spring Security** — Autenticação e autorização
- **Spring Data JPA** — Acesso a dados com Hibernate
- **Spring WebSocket** — Comunicação em tempo real

### Banco de Dados
- **PostgreSQL** — Banco de dados relacional
- **Hibernate** — ORM

### Criptografia & Segurança
- **BouncyCastle** — RSA, AES, SHA-256, SHA3
- **JWT (io.jsonwebtoken)** — Token management
- **Spring Security** — Authentication framework

### API & Documentação
- **Springdoc OpenAPI** — Swagger UI integrado
- **Spring HATEOAS** — RESTful API avançada

### Build & Deploy
- **Maven 3.8+** — Gerenciador de dependências
- **Docker** — Containerização

---

## 📦 Requisitos

- **Java 21** ou superior
- **Maven 3.8+**
- **PostgreSQL 12+**
- **Git**

---

## 🔒 Habilitar HTTPS em desenvolvimento

Para habilitar TLS/HTTPS local (desenvolvimento), o projeto inclui um script PowerShell que gera um keystore PKCS12 autoassinado.

1. Execute na raiz do repositório (Windows PowerShell):

   .\scripts\generate-dev-keystore.ps1 -Alias securemessaging -Password changeit

2. O script irá gerar `keystore.p12` em `secure-messaging-backend/src/main/resources/keystore.p12`.

3. O profile `dev` já contém configuração para ativar SSL na porta `8443`. Inicie a aplicação com o profile `dev` (Windows):

   cd secure-messaging-backend
   .\mvnw.cmd -Dspring-boot.run.profiles=dev spring-boot:run

4. Acesse o backend via: https://localhost:8443

Observação: em produção você deve usar um certificado válido emitido por uma CA confiável.

Nota: o script usa `keytool` (vem com o JDK). Se receber erro indicando que `keytool` não é encontrado, instale um JDK (por exemplo Temurin/OpenJDK) e adicione o diretório `bin` do JDK ao PATH antes de executar o script.

---

## � Tecnologias Utilizadas

### Backend (Java + Spring Boot)

- Spring Boot 3.x
- Spring Security (JWT)
- Spring Data JPA (Hibernate)
- PostgreSQL / MySQL
- BouncyCastle (criptografia RSA, AES, SHA-256, SHA3)
- Maven

### Frontend (React.js + Vite)

- React 18+
- Axios (requisições HTTP)
- TailwindCSS
- React Router
- Context API (auth state)

---

---

## 🚀 Quick Start

### 1️⃣ Clone o repositório

```bash
git clone https://github.com/seu-usuario/secure-messaging-api.git
cd secure-messaging-api
```

### 2️⃣ Configure o banco de dados

Criar um banco PostgreSQL:
```sql
CREATE DATABASE securemessaging;
```

Configure as credenciais em `src/main/resources/application.properties`:
```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/securemessaging
spring.datasource.username=postgres
spring.datasource.password=seu_password
```

### 3️⃣ Instale as dependências e execute

```bash
# Build com Maven
./mvnw clean install

# Execute com profile dev (HTTPS habilitado)
./mvnw -Dspring-boot.run.profiles=dev spring-boot:run
```

### 4️⃣ Acesse a documentação da API

Abra o navegador em: **http://localhost:8080/swagger-ui.html**

---

## 🏗️ Arquitetura

```
src/main/java/com/securemessaging/
├── config/                    # Configurações (JWT, CORS, Segurança)
├── controller/               # Endpoints REST
├── dto/                      # Data Transfer Objects
├── model/                    # Entidades JPA
├── repository/               # Acesso a dados
├── service/                  # Lógica de negócio
│   ├── CryptoService         # Criptografia RSA/AES
│   ├── CertificateService    # Gerenciamento de certificados
│   ├── MessageService        # Gerenciamento de mensagens
│   ├── AuthService           # Autenticação e JWT
│   └── ...
├── security/                 # Implementações de segurança
└── exception/                # Tratamento de erros
```

---

## 🔧 Configuração

### Variáveis de Ambiente

```bash
# Banco de dados
DB_HOST=localhost
DB_PORT=5432
DB_NAME=securemessaging
DB_USER=postgres
DB_PASSWORD=seu_password

# JWT
JWT_SECRET=sua_chave_secreta_longa_aqui
JWT_EXPIRATION=86400000

# Email (para recuperação de senha)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=seu_email@gmail.com
EMAIL_PASSWORD=sua_senha_app

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,https://seu-frontend.com
```

### Perfis de Execução

| Perfil | Descrição |
|--------|-----------|
| `dev` | Desenvolvimento com HTTPS/TLS ativado |
| `prod` | Produção com segurança máxima |
| `test` | Testes automatizados |

```bash
./mvnw -Dspring-boot.run.profiles=dev spring-boot:run
```

---

## 📡 Endpoints Principais

### 🔑 Autenticação
```
POST   /api/auth/register          # Registrar novo usuário
POST   /api/auth/login             # Login
POST   /api/auth/refresh           # Renovar token JWT
POST   /api/auth/logout            # Logout
```

### 📧 Mensagens
```
GET    /api/messages               # Listar mensagens
POST   /api/messages               # Enviar mensagem
GET    /api/messages/{id}          # Obter mensagem específica
DELETE /api/messages/{id}          # Deletar mensagem
```

### 📜 Certificados
```
POST   /api/certificates/csr       # Gerar CSR
POST   /api/certificates/upload    # Upload de certificado
GET    /api/certificates           # Listar certificados
DELETE /api/certificates/{id}      # Revogar certificado
```

### 🔐 Criptografia
```
POST   /api/crypto/encrypt         # Criptografar dados
POST   /api/crypto/decrypt         # Descriptografar dados
POST   /api/crypto/sign            # Assinar dados
POST   /api/crypto/verify          # Verificar assinatura
```

---

## 🧪 Testes

```bash
# Executar todos os testes
./mvnw test

# Testes de criptografia
./mvnw test -Dtest=CryptoServiceTest

# Testes de certificados
./mvnw test -Dtest=PKITest

# Cobertura de testes
./mvnw clean test jacoco:report
```

---

## 🐳 Docker

### Build da imagem
```bash
docker build -t secure-messaging-api:latest .
```

### Executar container
```bash
docker run -d \
  -p 8443:8443 \
  -e DB_HOST=postgres \
  -e DB_PASSWORD=postgres \
  --name secure-api \
  secure-messaging-api:latest
```

---

## 📚 Documentação Detalhada

- [Fluxo de Autenticação](docs/AUTHENTICATION.md)
- [Criptografia Híbrida](docs/ENCRYPTION.md)
- [Gerenciamento de Certificados](docs/CERTIFICATES.md)
- [API Reference](docs/API.md)
- [Segurança](docs/SECURITY.md)

---

## 🤝 Conectar com Frontend

O frontend (React) se conecta via WebSocket:

```javascript
// Frontend
const ws = new WebSocket('wss://localhost:8443/ws/messages');
ws.send(JSON.stringify({
  type: 'MESSAGE',
  content: encryptedMessage,
  recipientId: userId
}));
```

---

## 🔐 Segurança em Produção

- ✅ Use certificados SSL válidos (Let's Encrypt)
- ✅ Configure firewall adequadamente
- ✅ Use secrets manager para senhas e chaves
- ✅ Ative logging e monitoramento
- ✅ Faça backups regulares do banco de dados
- ✅ Atualize dependencies regularmente

---

## 📋 Status do Projeto

| Feature | Status |
|---------|--------|
| Autenticação JWT | ✅ Completo |
| Criptografia RSA/AES | ✅ Completo |
| Gerenciamento de Certificados | ✅ Completo |
| WebSocket Real-time | ✅ Completo |
| Upload de Arquivos | ✅ Completo |
| Geração de PDFs | ✅ Completo |
| Testes Automatizados | ✅ Completo |
| Documentação Swagger | ✅ Completo |
| Suporte a Produção | 🚧 Em progresso |

---

## 🐛 Troubleshooting

### Erro: `keytool not found`
Instale um JDK (OpenJDK/Temurin) e adicione ao PATH:
```bash
# Windows
setx JAVA_HOME "C:\Program Files\Eclipse Adoptium\jdk-21.0.1+12"
```

### Erro: Conexão recusada ao PostgreSQL
```bash
# Verificar se PostgreSQL está rodando
psql -U postgres -d securemessaging -c "SELECT 1;"
```

### Erro: CORS bloqueado
Configure em `application.properties`:
```properties
spring.web.cors.allowed-origins=http://localhost:3000
spring.web.cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
spring.web.cors.allowed-headers=*
```

---

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Add MinhaFeature'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

---

## 📝 Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

---

## 👨‍💻 Autor

**Arlindo Lázaro**
- GitHub: [@arlindolazaro](https://github.com/arlindolazaro)
- Email: arlindolazaro202@gmail.com

---

## 📞 Suporte

- 📧 Issues: [GitHub Issues](https://github.com/seu-usuario/secure-messaging-api/issues)
- 💬 Discussões: [GitHub Discussions](https://github.com/seu-usuario/secure-messaging-api/discussions)
- 📖 Wiki: [Documentação Completa](../../wiki)

---

**⭐ Se este projeto foi útil, deixe uma estrela! ⭐**
