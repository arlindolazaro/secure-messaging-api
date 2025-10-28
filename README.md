# 🔐 SecureMessaging

Aplicação fullstack para **mensagens seguras**, utilizando **Java Spring Boot** no backend e **React.js** no frontend.
O sistema implementa **criptografia híbrida (RSA + AES)**, gerenciamento de **certificados digitais** e autenticação segura.

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

## ⚙️ Funcionalidades

- ✅ Criação de certificados digitais (RSA)
- ✅ Geração de **Root CA** autoassinado
- ✅ Importação e revogação de certificados
- ✅ Validação de certificados (assinatura, validade, revogação)
- ✅ Criptografia híbrida (mensagens e arquivos com AES + RSA)
- ✅ Autenticação de usuários com JWT
- ✅ Dashboard no frontend para gerenciamento

---
