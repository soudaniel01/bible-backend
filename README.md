# Manager API

## Profiles

The application uses Spring profiles to load environment specific configuration files. The default configuration is defined in `application.properties`. For production, values from `application-prod.properties` are loaded when the `prod` profile is active.

Select the desired profile by setting the `spring.profiles.active` property when starting the application:

```bash
java -jar target/manager-0.0.1-SNAPSHOT.jar --spring.profiles.active=prod
```

When no profile is specified, Spring Boot uses the default configuration.

## JWT Claims Contract

- Claim padrão multi-tenant: `tenantId`
- Tipo: String (UUID)

## Testes

### Rodar testes locais (sem Docker)

```bash
mvn test
```

- Por padrão, a suíte roda com banco em memória (H2) para os testes de fluxo de autenticação.
- Testes que dependem de Docker/Testcontainers ficam desabilitados no `mvn test` por padrão.

### Rodar testes com Docker/Testcontainers

Requer Docker disponível no ambiente.

```bash
mvn test -Pdocker-tests
```

## Feature flags

### Exigir claim tenantId no JWT

Por padrão, o token sem `tenantId` continua válido. Para exigir a claim, habilite:

```properties
app.security.require-tenant-claim=true
```

## Rate limiting (login/refresh)

Rate limit in-memory aplicado em:
- `POST /api/auth/login`
- `POST /api/auth/refresh`

Propriedades:

```properties
app.security.ratelimit.enabled=true

app.security.ratelimit.login.ip.capacity=10
app.security.ratelimit.login.ip.windowSeconds=60
app.security.ratelimit.login.principal.capacity=5
app.security.ratelimit.login.principal.windowSeconds=60

app.security.ratelimit.refresh.ip.capacity=30
app.security.ratelimit.refresh.ip.windowSeconds=60

app.security.ratelimit.penalty.enabled=true
app.security.ratelimit.penalty.cooldownSeconds=300
```

Como ajustar:
- Aumente/diminua `capacity` para controlar quantas requisições cabem por janela.
- Ajuste `windowSeconds` para tornar a janela mais curta/longa.
- Para desabilitar temporariamente, use `app.security.ratelimit.enabled=false`.
- A penalidade por falhas consecutivas no login usa `cooldownSeconds` e é aplicada por `(IP + email/username)` quando disponível.

## Rotação de chaves JWT (kid)

Novos tokens JWT incluem `kid` no header. Tokens antigos (sem `kid`) continuam válidos enquanto pelo menos uma chave configurada validar a assinatura.

Propriedades:

```properties
app.jwt.keys.activeKid=key1
app.jwt.keys.key1.secret=${SECURITY_TOKEN_SECRET:CHANGE_ME}
app.jwt.keys.key2.secret=${SECURITY_TOKEN_SECRET_2:}
```

Passo a passo (key1 -> key2):
1. Defina `SECURITY_TOKEN_SECRET` com um secret forte (>= 32 chars, não `CHANGE_ME`) e mantenha `app.jwt.keys.activeKid=key1`.
2. Defina `SECURITY_TOKEN_SECRET_2` com outro secret forte (>= 32 chars).
3. Faça deploy mantendo `activeKid=key1` (a aplicação valida tokens com `key1` e `key2`, mas ainda assina novos tokens com `key1`).
4. Troque `app.jwt.keys.activeKid=key2` e faça novo deploy (tokens novos passam a sair com `kid=key2`).
5. Após expirar o tempo máximo de vida dos tokens emitidos com `key1`, remova `SECURITY_TOKEN_SECRET` (ou deixe `key1` vazio) para desativar validação por `key1`.
