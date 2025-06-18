# Instalação do Shibboleth IdP

_Elaborado por Rui Ribeiro – rui.ribeiro@cafe.rnp.br_

## 1. Visão Geral

Este repositório contém o script de instalação e os arquivos de configuração necessários para a implantação de um Provedor de Identidade (IdP) com a seguinte combinação de softwares:

- Ubuntu Server 24.04 LTS  
- Shibboleth IdP 5.1.4  
- Jetty 12.0.22

A execução do script deve ser realizada por meio da ferramenta **RPILOT**, mantida pela RNP.

## 2. Variáveis para execução

| **Variável**              | **Descrição** |
|---------------------------|----------------|
| `CITY` | Nome da cidade onde está localizada a instituição. Exemplo: `Porto Alegre`. |
| `COMPUTEDIDSALT` | Valor de hash utilizado como *salt* no contexto do identificador `ComputedID`. Exemplo: `a1b2c3d4...`. |
| `CONTACTGIVEN` | Primeiro nome do administrador responsável pelo servidor. Exemplo: `João`. |
| `CONTACTMAIL` | Endereço de e-mail do administrador responsável pelo servidor. Exemplo: `joao.admin@instituicao.edu.br`. |
| `CONTACTSUR` | Sobrenome do administrador responsável pelo servidor. Exemplo: `Silva`. |
| `DIRECTORY` | Tipo de diretório utilizado para autenticação. Valores possíveis: `OPENLDAP`, `AD`. |
| `FTICKSSALT` | Valor de hash utilizado como *salt* no contexto do `FTICKS`. Exemplo: `e5f6g7h8...`. |
| `HN` | Nome do host do servidor onde será instalado o IdP. Exemplo: `idp.instituicao.edu.br`. |
| `HN_DOMAIN` | Domínio da instituição. Exemplo: `instituicao.edu.br`. |
| `INITIALS` | Sigla ou acrônimo da instituição. Exemplo: `INST`. |
| `IP` | Endereço IP do servidor onde será instalado o IdP. Exemplo: `123.123.123.123`. |
| `LDAPATTR` | Atributo utilizado para consulta no diretório. Exemplos: `uid`, `sAMAccountName`. |
| `LDAPDN` | DN base para buscas no diretório. Exemplo: `ou=people,dc=instituicao,dc=edu,dc=br`. |
| `LDAPFORM` | Formato da identificação de usuários para autenticação. Exemplos: `uid=%s,dc=instituicao,dc=edu,dc=br`, `%s@ad.instituicao.edu.br`. |
| `LDAPPWD` | Senha do usuário de serviço do diretório (*bind user*). Exemplo: `senhaSegura123!`. |
| `LDAPSERVER` | Endereço do servidor de diretório. Exemplo: `diretorio.instituicao.edu.br`. |
| `LDAPSERVERPORT` | Porta utilizada para conexão com o servidor de diretório. Exemplos: `389`, `636`. |
| `LDAPSERVERPROTO` | Protocolo utilizado para conexão com o diretório. Exemplos: `ldap://`, `ldaps://`. |
| `LDAPSERVERSSL` | Indicativo de uso de SSL na conexão com o diretório. Valores possíveis: `0` (sem SSL), `1` (com SSL). |
| `LDAPSERVERSSLUSE` | Indicativo de uso de SSL na conexão com o diretório. Valores possíveis: `true`, `false`. |
| `LDAPSUBTREESEARCH` | Indica se a busca no diretório será do tipo *subtree*. Valores possíveis: `true`, `false`. |
| `LDAPUSER` | Identificação do usuário utilizado para *bind* no diretório. Exemplos: `cn=leitor-shib,dc=instituicao,dc=edu,dc=br`, `leitor-shib@ad.instituicao.edu.br`. |
| `MSG_AUTENTICACAO` | Texto exibido como instrução na tela de autenticação. Exemplo: `Digite seu número de matrícula`. |
| `MSG_URL_RECUPERACAO_SENHA` | URL da página de recuperação de senha. Exemplo: `https://senha.instituicao.edu.br/recuperar`. |
| `ORGANIZATION` | Nome completo da instituição. Exemplo: `Universidade Federal do Rio Grande do Sul`. |
| `OU` | Sigla da unidade organizacional responsável pelo IdP. Exemplo: `CPD`. |
| `PERSISTENTDIDSALT` | Valor de hash utilizado como *salt* no contexto do identificador `PersistentID`. Exemplo: `z9y8x7w6...`. |
| `STATE` | Nome por extenso do estado onde está localizada a instituição. Exemplo: `Rio Grande do Sul`. |
| `URL` | Endereço do site institucional oficial. Exemplo: `https://www.instituicao.edu.br`. |
| `SMTP_NOME_AMIGAVEL` | Nome que será exibido como remetente dos e-mails enviados pelo Painel MFA. Exemplo: `Painel MFA - UFRGS`. |
| `SMTP_EMAIL_ORIGINADOR` | Endereço de e-mail utilizado como remetente pelo Painel MFA. Exemplo: `mfa@instituicao.edu.br`. |
| `SMTP_ASSINATURA` | Texto da assinatura incluída nos e-mails do Painel MFA. Exemplo: `Equipe de Suporte - Painel MFA`. |
| `CAPTCHA_KEY` | *Key* utilizada para integração com o serviço CAPTCHA. Exemplo: `6Lcabc0aAAAAABCD123456`. |
| `CAPTCHA_TOKEN` | *Token* utilizado para integração com o serviço CAPTCHA. Exemplo: `03AGdBq25xyz...`. |
| `URL_RECUPERACAO_SENHA` | URL da funcionalidade de recuperação de senha. Exemplo: `https://senha.instituicao.edu.br/recuperar`. |
| `PAINEL_ADMIN_NAME` | Nome completo do administrador do Painel MFA. Exemplo: `João da Silva`. |
| `PAINEL_ADMIN_EPPN` | Hash do EPPN do administrador do Painel MFA. Exemplo: `5a33b2c98f0e...`. |
| `PAINEL_ADMIN_EMAIL` | Endereço de e-mail do administrador do Painel MFA. Exemplo: `joao.silva@instituicao.edu.br`. |
| `SMTP_HOST` | Endereço do servidor SMTP utilizado para envio de e-mails. Exemplo: `smtp.instituicao.edu.br`. |
| `SMTP_PORT` | Porta utilizada para conexão SMTP. Exemplos: `25`, `465`, `587`. |
| `SMTP_USERNAME` | Nome de usuário utilizado na autenticação SMTP. Exemplo: `smtpuser@instituicao.edu.br`. |
| `SMTP_PASSWORD` | Senha utilizada na autenticação SMTP. Exemplo: `senhaEmail456!`. |