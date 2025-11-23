# Configuração dos atributo eduPersonTargetedID e eduPersonScopedAffiliation

_Elaborado por Rui Ribeiro – rui.ribeiro@cafe.rnp.br_

## 1. Visão Geral

Este roteiro descreve o processo de configuração dos atributos `eduPersonTargetedID` e `eduPersonScopedAffiliation`.  
Cada atributo é abordado em uma seção específica, o que permite uma compreensão mais clara e estruturada das etapas necessárias para sua correta implementação.

## 2. Configuração do *eduPersonScopedAffiliation* 

> **Atenção:** a configuração deste atributo pressupõe que o atributo `eduPersonAffiliation` já esteja devidamente configurado.

O atributo `eduPersonScopedAffiliation` é composto pelo valor do atributo de vínculo (`eduPersonAffiliation`) acrescido do sufixo institucional. Exemplo: `usuario@instituicao.edu.br`

A configuração é realizada em duas etapas:  
1. Geração do atributo  
2. Liberação do atributo

### 2.1 Geração do atributo

Para gerar o atributo, adicione a seguinte definição no arquivo `/opt/shibboleth-idp/conf/attribute-resolver.xml`. A definição deve ser inserida antes do bloco de configuração dos `Data Connectors`.

```xml
<!-- eduPersonScopedAffiliation -->
<AttributeDefinition id="eduPersonScopedAffiliation" xsi:type="Scoped" scope="%{idp.scope}">
    <InputAttributeDefinition ref="eduPersonAffiliation" />
</AttributeDefinition>
```

Após configurada a geração, é necessário liberar o atributo para os provedores de serviço. Para isso, edite o arquivo `/opt/shibboleth-idp/conf/attribute-filter.xml` e adicione o trecho abaixo nos blocos `AttributeFilterPolicy` denominados `releaseToChimarraoOrCafe` e `releaseToEduGAIN`.

```xml
<AttributeRule attributeID="eduPersonScopedAffiliation">
    <PermitValueRule xsi:type="ANY" />
</AttributeRule>
```

## 3. Configuração do `eduPersonTargetedID`

> **Atenção:** o atributo `eduPersonTargetedID` encontra-se **obsoleto desde janeiro de 2020**, conforme a especificação [eduPerson 2020-01](https://wiki.refeds.org/display/STAN/eduPerson+2020-01#eduPerson202001-eduPersonTargetedID).  
> Ele foi substituído pelo `NameID` no formato persistente (`persistent-id`).  
> Contudo, sua configuração ainda pode ser necessária, pois alguns provedores de serviço (SPs) continuam a exigir este atributo.

O atributo `eduPersonTargetedID` consiste em um identificador único, opaco e não reutilizável* utilizado para representar de forma persistente e anônima o relacionamento entre um usuário e um provedor de serviço.

A configuração é composta por quatro etapas principais:

1. Criação de um *salt* para geração do identificador.
2. Definição das propriedades do atributo.
3. Definição e vinculação do atributo no `attribute-resolver.xml`.  
4. Liberação do atributo no `attribute-filter.xml`.

### 3.1 Criação do *salt*

O *salt* será utilizado para gerar o identificador persistente. Execute o comando abaixo e salve o resultado:

```bash
openssl rand -base64 32
```

Em seguida, insira o valor gerado ao final do arquivo  
`/opt/shibboleth-idp/credentials/secrets.properties` conforme o exemplo abaixo:

```
idp.cafe.computedIDsalt = ResultadoDoComando
```
### 3.2. Definição das propriedades do atributo

O atributo `eduPersonTargetedID` não está mais presente no schema eduPerson. Por esse motivo, suas propriedades precisam ser definidas manualmente no Shibboleth IDP.

Crie o arquivo `/opt/shibboleth-idp/conf/attributes/custom/eduPersonTargetedID.properties` e adicione o conteúdo abaixo:

```xml
# eduPersonTargetedID

id=eduPersonTargetedID
transcoder=SAML2XMLObjectTranscoder
saml2.name=urn:oid:1.3.6.1.4.1.5923.1.1.1.10
displayName.en=Opaque per-service identifier eduPersonTargetedID
description.en=Opaque per-service identifier eduPersonTargetedID
saml1.encodeType=falses
```

### 3.3 Definição e vinculação do atributo

O próximo passo consiste na criação da definição do atributo e de seu respectivo *data connector*. Para isso, edite o arquivo  
`/opt/shibboleth-idp/conf/attribute-resolver.xml` e faça as seguintes alterações.

#### a) Definição do atributo

Adicione a definição abaixo antes do bloco de configuração dos `Data Connectors`.

```xml
<!-- CAFe - eduPersonTargetedID -->
<AttributeDefinition id="eduPersonTargetedID" xsi:type="SAML2NameID"
    nameIdFormat="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
    <InputDataConnector ref="ComputedIDConnector" attributeNames="ComputedID" />
</AttributeDefinition>
```

#### b) Definição do *Data Connector*

Adicione este bloco antes do `DataConnector` cujo `id` é `staticAttributes`.

```xml
<DataConnector id="ComputedIDConnector" xsi:type="ComputedId"
    generatedAttributeID="ComputedID" salt="%{idp.cafe.computedIDsalt}">
    <InputDataConnector ref="dcLDAP"
        attributeNames="%{idp.authn.LDAP.returnAttributes}" />
</DataConnector>
```

### 3.4 Liberação do atributo

Para disponibilizar o atributo aos provedores de serviço, é necessário criar uma nova política de liberação. Edite o arquivo  
`/opt/shibboleth-idp/conf/attribute-filter.xml` e adicione o bloco a seguir antes do `AttributeFilterPolicy` cujo `id` é `releaseToChimarraoOrCafe`.

```xml
<AttributeFilterPolicy id="releaseToAnyone">

    <PolicyRequirementRule xsi:type="ANY"/>

    <AttributeRule attributeID="eduPersonTargetedID">
        <PermitValueRule xsi:type="ANY" />
    </AttributeRule>

</AttributeFilterPolicy>
```

## 4. Ações Finais

Após concluir a configuração de um ou ambos os atributos, é necessário reiniciar o Shibboleth IdP para aplicar as alterações. Para tanto, execute o comando abaixo:

```bash
systemctl restart jetty.service
```

Realizada a reinicialização do Shibboleth IDP é possível testar os novos atributos através do [Serviço de Homologação de Atributos](https://sp.rnp.br)

### 4.1 Validação

Após a reinicialização, é possível testar a disponibilidade dos novos atributos por meio do  [Serviço de Homologação de Atributos da RNP](https://sp.rnp.br). Após autenticar-se no serviço, verifique se os atributos `eduPersonScopedAffiliation` e/ou `eduPersonTargetedID` aparecem corretamente listados.