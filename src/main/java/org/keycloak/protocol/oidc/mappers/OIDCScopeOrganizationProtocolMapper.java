package org.keycloak.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.rar.AuthorizationRequestContext;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.StringUtil;
import org.keycloak.organization.OrganizationProvider;

public class OIDCScopeOrganizationProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    private static final String ATTRIBUTE = "attribute";
    private static final String ID = "kc.org.id";
    private static final String NAME = "kc.org.name";
    private static final String ALIAS = "kc.org.alias";
    private static final String SCOPE = "scope";

    public static final String PROVIDER_ID = "oidc-scope-group-protocol-mapper";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty attributeProperty = new ProviderConfigProperty();
        attributeProperty.setName(ATTRIBUTE);
        attributeProperty.setLabel("Organization Attribute Name");
        attributeProperty.setHelpText(
                "Organization attribute name to store claim.  Use kc.org.id, kc.org.name, and kc.org.alias to map to those predefined organization properties.");
        attributeProperty.setType(ProviderConfigProperty.STRING_TYPE);

        configProperties.add(attributeProperty);

        ProviderConfigProperty scopeProperty = new ProviderConfigProperty();
        scopeProperty.setName(SCOPE);
        scopeProperty.setLabel("Scope name");
        scopeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        scopeProperty.setDefaultValue("organization");
        scopeProperty.setHelpText(
                "Name of dynamic scope, which will be used to match the default organization. Defaults to 'organization'");

        configProperties.add(scopeProperty);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, OIDCScopeOrganizationProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Scope-based Organization Membership";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getHelpText() {
        return "Map scope to user organization membership";
    }

    @Override
    protected void setClaim(IDToken idToken, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        String membership = getMembership(mappingModel, userSession, keycloakSession, clientSessionCtx);
        if (membership != null) {
            OIDCAttributeMapperHelper.mapClaim(idToken, mappingModel, membership);
        }
    }

    @Override
    protected void setClaim(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession,
            ClientSessionContext clientSessionCtx) {
        String membership = getMembership(mappingModel, userSession, keycloakSession, clientSessionCtx);
        if (membership != null) {
            OIDCAttributeMapperHelper.mapClaim(accessTokenResponse, mappingModel, membership);
        }
    }

    private static String getMembership(ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        String attribute = mappingModel.getConfig().get(ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return null;
        }

        AuthorizationRequestContext authorizationRequestContext = clientSessionCtx.getAuthorizationRequestContext();
        String scopeName = mappingModel.getConfig().get(SCOPE);
        String orgId = authorizationRequestContext.getAuthorizationDetailEntries()
                .stream()
                .filter(d -> d.getClientScope().getName().equals(scopeName))
                .map(d -> d.getDynamicScopeParam())
                .findFirst().orElse(null);
        if (orgId != null) {
            OrganizationModel organization = keycloakSession.getProvider(OrganizationProvider.class).getById(orgId);
            if (organization != null && organization.isEnabled() && organization.isMember(userSession.getUser())) {
                if (ID.equalsIgnoreCase(attribute)) {
                    return organization.getId();
                } else if (NAME.equalsIgnoreCase(attribute)) {
                    return organization.getName();
                } else if (ALIAS.equalsIgnoreCase(attribute)) {
                    return organization.getAlias();
                } else {
                    Map<String, List<String>> attributes = organization.getAttributes();
                    List<String> values = attributes.get(attribute);
                    if (values != null && values.size() > 0) {
                        return values.get(0);
                    }
                }
            }
        }

        return null;
    }

    public static ProtocolMapperModel createClaimMapper(String name,
            String tokenClaimName,
            boolean consentRequired, String consentText,
            boolean accessToken, boolean idToken) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<String, String>();
        config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, tokenClaimName);

        if (accessToken) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        }

        if (idToken) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        }

        mapper.setConfig(config);
        return mapper;
    }
}
