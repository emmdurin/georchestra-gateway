package org.georchestra.gateway.security.oauth2;

import com.jayway.jsonpath.JsonPath;
import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.LinkedHashMap;

public class LdapEnabledCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Resource resource = new FileSystemResource(
                System.getProperty("georchestra.datadir", "/etc/georchestra") + "/gateway/security.yaml");
        YamlMapFactoryBean yaml = new YamlMapFactoryBean();
        yaml.setResources(resource);
        LinkedHashMap<String, LinkedHashMap<String, Object>> ldap = JsonPath.read(yaml.getObject().get("georchestra"),
                "$.gateway.security.ldap");
        return ldap.values().stream().anyMatch(el -> el.containsKey("enabled") && ((Boolean) el.get("enabled")));
    }
}