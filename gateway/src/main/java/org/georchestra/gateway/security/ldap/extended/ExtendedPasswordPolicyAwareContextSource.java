package org.georchestra.gateway.security.ldap.extended;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;

import org.springframework.core.log.LogMessage;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.ldap.ppolicy.PasswordPolicyAwareContextSource;
import org.springframework.security.ldap.ppolicy.PasswordPolicyControl;
import org.springframework.security.ldap.ppolicy.PasswordPolicyControlExtractor;
import org.springframework.security.ldap.ppolicy.PasswordPolicyException;
import org.springframework.security.ldap.ppolicy.PasswordPolicyResponseControl;

public class ExtendedPasswordPolicyAwareContextSource extends PasswordPolicyAwareContextSource {

    public ExtendedPasswordPolicyAwareContextSource(String providerUrl) {
        super(providerUrl);
    }

    @Override
    public DirContext getContext(String principal, String credentials) throws PasswordPolicyException {
        if (principal.equals(this.userDn)) {
            return super.getContext(principal, credentials);
        }
        this.logger.trace(LogMessage.format("Binding as %s, prior to reconnect as user %s", this.userDn, principal));
        // First bind as manager user before rebinding as the specific principal.
        LdapContext ctx = (LdapContext) super.getContext(this.userDn, this.password);
        Control[] rctls = { new PasswordPolicyControl(false) };
        try {
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, principal);
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, credentials);
            ctx.reconnect(rctls);
        } catch (javax.naming.NamingException ex) {
            PasswordPolicyResponseControl ctrl = PasswordPolicyControlExtractor.extractControl(ctx);
            if (this.logger.isDebugEnabled()) {
                this.logger.debug(LogMessage.format("Failed to bind with %s", ctrl), ex);
            }
            LdapUtils.closeContext(ctx);
            if (ctrl != null && ctrl.getErrorStatus() != null) {
                throw new PasswordPolicyException(ctrl.getErrorStatus());
            }
            throw LdapUtils.convertLdapException(ex);
        }
        this.logger.debug(LogMessage.of(() -> "Bound with " + PasswordPolicyControlExtractor.extractControl(ctx)));
        return ctx;
    }
}