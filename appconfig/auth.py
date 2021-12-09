#!/bin/env python

###---------------------------------------------------------------------------
### File    : auth.py
###
### Content : Set up user authentication for a virtual node using the EPIC
###           API configuration for a StartTLS-enabled LDAP/AD server.
###
### Copyright 2020 HPE
###---------------------------------------------------------------------------

# Imports of standard Python packages.
import sys
import subprocess
import os
import os.path
import errno
import filecmp
import platform
import urlparse
import ConfigParser
import base64, json

#**# Import bd_vlib -- must be able to do this to work with vAgent.
#**import bd_vlib
from configcli import ConfigCli

from collections import defaultdict

# This is a hacky way to make a python enum
class AuthConfigType:
    undefined = 0
    single_ldap_domain = 1
    many_ldap_domains = 2

# Whether to configure authentication when run on an independent (main)
# nodegroup of a cluster.
RUN_ON_INDEPENDENT_GROUP = True
# Whether to configure authentication when run on a dependent nodegroup
# (edge nodes).
RUN_ON_DEPENDENT_GROUP = True
# IDs of tenants to run on. This is a list of string IDs, e.g. [ "2", "10" ]
# If empty-list then ALL tenants are whitelisted.
RUN_ON_TENANT_WHITELIST = []
# IDs of tenants to NOT run on. Evaluated after whitelist. If empty-list
# then NO tenants are blacklisted.
RUN_ON_TENANT_BLACKLIST = []
# Node roles to run on. If empty-list then ALL roles are whitelisted.
RUN_ON_ROLE_WHITELIST = []
# Node roles to NOT run on. Evaluated after whitelist. If empty-list
# then NO roles are blacklisted.
RUN_ON_ROLE_BLACKLIST = []
# How to interpret the case where no External User Groups are defined for a
# tenant. If True, we allow authentication for anyone found by the user
# search. If False, we don't configure authentication.
RUN_IF_NO_TENANT_USER_GROUPS = False
# Whether to allow login in the independent nodegroup if dependent nodegroups
# (edge nodes) exist. If set to False, all user accounts will still be present
# for the independent nodegroup, but login will be disallowed there except for
# members of the tenant admin groups (if any).
ALLOW_INDEP_MEMBER_LOGIN_IF_DEPENDENTS = True

# Other handy constants.
CERTDIR = "/etc/openldap/cacerts"
CERTNAME = "ca.crt"
CERTPATH = os.path.join(CERTDIR, CERTNAME)
SSSDCONFPATH = "/etc/sssd/sssd.conf"
SUDOERSNAME = "epic_tenant_admin"
SERVICENAME = "sssd"
SERVICEDESC = "User Auth"
REGATTEMPTS = 5

# Define some logging functions. Currently just dump to stdout/stderr;
# vAgent's execution of this script will redirect output to:
# /var/log/bluedata/postconfig.log
def log(str):
    sys.stdout.write(str + "\n")

def errlog(str):
    sys.stderr.write(str + "\n")

distro, ver, distid = platform.linux_distribution()

configcli = ConfigCli(shell=False)
ConfigMeta = configcli.getCommandObject("namespace")

# OK theoretically we should be able to work with this image. Let's get
# started.

# By default don't allow anyone else to read files that we create.
os.umask(077)

# Check for non-standard Python package imports.
try:
    import ldap
    import ldap.dn
    from SSSDConfig import SSSDConfig
    from SSSDConfig import NoOptionError
except ImportError:
    # In normal usage this could only fail in initial setup; once the
    # image is correct this error should not happen.
    errlog("Skipping auth setup: required Python packages not installed.")
    sys.exit(1)


# Set up mappings of some sssd config settings to Python-LDAP settings.
REQCERT_MAP = {"never": ldap.OPT_X_TLS_NEVER,
               "allow": ldap.OPT_X_TLS_HARD,
               "try": ldap.OPT_X_TLS_TRY,
               "demand": ldap.OPT_X_TLS_DEMAND,
               "hard": ldap.OPT_X_TLS_HARD}

def epic_config_get(param):
    return ConfigMeta.getWithTokens(param.split('.'))

def epic_config_get_decoded(param):
    return base64.b64decode(ConfigMeta.getWithTokens(param.split('.'))).decode('utf-8').replace('\n', '')

def epic_config_get_allow_undefined(param):
    try:
        return epic_config_get(param)
    except Exception:
        return None

def epic_config_get_allow_undefined_decoded(param):
    try:
        return epic_config_get_decoded(param)
    except Exception:
        return None

def abort_on_epic_config_undefined(config_fun):
    def wrapper(*args, **kwargs):
        try:
            return config_fun(*args, **kwargs)
        except Exception as e:
            # In normal usage this should not fail. Failure could happen if
            # this script is being modified and a bug/typo is introduced in
            # the bd_vlib property fetches, or if this script is manually
            # moved to run in nodes that have older vAgent versions.
            errlog("Required config options not specified.")
            log("Exiting auth setup.")
            sys.exit(1)
    return wrapper


@abort_on_epic_config_undefined
def get_epic_context_params():
    log("Fetching misc context info from EPIC...")
    is_independent = (epic_config_get('node.nodegroup_id') == u'1')
    try:
        multi_nodegroup = (epic_config.getNumNodegroups() > 1)
    except:
        log("Old deployment; can't determine if multi-nodegroup.")
        multi_nodegroup = False
    distro_id = epic_config_get('node.distro_id')
    role = epic_config_get('node.role_id')
    cluster_id = epic_config_get('cluster.id')
    cluster_name = epic_config_get('cluster.name')
    cluster_isolated = epic_config_get_allow_undefined('cluster.isolated')

    if is_independent and (not RUN_ON_INDEPENDENT_GROUP):
        log("Nothing to be done (skipping independent nodegroup).")
        return None
    if (not is_independent) and (not RUN_ON_DEPENDENT_GROUP):
        log("Nothing to be done (skipping dependent nodegroup).")
        return None
    if RUN_ON_ROLE_WHITELIST and (role not in RUN_ON_ROLE_WHITELIST):
        log("Nothing to be done (this role not whitelisted).")
        return None
    if RUN_ON_ROLE_BLACKLIST and (role in RUN_ON_ROLE_BLACKLIST):
        log("Nothing to be done (this role blacklisted).")
        return None
    log("...done.")
    return {'is_independent': is_independent,
            'multi_nodegroup': multi_nodegroup,
            'distro_id': distro_id,
            'role': role,
            'cluster_id': cluster_id,
            'cluster_name': cluster_name,
            'cluster_isolated': cluster_isolated
            }

def only_domained_groups(context_params, key, domain="undefined"):
    if not domain:
        domain = "undefined"
    log('output from only_domained_groups - ')
    return list(set(context_params[key].get(domain, {}).values() + context_params[key].get("undefined", {}).values()))

#not sure what to update hence leaving this for now
def check_if_domain_is_ldaps_secured(domain):
    ldaps_enabled = False
    try:
        ldaps_enabled = epic_config_get('auth.domain_map.' + domain + '.host')[:5] == 'ldaps'
    except:
        # We're using multiple urls
        pass
    try:
        ldaps_enabled = ldaps_enabled or epic_config_get('auth.domain_map.' + domain + '.urls')[:5] == 'ldaps'
    except:
        # we're using one host
        pass
    return ldaps_enabled

@abort_on_epic_config_undefined
def is_ldap_secured():
    log("Checking if EPIC login with LDAP/AD is secured...")
    auth_auth_type = epic_config_get_allow_undefined_decoded('connections.secrets.extAuth.data.type')
    if auth_auth_type is None:
        log("External auth server not configured for EPIC.")
        return False
    if (auth_auth_type != u'LDAP') and \
            (auth_auth_type != u'Active Directory') and \
            (auth_auth_type != u'multi-domain'):
        log("Auth type is '{0}' (not LDAP/AD/multi-domain).".format(auth_auth_type))
        return False

    auth_tls_enabled = True
    ldaps_enabled = False

    if auth_auth_type == u'LDAP' or auth_auth_type == u'Active Directory':
#        auth_tls_enabled = epic_config_get('connections.configmaps.ldap_config.data.ssl_enabled')
        try:
            #ldaps_enabled = epic_config_get('auth.host')[:5] == 'ldaps'
            ldaps_enabled = epic_config_get_decoded('connections.secrets.extAuth.data.security_protocol') == 'ldaps'
        except:
            # We're using multiple urls
            pass
        try:
            #ldaps_enabled = ldaps_enabled or epic_config_get('auth.urls')[:5] == 'ldaps'
            ldaps_enabled = ldaps_enabled or epic_config_get_decoded('connections.secrets.extAuth.data.security_protocol') == 'ldaps'
        except:
            # We're using one host
            pass
    # Not sure how to handle multiple domains, hence leaving that for now
    elif auth_auth_type == u'multi-domain':
        domain_keys = epic_config_get('auth.domain_map')
        for key in domain_keys:
            auth_tls_enabled = auth_tls_enabled or epic_config_get('auth.domain_map.' + key + '.tls_enabled')
            ldaps_enabled = ldaps_enabled or check_if_domain_is_ldaps_secured(key)

    if not (auth_tls_enabled or ldaps_enabled):
        log("AD/LDAP login is not secured - either enable StartTLS or use the LDAPS protocol.")
        return False
    if auth_tls_enabled:
        log("Login is secured with StartTLS.")
    if ldaps_enabled:
        log("Login is secured with LDAPS.")
    return True

def sssd_init():
    if os.path.isfile(SSSDCONFPATH):
        # Already initialized.
        log('sssd is already exist')
        return True
    log("Initializing auth service...")

    try:
        log('it is CentOS....')
        # sssd has not yet been configured; configure, but don't start it.
        subprocess.check_call(
            ["authconfig", "--enablesssd", "--enablesssdauth", "--enableldap",
            "--enableldapauth", "--enableldaptls", "--enablelocauthorize",
            "--enablemkhomedir", "--enablecachecreds", "--update", "--nostart"],
            stdout=subprocess.PIPE)

    except subprocess.CalledProcessError:
        errlog("Unable to initialize auth service.")
        return False
    except IOError:
        errlog("Unable to create base sssd.conf file")
        return False
    log("...done.")
    return True

@abort_on_epic_config_undefined
def get_epic_auth_params(context_params, sssd_domain, transmitted_domain=None):
    auth_ca_cert = None
    def get_guaranteed_param_from_config(config_value):
        if transmitted_domain:
            auth_start_string = 'auth.domain_map.' + transmitted_domain + '.'
        else:
            auth_start_string = 'connections.secrets.extAuth.data.'
        path_value = auth_start_string + config_value
        return epic_config_get_decoded(path_value)

    def get_optional_param_from_config(config_value):
        if transmitted_domain:
            auth_start_string = 'auth.domain_map.' + transmitted_domain + '.'
        else:
            auth_start_string = 'connections.secrets.extAuth.data.'
        path_value = auth_start_string + config_value
        return epic_config_get_allow_undefined_decoded(path_value)

    log("Fetching auth info from EPIC...")
    auth_server_uri = ""
    try:
        auth_hosts = get_guaranteed_param_from_config('auth_service_locations')
        auth_ssl_enabled = get_guaranteed_param_from_config('security_protocol')
        auth_host_list = auth_hosts.split('::::')
        if len(auth_host_list) > 0:
            protocol = "ldap"
            if auth_ssl_enabled == 'ldaps':
                protocol = "ldaps"
            isFirst = True
            for auth_host in auth_host_list:
                if isFirst == True:
                    auth_server_uri = "{0}://{1}".format(protocol, auth_host)
                    isFirst = False
                else:
                    auth_server_uri =  "{0}, {1}://{2}".format(auth_server_uri, protocol, auth_host)
    except Exception as inst:
        # Using URLs
        pass
    try:
        auth_server_uris = get_guaranteed_param_from_config('auth_service_locations')
    except:
        pass
    auth_user_attr = get_optional_param_from_config('user_attr')
    if auth_user_attr is None:
        # This case can happen if upgraded to post-2.2 from a 2.2 setup that
        # used NT Domain. User attribute needs to be set in the site admin
        # settings for user authentication. We'll exit soon, but continue for
        # now to also generate the user subtree message below if necessary.
        log("EPIC LDAP auth not configured with a user attribute.")
    auth_base_dn = get_optional_param_from_config('base_dn')
    if auth_base_dn is None:
        log("EPIC LDAP auth not configured for \"search bind\".")
        auth_base_dn = get_optional_param_from_config('user_subtree')
        if auth_base_dn is None:
            log("EPIC LDAP auth not configured with a user subtree DN.")
        else:
            log("EPIC LDAP auth not configured for \"search bind\".")
        auth_bind_dn = None
        auth_bind_pwd = None
    else:
        bind_type = get_optional_param_from_config('bind_type')
        if bind_type == 'search_bind':
            auth_bind_dn = get_optional_param_from_config('bind_dn')
            if auth_bind_dn is None:
                auth_bind_pwd = None
                log("EPIC LDAP auth not configured with a bind DN.")
                log("Note that in this case LDAP-based node access will only work")
                log("if the LDAP server supports anonymous search.")
            else:
                auth_bind_pwd = get_optional_param_from_config("bind_pwd")
                auth_ca_cert = None

    if (auth_user_attr is None) or (auth_base_dn is None):
        log("Exiting auth setup.")
        sys.exit(1)
    sssd_domain.set_option('id_provider', 'ldap')
    auth_auth_type = get_optional_param_from_config("type")
    if get_guaranteed_param_from_config('type') == u'LDAP':
        sssd_domain.set_option('ldap_schema', "rfc2307")
        sssd_domain.set_option('ldap_id_mapping', "false")
        sssd_domain.set_option('ldap_user_object_class', "posixAccount")
        sssd_domain.set_option('ldap_user_fullname', "cn")
        sssd_domain.set_option('ldap_user_gecos', "gecos")
        sssd_domain.set_option('ldap_group_object_class', "posixGroup")
        sssd_domain.set_option('ldap_group_name', "cn")
    else:
        sssd_domain.set_option('ldap_schema', "ad")
        sssd_domain.set_option('ldap_id_mapping', "true")
        sssd_domain.set_option('ldap_user_object_class', "user")
        sssd_domain.set_option('ldap_user_fullname', "displayName")
        sssd_domain.set_option('ldap_user_gecos', "description")
        sssd_domain.set_option('ldap_group_object_class', "group")
        sssd_domain.set_option('ldap_group_name', "sAMAccountName")
    sssd_domain.set_option('ldap_uri', auth_server_uri)
    sssd_domain.set_option('ldap_user_name', auth_user_attr)
    sssd_domain.set_option('ldap_search_base', auth_base_dn)
    sssd_domain.set_option('autofs_provider', 'ldap')
    sssd_domain.set_option('fallback_homedir', "/home/%u")
    sssd_domain.set_option('case_sensitive', "False")

    if bind_type == 'search_bind':
        # This is a hack - because we can't really touch the vagent
        # code, we can't sanitize this information, and we have to
        # manually remove the case where this bind dn is undefined
        # in the mnesia db.
        if auth_bind_dn and (auth_bind_dn != 'undefined' and auth_bind_pwd != 'undefined'):
            sssd_domain.set_option('ldap_default_bind_dn', auth_bind_dn)
            sssd_domain.set_option('ldap_default_authtok', auth_bind_pwd)
        else:
            sssd_domain.remove_option('ldap_default_bind_dn')
            sssd_domain.remove_option('ldap_default_authtok')

    log("...done.")
    return auth_ca_cert

@abort_on_epic_config_undefined
def get_epic_auth_config_type():
    top_level_keys = epic_config_get('connections.secrets.extAuth.data')
    if 'auth_service_locations' in top_level_keys :
        return AuthConfigType.single_ldap_domain
    elif 'domain_regex' in top_level_keys and 'domain_map' in top_level_keys:
        return AuthConfigType.many_ldap_domains
    else:
        return AuthConfigType.undefined


def get_more_auth_params(context_params, sssd_domain, transmitted_domain=None):
    log("Determining other auth params...")
    def get_members_param_from_config(config_value):
        if transmitted_domain:
            auth_start_string = 'auth.domain_map.' + transmitted_domain + '.'
            path_value = auth_start_string + config_value
            return epic_config_get_allow_undefined(path_value)
        else:
            auth_start_string = 'connections.secrets.extAuth.data.'
            path_value = auth_start_string + config_value
            return epic_config_get_allow_undefined_decoded(path_value)

    # Would like to use allow_no_value=True here, so we can support getting
    # None results as a way to indicate values should be reset to default.
    # But that only works with Python 2.7 and later.
    auth_props_cfg = ConfigParser.RawConfigParser()
    here = os.path.abspath(os.path.dirname(__file__))
    try:
        with open(os.path.join(here, 'auth.props')) as auth_props_file:
            auth_props_cfg.readfp(auth_props_file)
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
        log("...done (no auth.props file).")
        return
    # Set up some filters (optionally) based on the tenant groups and the
    # ldap_user_member_of property. These could be overridden later by
    # properties from the auth.props file.
    # In the no-groups case, we will have only gotten to this point if "no
    # groups" is to be interpreted as "no filtering" (because of the
    # RUN_IF_NO_TENANT_USER_GROUPS value). However even in that case we would
    # still do filtering when isolation is enabled.
#    if ((not context_params['tenant_member_groups']) and
#        (not context_params['tenant_admin_groups']) and
#        (not context_params['cluster_isolated'])):
#        # Block no groups in this case.
#        sssd_domain.remove_option('access_provider')
#        sssd_domain.remove_option('ldap_access_order')
#        sssd_domain.remove_option('ldap_access_filter')
#    else:
        # Set up filtering.
    sssd_domain.set_option('access_provider', 'ldap')
    sssd_domain.set_option('ldap_access_order', 'filter')
    sssd_domain.set_option('ldap_tls_reqcert', 'never')

    try:
        member_of = auth_props_cfg.get('ldap_user', 'member_of')
    except:
        member_of = 'memberOf'
    # OK let's see which groups can get in here. First, does the edge
    # node situation shut out tenant members?
    allow_member_login = ALLOW_INDEP_MEMBER_LOGIN_IF_DEPENDENTS
    allow_member_login = allow_member_login or (not context_params['multi_nodegroup'])
    allow_member_login = allow_member_login or (not context_params['is_independent'])
    if not allow_member_login:
        log("Preventing non-admin logins on independent nodegroup.")
    # And does the isolation state shut out members and/or admins?
    allow_admin_login = True
    if context_params['cluster_isolated']:
        if context_params['tenant_key_visibility'] == "all_admins":
            if allow_member_login:
                log("Preventing non-admin logins because cluster is isolated.")
            allow_member_login = False
        elif context_params['tenant_key_visibility'] == "site_admin_only":
            log("Preventing logins because cluster is isolated.")
            allow_admin_login = False
            allow_member_login = False

    mem_of = get_members_param_from_config('groups')
    if mem_of is None:
       mem_of = get_members_param_from_config('tenantGroups')

    if mem_of:
        if len(mem_of) > 0:
            members_of = list(mem_of.replace('\n', '').split("::::"))
            filter_groups = list(set(members_of))
            if len(filter_groups) > 0:
                filter_expr = '(|(' + ')('.join(['='.join([member_of, g]) for g in filter_groups]) + '))'
        else:
            filter_expr = '(|)' # filter blocks all
        sssd_domain.set_option('ldap_access_filter', filter_expr)

    for section in auth_props_cfg.sections():
        for (prop, value) in auth_props_cfg.items(section):
            if section == 'general':
                prop_name = prop
            else:
                prop_name = '_'.join([section, prop])

            sssd_domain.set_option(prop_name, value)

    log("...done.")

def update_cert(auth_ca_cert, sssd_domain, transmitted_domain=None):
    log("Updating CA cert if necessary...")
    cert_path = None
    cert_dir = None

    try:
        if transmitted_domain:
            cert_path = os.path.join(CERTDIR, transmitted_domain, CERTNAME)
            cert_dir = os.path.join(CERTDIR, transmitted_domain)
        else:
            cert_path = CERTPATH
            cert_dir = CERTDIR
        with open(cert_path, 'r') as infile:
            if infile.read() == auth_ca_cert:
                # Previous cert and new cert are same.
                log("...done (no change).")
                return False
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
        if auth_ca_cert is None:
            # No previous cert, and no new cert.
            log("...done (no change).")
            return False

    if auth_ca_cert is not None:
        if not os.path.isdir(cert_dir):
            os.makedirs(cert_dir)
        with open(cert_path, 'w') as outfile:
            outfile.write(auth_ca_cert)
        os.chmod(cert_path, 0o600)
        sssd_domain.set_option('ldap_tls_cacertdir', cert_dir)
    else:
        if os.path.isfile(cert_path):
            os.remove(cert_path)

    try:
        subprocess.check_call(
            ["cacertdir_rehash", cert_dir],
            stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        errlog("Warning: failed to rehash LDAP CA certs.")

    log("...done (updated).")
    return True

def update_sssd(sssd_config, sssd_domain):
    log("Updating auth service config if necessary...")
    temp_conf_path = SSSDCONFPATH + ".new"
    sssd_config.save_domain(sssd_domain)
    sssd_config.write(temp_conf_path)
    same_conf = filecmp.cmp(SSSDCONFPATH, temp_conf_path)
    os.remove(temp_conf_path)
    if same_conf:
        log("...done (no change).")
        return False
    sssd_config.write(SSSDCONFPATH)
    log("...done (updated).")
    return True

def stop_sssd():
    log("Stopping auth service so that changes can be applied...")
    try:
        subprocess.check_call(["systemctl", "stop", "sssd.service"])
    except subprocess.CalledProcessError:
        errlog("Unable to stop auth service.")
        return False

    log("...done.")
    return True

def start_sssd():
    log("starting auth service so that changes can be applied...")
    try:
        subprocess.check_call(["systemctl", "restart", "sssd.service"])
    except subprocess.CalledProcessError:
        errlog("Unable to stop auth service.")
        return False

    log("...done.")
    return True

def clear_sssd_cache():
    log("Clearing auth credentials cache (can fail if cache is empty)...")
    try:
        subprocess.check_call(
            ["sss_cache", "-E"],
            stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        errlog("Warning: failed to clear auth credentials cache.")

    # Certain changes are not recognized, even with cache-clearing, unless this
    # config cache is manually removed:
    cached_config_dir = "/var/lib/sss/db"
    if os.path.isdir(cached_config_dir):
        files = os.listdir(cached_config_dir)
        for file in files:
            if file[6:] == "cache_" and file[:4] == ".ldb":
                os.remove(os.path.join(cached_config_dir, file))
    else:
        errlog(cached_config_dir + " was not a directory")

    log("...done.")

def group_name_from_dn(group_dn, group_name_attr):
    # See if the relevant attribute is the RDN.
    # XXX
    # Need to see if this optimization is always valid... particularly, can the
    # attribute's value be capitalized differently than how it is expressed in
    # the DN specified for the search?
    try:
        dn_components = ldap.dn.str2dn(group_dn)
        if dn_components:
            (attr, value, flags) = dn_components[0][0]
            if attr == group_name_attr:
                if flags == ldap.AVA_BINARY:
                    # We don't currently do any transformations for special
                    # chars that are BER/DER encoded. Need more investigation
                    # on how sssd and Linux would handle these as group names.
                    errlog("Warning: group name '{0}' includes special chars.".format(
                        value))
                log("    (using name '{0}' for group '{1}')".format(value, group_dn))
                return value
    except:
        pass
    return None

def group_names_from_dns(sudo_groups, sssd_domain):
    try:
        group_name_attr = sssd_domain.get_option('ldap_group_name')
    except NoOptionError:
        group_name_attr = None
    if group_name_attr:
        unresolved_group_names = False
        for group_dn in sudo_groups.keys():
            group_name = group_name_from_dn(group_dn, group_name_attr)
            sudo_groups[group_dn] = group_name
            if group_name is None:
                unresolved_group_names = True
        return not unresolved_group_names
    return True

def group_names_from_lookup(sudo_groups, sssd_domain):
    group_name_attr = sssd_domain.get_option('ldap_group_name')
    ldap_uri = sssd_domain.get_option('ldap_uri')
    cacert_verify = sssd_domain.get_option('ldap_tls_reqcert').lower()
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, REQCERT_MAP[cacert_verify])
    if sssd_domain.get_option('ldap_referrals'):
        ldap.set_option(ldap.OPT_REFERRALS, ldap.OPT_ON)
    else:
        ldap.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
    try:
        bind_dn = sssd_domain.get_option('ldap_default_bind_dn')
        bind_pwd = sssd_domain.get_option('ldap_default_authtok')
    except NoOptionError:
        bind_dn = None
        bind_pwd = None
    con = ldap.initialize(ldap_uri)
    if urlparse.urlparse(ldap_uri)[0] == "ldap":
        con.start_tls_s()
    if bind_dn:
        con.simple_bind_s(bind_dn, bind_pwd)
    for group_dn in sudo_groups.keys():
        if sudo_groups[group_dn] is None:
            try:
                result = con.search_s(group_dn, ldap.SCOPE_BASE, attrlist=[group_name_attr])
                attrs_dict = result[0][1]
                if group_name_attr in attrs_dict:
                    value = attrs_dict[group_name_attr][0]
                    log("    (using name '{0}' for group '{1}')".format(value, group_dn))
                    sudo_groups[group_dn] = value
                else:
                    errlog("Warning: group '{0}' doesn't have group name attribute '{1}'.".format(
                        group_dn, group_name_attr))
            except:
                errlog("Warning: error trying to read group name attribute of group '{0}'.".format(
                    group_dn))

def update_sudoers(context_params, sssd_domain, transmitted_domain=None):
    log("Updating sudoers groups...")
    sudoers_path = os.path.join("/etc/sudoers.d", SUDOERSNAME)
    if context_params['tenant_key_visibility'] == "all":
        sudo_group_dns = list(set(only_domained_groups(context_params, 'tenant_member_groups', transmitted_domain) +
            only_domained_groups(context_params, 'tenant_admin_groups', transmitted_domain)))
    elif context_params['tenant_key_visibility'] == "all_admins":
        sudo_group_dns = only_domained_groups(context_params, 'tenant_admin_groups', transmitted_domain)
    else:
        sudo_group_dns = []
    sudo_groups = dict.fromkeys(sudo_group_dns)
    # First see how many names we can determine from the DNs.
    all_group_names_resolved = group_names_from_dns(sudo_groups, sssd_domain)
    # For any we couldn't resolve, look up name from server.
    if not all_group_names_resolved:
        group_names_from_lookup(sudo_groups, sssd_domain)
    sudo_group_names = sudo_groups.values()
    sudo_group_names = [n for n in sudo_group_names if n is not None]
    if os.path.isfile(sudoers_path):
        os.remove(sudoers_path)
    if not sudo_group_names:
        return
    # When writing group names to sudoers, backslash any space characters.
    sudo_rules = ["%{0} ALL=(ALL) NOPASSWD: ALL".format(g.replace(" ", "\\ "))
                  for g in sudo_group_names]
    with open(sudoers_path, 'w') as outfile:
        outfile.write('\n'.join(sudo_rules))
    os.chmod(sudoers_path, 0o440)
    log("...done.")

def main(args):
    log("Beginning auth setup.")

    # Get general params from EPIC and decide if we want to configure sssd.
    context_params = get_epic_context_params()
    log('is ldap secured??')
    log(str(is_ldap_secured()))
    if (context_params is None) or (not is_ldap_secured()):
        # We're not intending to configure user auth in this case, so
        # make sure the sssd service is stopped & unregistered.
#        bd_vlib.BDVLIB_UnregisterSystemSysVService(SERVICENAME)
        return 0 # this is not an error case
    if not sssd_init():
        # We're intending to configure user auth but we can't do initial
        # sssd setup. In normal use, the sssd service will never be registered
        # in this case, but let's make sure.
#        bd_vlib.BDVLIB_UnregisterSystemSysVService(SERVICENAME)
        return 1
    # Load the sssd config.
    sssd_config = SSSDConfig()

    if not os.path.isfile(SSSDCONFPATH):
        with open(SSSDCONFPATH, 'w') as fh:
            fh.write('')
            os.chmod(SSSDCONFPATH, 0o600)

    sssd_config.import_config(SSSDCONFPATH)

    domain_cardinality = get_epic_auth_config_type()
    def sssd_setup_fun(input_sssd_domain, transmitted_domain=None):
        sssd_domain = None
        try:
            sssd_domain = sssd_config.get_domain(str(input_sssd_domain))
        except:
            sssd_domain = sssd_config.new_domain(str(input_sssd_domain))

        # Get auth-specific params (and CA cert) from EPIC and from auth.props.
        auth_ca_cert = get_epic_auth_params(context_params, sssd_domain, transmitted_domain)
        get_more_auth_params(context_params, sssd_domain, transmitted_domain)
        # Update the CA cert and sssd config if appropriate.
        cert_changed = update_cert(auth_ca_cert, sssd_domain, transmitted_domain)
        sssd_changed = update_sssd(sssd_config, sssd_domain)
#        update_sudoers(context_params, sssd_domain, transmitted_domain)
        return sssd_changed or cert_changed

    def delete_removed_domains(domain_list):
        # Remove domains that used to be defined that are no longer defined
        configured_domain_list = list(set(sssd_config.list_domains()) - set(domain_list))
        if configured_domain_list:
            map(lambda x: sssd_config.delete_domain(x), configured_domain_list)
        return configured_domain_list

    def set_domains_in_sssd(domain_or_domain_list):
        sssd_config.set('sssd', 'domains', domain_or_domain_list)
        sssd_config.set('domain', 'override_homedir', '/home/%u')
        sssd_config.set('sssd', 'services', "nss, pam, autofs")
        sssd_config.save_service(sssd_config.get_service('sssd'))

    def set_domains_in_nss(domain_or_domain_list):
        sssd_config.set('nss', 'homedir_substring', '/home')

    sssd_config_changed = False

    if (domain_cardinality == AuthConfigType.single_ldap_domain or
            domain_cardinality == AuthConfigType.undefined):
        domains_deleted = len(delete_removed_domains(['default'])) != 0
        sssd_config_changed = sssd_setup_fun('default') or domains_deleted
        sssd_config.activate_domain('default')
        set_domains_in_sssd('default')
        set_domains_in_nss('default')
    elif domain_cardinality == AuthConfigType.many_ldap_domains:
        log("Inside AuthConfigType.many_ldap_domains")
        def check_if_domain_secure(domain_string):
            return (check_if_domain_is_ldaps_secured(domain_string) or
                epic_config_get('auth.domain_map.' + domain_string + '.tls_enabled'))

        domain_names = epic_config_get('auth.domain_map')
        secured_domain_names = filter(lambda d: check_if_domain_secure(d), domain_names)
        domains_deleted = len(delete_removed_domains(secured_domain_names)) != 0
        map_result = map(lambda x: sssd_setup_fun(x, x), secured_domain_names)
        map(lambda x: sssd_config.activate_domain(str(x)), secured_domain_names)
        set_domains_in_sssd(secured_domain_names)
        sssd_config.set('sssd', 're_expression', epic_config_get('auth.domain_regex'))

        for result in map_result:
            sssd_config_changed = sssd_config_changed or result or domains_deleted

    sssd_config.write(SSSDCONFPATH)

    # If sssd config has changed, we need to stop sssd and restart it.
    if sssd_config_changed:
        if not stop_sssd():
            return 1
        clear_sssd_cache()

    registered = False
    for attempt in range(REGATTEMPTS):
        start_sssd()
        log("...done.")
        registered = True
        break
    if not registered:
        errlog("Unable to register auth service.")

    if sssd_config_changed:
        log("account settings have changed; killing current ssh connections")
        subprocess.call(
            ["pkill", "-HUP", "sshd"],
            stdout=subprocess.PIPE)
    log("Finished auth setup.")
    return 0

if __name__ == "__main__":
    sys.exit(main(None))
