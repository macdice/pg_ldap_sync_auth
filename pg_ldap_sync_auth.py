#!/usr/bin/env python

# On-the-fly role LDAP/PostgreSQL role synchronization and authentication
# script, for use with pam_exec.so.
#
# Authenticates users via LDAP, much the same way as the built-in LDAP
# authentication in PostgreSQL.  Optionally, also CREATEs the PostgreSQL
# user on the fly.  Optionally, also GRANTs/REVOKEs membership of other
# roles based on group membership in LDAP.
#
# This is experiment-grade prototype code only.  Not for production use.
# A better version of this would skip doing catalog sync work based on
# change sequence numbers from the LDAP server.  And be a proper PAM module.
# And support Kerberos etc.  And support StartTLS.  And client certificates.
# And a configuration file.  And a review of filter escaping hygiene etc.
# And logging?  And better error reporting than just bombing out.  And
# time-outs.
#
# To test from the command line:
#
#   echo -n "password" | pg_ldap_sync_auth.py username
# 
# To test with PAM, having built PostgreSQL --with-pam, put this in
# /etc/pam.d/postgresql (or some other name):
#
#   auth required pam_exec.so expose_authtok /path/to/pg_ldap_sync_auth.py
#   account required pam_permit.so
#
# ... then put something like this in pg_hba.conf:
#
#   host all all all pam pamservice=postgresql
#
# Only works on Linux for now (because expose_authtok is a Linux PAM
# extension, so you need to write some C on other OSes...)
#   
# Thomas Munro

import ldap
import ldap.filter
import os
import psycopg2
import re
import sys

from psycopg2.extensions import quote_ident

# configuration
AUTO_CREATE_USER = True # create users on demand?
AUTO_GRANT_REVOKE_ROLES = True # sync extra roles based on group membership?
DB = "dbname=postgres user=munro port=5433"
LDAP_URL = "ldap://localhost"
LDAP_USER_BASE = "dc=my-domain, dc=com" # base for user search
LDAP_USER_FILTER = "(cn=%s)" # find user
LDAP_GROUP_BASE = "ou=groups,dc=my-domain,dc=com" # base for group search
LDAP_GROUP_FILTER = "(&(cn=*)(member=%s))" # find groups you're a member of
LDAP_GROUP_ATTRIBUTE = "cn" # which attribute of the group is the pg role name?
ROLE_PATTERN = r"^.+$" # a regex to limit the groups/roles we synchronize

def auto_create_user(cursor, username):
  """Automatically CREATE USER if the user doesn't exist yet and return True
     if a new user was created."""
  # does this user exist in the database?
  cursor.execute("""SELECT usesysid
                      FROM pg_user
                     WHERE usename = %s""",
                 [username])
  row = cursor.fetchone()
  if row:
    return False
  else:
    # we need to create the user now
    cursor.execute("CREATE USER %s" % (quote_ident(username, cursor)))
    cursor.execute("""SELECT usesysid
                        FROM pg_user
                       WHERE usename = %s""",
                   [username])
    return True

def auto_grant_revoke_roles(cursor, l, user_dn, username):
  """Automatically GRANT and REVOKE role membership to match the set of
     groups that the user is a member of in the LDAP server.  Return True
     is any changes were made."""
  # which roles is this user currently a member of in the database?
  cursor.execute("""SELECT r.rolname
                      FROM pg_roles r
                      JOIN pg_auth_members m ON r.oid = m.roleid
                     WHERE m.member = (SELECT usesysid FROM pg_user WHERE usename = %s)""",
                 [username])
  db_roles = [role
              for role, in cursor.fetchall()
              if re.match(ROLE_PATTERN, role)]
  # which groups is this user a member of in the LDAP directory?
  results = l.search_s(LDAP_GROUP_BASE,
                       ldap.SCOPE_SUBTREE,
                       LDAP_GROUP_FILTER % ldap.filter.escape_filter_chars(user_dn),
                       [LDAP_GROUP_ATTRIBUTE])
  ldap_groups = [attributes[LDAP_GROUP_ATTRIBUTE][0]
                 for dn, attributes in results
                 if re.match(ROLE_PATTERN, attributes[LDAP_GROUP_ATTRIBUTE][0])]
  # make them match
  change = False
  for role in ldap_groups:
    if role not in db_roles:
      cursor.execute("GRANT %s TO %s" % (quote_ident(role, cursor),
                                         quote_ident(username, cursor)))
      change = True
  for role in db_roles:
    if role not in ldap_groups:
      cursor.execute("REVOKE %s FROM %s" % (quote_ident(role, cursor),
                                            quote_ident(username, cursor)))
      change = True
  return change

def authenticate(username, password):
  """Authenticate.  Either returns or throws on failure.  Also synchronize
     user and roles, if configured."""
  # connect to the LDAP server
  l = ldap.initialize(LDAP_URL)

  # seach for the user with the configured filter
  results = l.search_s(LDAP_USER_BASE,
                       ldap.SCOPE_SUBTREE,
                       LDAP_USER_FILTER % ldap.filter.escape_filter_chars(username))
  if len(results) == 0:
    raise Exception("No user found")
  elif len(results) > 1:
    raise Exception("Too many matches")
  user_dn, attributes = results[0]

  # try to authenticate as this user, using a second connection
  if password:
    l2 = ldap.initialize(LDAP_URL)
    l2.bind_s(user_dn, password) # throws on failure
    l2.unbind_s()

  # do we need to make a connection to the database?
  commit = False
  if AUTO_CREATE_USER or AUTO_GRANT_REVOKE_ROLES:
    conn = psycopg2.connect(DB)
    cursor = conn.cursor()
  # make catalog changes on demand, if configured
  if AUTO_CREATE_USER:
    commit |= auto_create_user(cursor, username)
  if AUTO_GRANT_REVOKE_ROLES:
    commit |= auto_grant_revoke_roles(cursor, l, user_dn, username)

  # we're done; commit if anything changed
  l.unbind_s()
  if AUTO_CREATE_USER or AUTO_GRANT_REVOKE_ROLES:
    if commit:
      conn.commit()
    conn.close()

if __name__ == "__main__":
  # when invoked by pam_exec.so we take the username from an env
  # variable, but otherwise we'll take it from the command line for testing;
  # the password is read from stdin, so you can test like this:
  if "PAM_USER" in os.environ:
    username = os.environ["PAM_USER"]
  else:
    username = sys.argv[1]
  #password = sys.stdin.read()
  password = "password"
  authenticate(username, password)
