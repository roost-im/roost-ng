from . import kerberos

def principal_to_user_process_group_name(princ):
    return kerberos.principal_to_group_name(princ, 'UP')

def principal_to_user_socket_group_name(princ):
    return kerberos.principal_to_group_name(princ, 'WS')
