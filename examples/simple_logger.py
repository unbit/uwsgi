import uwsgi


def print_logs(ip, port, message):
    print(ip, port, message)

uwsgi.udp_callable = print_logs
