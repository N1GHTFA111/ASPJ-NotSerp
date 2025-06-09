# https://github.com/payloadbox
import datetime
import hashlib
import html
import imghdr
import os

import re
import secrets
import string
import random
from pprint import pprint

import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException

# env file
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv(dotenv_path='../config/.env')
test_key = os.getenv('TEST_KEY')
CLOUDMERSIVE_API_KEY = os.getenv('CLOUDMERSIVE_API_KEY')

api_instance = cloudmersive_virus_api_client.ScanApi()
api_instance.api_client.configuration.api_key['Apikey'] = CLOUDMERSIVE_API_KEY


def detect_path_traversal(url):
    # hex code: 0x2e=. 0x2f=/, 0x5c=\

    # check for common files like .htaccess, passwd, etc, shadow

    sus_chars = ['..', '../', '..\/', '%2e', '%2f', '%252e', '%252f', "%c0", "%ae",
                 "%af", "%uff0e", "%u2215", "%u2216", "./\/", ".\/", "%25c0", "%25ae", "%%"
                                                                                       "0x2e", "0x2f", "%%32", "%65",
                 "0x5c", "0x2e0x2e", ".htaccess", "htaccess", "passwd", "shadow", "boot.ini", ".asa"]
    for char in sus_chars:
        if char in url.lower():
            print("Path traversal detected")
            return True


# done
def detect_xss(user_input):
    sus_chars = ['<', 'href', 'src', 'javascript', '>', 'alert(', "<iframe", "<embed", "<input", "&gt", "onload",
                 "onpageshow",
                 "onfocus", "onmouseover", "&lt;", "&gt;", "%3e", "%3c", "prompt(", "()", "eval(", "`", "%60", "&lpar;",
                 "&rpar;", "&#x28;", "&#x29;", "&#40",
                 "&#41", "(alert", "=alert", ".source", '"al"+"ert', "/a", "/e", "(1)", '";', ".vibrate", "*{", ":url(",
                 ")}"]
    for char in sus_chars:
        if char in str(user_input).lower():
            return True


# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files


# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection


def calculate_md5(file_path):
    with open(file_path, 'rb') as file:
        md5_hash = hashlib.md5()
        while chunk := file.read(4096):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()


def scan_file(file_path):
    md5_hash = calculate_md5(file_path)

    return False


def generate_secure_filename(extension):
    # Generate a random string to add uniqueness
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    # Combine the safe filename, random string, and extension
    secure_filename = f"{random_string}.{extension}"
    return secure_filename


def generate_role_id():
    role_id = "ROLE_" + secrets.token_urlsafe(32)
    return role_id


def generate_auth_id():
    auth_id = "AUTH_" + secrets.token_urlsafe(32)
    return auth_id


def generate_transaction_id():
    tran_id = "TRANSACT_" + secrets.token_urlsafe(32)
    return tran_id


def generate_evirec_id():
    evirec_id = "EVIREC_" + secrets.token_urlsafe(32)
    return evirec_id


def generate_voucher_id():
    vch_id = "VCH_" + secrets.token_urlsafe(32)
    return vch_id


def generate_voucher_cart_id():
    vchcart_id = "VCHCART_" + secrets.token_urlsafe(32)
    return vchcart_id


def generate_blog_id():
    blog_id = "BLOG_" + secrets.token_urlsafe(32)
    return blog_id


def generate_feedback_id():
    feedback_id = "FDBACK_" + secrets.token_urlsafe(32)
    return feedback_id

def generate_code_id():  # michael added
    code_id = "POINTS_" + secrets.token_urlsafe(32)
    return code_id

def generate_voucher_transaction_id():
    voucher_transact_id = "VOUCH_TRANSACT_" + secrets.token_urlsafe(32)
    return voucher_transact_id

def generate_secure_voucher_code():
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    voucher_code_part_1 = ''.join(secrets.choice(characters) for _ in range(8))
    voucher_code_part_2 = ''.join(secrets.choice(characters) for _ in range(8))
    voucher_code_part_3 = ''.join(secrets.choice(characters) for _ in range(8))
    voucher_code_part_4 = ''.join(secrets.choice(characters) for _ in range(8))
    voucher_code = voucher_code_part_1 + "-" + voucher_code_part_2 + "-" + voucher_code_part_3 + "-" + voucher_code_part_4
    return voucher_code


def generate_time_based_one_time_pass():
    one_time_pass = secrets.token_urlsafe(32)

    current_time = datetime.datetime.now()

    expiration_time = current_time + datetime.timedelta(minutes=1)

    one_time_pass_dict = {
        "one_time_pass": one_time_pass,
        "current time": current_time,
        "expiration time": expiration_time
    }

    return one_time_pass_dict


class FileChecker:
    def __init__(self):
        active = True

    # @staticmethod
    # def check_file_content(file_to_check):
    #     try:
    #
    #         content = file_to_check.read().decode()
    #
    #         # Check for suspicious patterns or known signatures
    #         reverse_shell_pattern = r'(bash|cmd|nc|powershell|php|python|perl|rsh|ssh|telnet)\s*-c\s*'
    #         xss_script_pattern = r'<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>'
    #
    #         if re.search(reverse_shell_pattern, content, re.IGNORECASE):
    #             print('Potential reverse shell code detected')
    #             return False
    #
    #         if re.search(xss_script_pattern, content, re.IGNORECASE):
    #             print('Potential XSS script detected')
    #             return False
    #
    #         print('File content is clean')
    #         return True
    #     except OSError:
    #         print('Unable to read the file')
    #         return False

    @staticmethod
    def check_file_type(file):
        # Read the first few bytes of the file
        file.seek(0)

        bytes = file.read(4)

        # Check if the file is a PNG
        if bytes[:4] == b'\x89PNG':
            print("File type pass")
            return True

        # Check if the file is a JPEG
        if bytes[:2] == b'\xff\xd8':
            print("File type pass")
            return True
        # Check if the file is a JPEG using the imghdr library

        # Remember the initial file read position

        file.seek(0)  # Reset the file read position
        if imghdr.what(file) == 'jpeg':
            print("File type: JPEG")
            return True

        # File type is unknown
        print("File type fail")
        return False

    @staticmethod
    def is_allowed_file(filename):
        print("is allowed file")
        print(filename.split(".")[1] in ['png', 'jpg', 'jpeg'])
        return filename.split(".")[1] in ['png', 'jpg', 'jpeg']

    @staticmethod
    def cloudmersivescan(filename):
        # uncomment when in production
        try:
            # Scan a file for viruses
            api_response = api_instance.scan_file(filename)
            response_data = api_response
            # pprint(api_response)
            clean_result = response_data.clean_result
            print(clean_result)
            if clean_result:
                return True
            else:
                return False
        except ApiException as e:
            print("Exception when calling ScanApi->scan_file: %s\n" % e)
            return False
        #return True

    @staticmethod
    def is_file_safe(file, filename):
        # save file in DMZ
        # Read the file content into a variable
        file_content = file.read()

        file_name = str(random.randint(100000, 111111)) + "." + filename.split(".")[1]

        saved_file_path = os.path.join('../Detection_System/DMZ', secure_filename(file_name))

        # file.save(saved_file_path)

        # Save the file to the DMZ folder
        with open(saved_file_path, 'wb') as f:
            f.write(file_content)

        if FileChecker.check_file_type(file) and FileChecker.is_allowed_file(filename) and FileChecker.cloudmersivescan(
                saved_file_path):
            os.remove(saved_file_path)
            return True
        else:
            return False

    @staticmethod
    def check_file_metadata_comments(file):
        pass


class HTTPSecurityHeaders:

    def __init__(self):
        status = "Active"

    @staticmethod
    def generate_csp():
        csp = {
            'default-src': '\'self\'',
            'script-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdn.jsdelivr.net/npm/', 'https://js.stripe.com/',
                           'https://hooks.stripe.com/', 'https://checkout.stripe.com/', 'https://www.google.com/',
                           'https://www.gstatic.com/', 'https://stripe.com/', 'https://ajax.googleapis.com/'],
            'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://fonts.googleapis.com/', 'https://cdn.jsdelivr.net/',
                          'https://ajax.googleapis.com/'],
            'font-src': ['\'self\'', 'https://fonts.gstatic.com/', 'data:'],
            'img-src': ['\'self\'', 'data:', 'https://ajax.googleapis.com/'],
            'connect-src': ['\'self\'', 'https://fonts.gstatic.com/'],
            'object-src': '\'none\'',
            'base-uri': '\'self\'',
            'form-action': ['\'self\'', 'https://checkout.stripe.com/'],
            'frame-ancestors': '\'none\'',
            'frame-src': [
                '\'self\'',
                'https://js.stripe.com/',
                'https://hooks.stripe.com/',
                'https://checkout.stripe.com/',
                'https://www.google.com/',
                'https://stripe.com/'
            ],
        }

        return csp


class AuthenticationEllipticCurve:
    def __init__(self):
        # y^2 = x^3 + 7
        base_point_x_val = random.randint(100, 119)
        base_point_y_val = int((base_point_x_val ** 3 + 7) ** 0.5)

        # how it works is
        # when the route is called and that route wants to call the helper function
        # 1 parameter called code must be passed to helper function
        # the code is first put into the database with the helper function id
        # then the code is then sent from the route to the helper function
        # the helper function will compare with the database and if match it will call the function
        # if not it will reject

        # calculation
        database_x_multiplier = random.randint(100, 119)  # store in server

        # user num
        user_x_multiplier = random.randint(100, 119)  # user will pass to function

        # pass the user_y value to the helper function
        # store the database_y value in the server with the function id

        # what will be stored in the server to be compared
        x_val_server = base_point_x_val * database_x_multiplier * user_x_multiplier
        y_val_server = base_point_y_val * database_x_multiplier * user_x_multiplier

        # what user will give
        # user_x_multiplier

        # how function will compare
        print(f"Base point x: {base_point_x_val}")
        print(f"Base point y: {base_point_y_val}")
        print(f"Database x key: {database_x_multiplier}")
        print(f"user key: {user_x_multiplier}")
        user_param = user_x_multiplier
        point_generated_x = base_point_x_val * database_x_multiplier * user_param
        point_generated_y = base_point_y_val * database_x_multiplier * user_param
        print(f"X point generated {point_generated_x}")
        print(f"Y point generated {point_generated_y}")
        print(f"X point server generated {x_val_server}")
        print(f"Y point server generated {y_val_server}")

        if x_val_server == point_generated_x and y_val_server == point_generated_y:
            print("Yes")
        else:
            print("No")


if __name__ == "__main__":
    # file = '../demo_avatars/avatar-4.jpg'
    # with open(file, 'rb') as f:
    #     filechecker = FileChecker()
    #     FileChecker.check_file_type(f)
    authmodel = AuthenticationEllipticCurve()
