"Script for logging encryption/decryptions, login/logout dates, and password changes for the Revenant app."

import os

class Log:
    """
    A logging class.
    """


    def __init__(self, username) -> None:
        self.username = username


    def log_exists(self) -> bool:
        "Checks if a log file exists. Returns a boolean  value."
        file_name_validity = os.path.exists("/home/{}/.log.log".format(self.username))
        return file_name_validity


    def create_log(self) -> int:
        "Creates a log file."
        with open ("/home/{}/.log.log".format(self.username), "w+") as file:
            file.write("log file created.")
        return 0

        
    def audit(self, keywords = list) -> int:
        with open ("/home/{}/log.log".format(self.username), "w+") as file:
            lines = file.readlines()
            for word in keywords:
                for line in lines:
                    if word not in line:
                        file.write(line)


    def log(self, logstring = str) -> int:
        with open ("/home/{}/.log.log".format(self.username), "w") as file:
            file.write("{}\n".format(logstring))
        return 0
    

    def change_user(self, new_user=str) -> int:
        self.username = new_user
        return 0