"""Create a b2handle api and call dummy function.
"""
from api import B2Handle
import logging
import datetime # for storing logfile with date and time
import os # for filename joins


if __name__ == "__main__":

    # Create logfile (+directory)
    currtime = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S_%f')
    logdirname = 'logs'
    logfilename = os.path.join(logdirname,'logfile_'+str(currtime)+'.log')
    logdir = os.path.dirname(logfilename)
    if not os.path.exists(logdir):
        os.makedirs(logdir)
    logging.basicConfig(filename=logfilename, level=logging.INFO)

    # Example use of api
    api = B2Handle()
    check = api.dummy()
    if check:
        logging.info("Dummy method worked.")

    print("Done!")