
from past.builtins import xrange
def add_missing_optional_args_with_value_none(args, optional_args):
    '''
    Adds key-value pairs to the passed dictionary, so that
        afterwards, the dictionary can be used without needing
        to check for KeyErrors.

    If the keys passed as a second argument are not present,
        they are added with None as a value.

    :args: The dictionary to be completed.
    :optional_args: The keys that need to be added, if
        they are not present.
    :return: The modified dictionary.
    '''

    for name in optional_args:
        if not name in args.keys():
            args[name] = None
    return args


def check_presence_of_mandatory_args(args, mandatory_args):
    '''
    Checks whether all mandatory arguments are passed.

    This function aims at methods with many arguments
        which are passed as kwargs so that the order
        in which the are passed does not matter.

    :args: The dictionary passed as args.
    :mandatory_args: A list of keys that have to be
        present in the dictionary.
    :raise: :exc:`~ValueError`
    :returns: True, if all mandatory args are passed. If not,
        an exception is raised.

    '''
    missing_args = []
    for name in mandatory_args:
        if name not in args.keys():
            missing_args.append(name)
    if len(missing_args) > 0:
        raise ValueError('Missing mandatory arguments: '+', '.join(missing_args))
    else:
        return True

def return_keys_of_value_none(dictionary):
    isnone = []
    for key,value in dictionary.items():
        if value is None:
            isnone.append(key)
    return isnone

def remove_value_none_from_dict(dictionary):
    isnone = return_keys_of_value_none(dictionary)
    if len(isnone) > 0:
        for nonekey in isnone:
            dictionary.pop(nonekey)
    return dictionary

def return_indices_of_value_none(mylist):
    isnone = []
    for i in xrange(len(mylist)):
        if mylist[i] is None:
            isnone.append(i)
    return isnone

def remove_value_none_from_list(mylist):
    isnone = return_indices_of_value_none(mylist)
    if len(isnone) > 0:
        for index in isnone:
            mylist.pop(index)
    return mylist
