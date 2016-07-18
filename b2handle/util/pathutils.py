import os

def get_absolute_path(path, file_path_string):
    if os.path.isabs(path):
        return path

    elif path.startswith(os.path.curdir):
        path = path.lstrip(os.path.curdir)
        pathlist = path.split(os.path.sep)
        thisdir = get_this_directory(file_path_string, as_list=True)
        newdir = thisdir + list(pathlist)
        return os.path.sep+os.path.join(*newdir)

    else:
        raise ValueError('Path is neither absolute nor relative.')

def get_this_directory(file_path_string, as_list=False):
    this_directory_string = os.path.split(os.path.realpath(file_path_string))[0]

    if as_list:
        this_directory_list = this_directory_string.split(os.path.sep)
        return this_directory_list
    else:
        return this_directory_string

def get_super_directory(file_path_string, as_list=False):
    this_directory_list = get_this_directory(file_path_string, as_list=True)
    super_directory_list = this_directory_list[0:len(this_directory_list)-1]

    if as_list:
        return super_directory_list
    else:
        super_directory_string = os.path.join(*super_directory_list)
        return os.path.sep+super_directory_string


def get_neighbour_directory(file_path_string, dirname):
    super_directory_list = get_super_directory(file_path_string, as_list=True)
    super_directory_list.append(dirname)
    neighbour_directory_string = os.path.join(*super_directory_list)
    return os.path.sep+neighbour_directory_string