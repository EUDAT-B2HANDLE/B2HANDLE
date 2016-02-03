def add_missing_optional_args_with_value_none(args, optional_args):
    if not type(args) == 'dict' and not type(optional_args)==list:
        if type(args) == list and type(optional_args) == dict:
            temp = optional_args
            optional_args = args
            args = temp
        else:
            raise ValueError('Wrong argument types for method "add_missing_optional_args_with_value_none"')
        
    for name in optional_args:
        if not name in args.keys():
            args[name] = None
    return args