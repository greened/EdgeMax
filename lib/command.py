import re
import sys
import subprocess as sp

def close_shell(vyatta_shell):
    out, err = vyatta_shell.communicate()

    cfg_error = False

    if out:
        if re.search(r'(^Error:.?|not valid|[Ee]rror|[Ww]arning|[Ff]ailed|without config session|(?<!Nothing to delete [(])the specified node does not exist)', out) :
            cfg_error = True
            print "configure message:"
            print out
    if err:
        cfg_error = True
        raise Exception('Error reported by configure: {}'.format(err))

    if (vyatta_shell.returncode == 0) and not cfg_error:
        print "Configuration was successful."
        return  True
    else:
        raise Exception('Configuration was NOT successful!')

    return True

def yesno(*args):

    if len(args) > 1:
        default                                             = args[0].strip().lower()
        question                                            = args[1].strip()
    elif len(args) == 1:
        default                                             = args[0].strip().lower()
        question                                            = 'Answer y or n:'
    else:
        default                                             = None
        question                                            = 'Answer y or n:'

    if default == None:
        prompt                                              = " [y/n] "
    elif default == "y":
        prompt                                              = " [Y/n] "
    elif default == "n":
        prompt                                              = " [y/N] "
    else:
        raise ValueError(
            "{} invalid default parameter: \'{}\' - only [y, n] permitted".format(
                __name__, default))

    while 1:
        sys.stdout.write(question + prompt)
        choice                                              = (raw_input().lower().strip() or '')
        if default is not None and choice == '':
            if default == 'y':
                return True
            elif default == 'n':
                return False
        elif default is None:
            if choice == '':
                continue
            elif choice[0] == 'y':
                return True
            elif choice[0] == 'n':
                return False
            else:
                sys.stdout.write("Answer must be either y or n.\n")
        elif choice[0] == 'y':
            return True
        elif choice[0] == 'n':
            return False
        else:
            sys.stdout.write("Answer must be either y or n.\n")


def update_router(commands, do_update=False):
    vyatta_cmd       = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"
    # vyatta_cmd                                                = "echo" # Debug

    if do_update and yesno(
            'y', 'OK to update your configuration?'):  # Open a pipe to bash and iterate commands

        new_shell = True
        cfg_error = False
        for cmd in commands:  # print to stdout
            print cmd
            if new_shell:
                vyatta_shell = sp.Popen(
                    'bash',
                    shell=True,
                    stdin = sp.PIPE,
                    stdout=sp.PIPE,
                    stderr = sp.PIPE)
                new_shell = False
                vyatta_shell.stdin.write('{} begin;\n'.format(vyatta_cmd))

            vyatta_shell.stdin.write('{} {};\n'.format(vyatta_cmd, cmd))

            if cmd == 'save':
                vyatta_shell.stdin.write('{} end;\n'.format(vyatta_cmd))
                new_shell = True
                if not close_shell(vyatta_shell):
                    raise Exception('Configuration error')
                    sys.exit(1)
        if not new_shell:
            # No save command, consider an error.
            raise Exception('Did not save configuration')
    else:
        for cmd in commands:
            #print "echo %s" % cmd
            print cmd
