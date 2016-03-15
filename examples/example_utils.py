import termcolor

def log(title, content):
    print termcolor.colored(title + ":", 'green', attrs = ['bold'])
    print content
    print ''
