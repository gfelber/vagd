import os
if __name__ == '__main__':
    dir = os.path.dirname(os.path.realpath(__file__))
    with open(dir + '/template.py', 'r') as template:
        for line in template.readlines():
            print(line, end='')
