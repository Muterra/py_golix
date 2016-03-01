import trashtest
import trashtest_getlow
import trashtest_spec

def run():
    trashtest_getlow.run()
    trashtest_spec.run()
    trashtest.run()
          
if __name__ == '__main__':
    run()