from tqdm import tqdm
import time 
import requests

def check_requests_version():
    print("Versión de requests instalada:", requests.__version__)
    if requests.__version__ == "2.25.0":
        print("¡La versión de requests es correcta!")
    else:
        print("La versión de requests no es la correcta.")

def test():
	print('hello torero')
	 
	for i in tqdm (range (101), 
	               desc="Loading…", 
	               ascii=False, ncols=75):
	    time.sleep(0.01)
	     
	print("Complete.")

def main():
    check_requests_version()
    test()
	     
print("Complete.")
if __name__ == "__main__":
    main()

