import requests

def check_requests_version():
    print("Versión de requests instalada:", requests.__version__)
    if requests.__version__ == "2.26.0":
        print("¡La versión de requests es correcta!")
    else:
        print("La versión de requests no es la correcta.")

def main():
    check_requests_version()

if __name__ == "__main__":
    main()
