import sys

if len(sys.argv) > 1:
    # Imprimir los argumentos
    for arg in sys.argv[1:]:
        print(arg)
else:
    print("No se pasaron argumentos.")

x=input('who are you?:')
print(f'you are {x}')
